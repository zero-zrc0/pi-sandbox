#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/landlock.h>
#include <linux/memfd.h>
#include <linux/openat2.h>
#include <linux/seccomp.h>
#include <limits.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <sched.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define MAX_RULES 256
#define MAX_BINDS 128
#define MAX_MASKS 128
#define MAX_ENV 128
#define MAX_ARGS 2048
#define MAX_FILE_BYTES (4U * 1024U * 1024U)
#define MAX_SECCOMP_FILTER_INSNS 256
#define EGRESS_ENV_PROXY "PI_EGRESS_PROXY"
#define EGRESS_ENV_LEASE "PI_EGRESS_LEASE"
#define EGRESS_ENV_CREDENTIAL "PI_EGRESS_CREDENTIAL"
#define EGRESS_BRIDGE_NAME "linux-egress-bridge"
#define EGRESS_MAX_CONNECTIONS 64
#define EGRESS_ACK_TIMEOUT_MS 10000

static int bundled_bwrap_path(char path[PATH_MAX]) {
  char executable[PATH_MAX];
  ssize_t length = readlink("/proc/self/exe", executable, sizeof(executable) - 1);
  if (length <= 0 || (size_t)length >= sizeof(executable) - 1) return -1;
  executable[length] = '\0';
  char *separator = strrchr(executable, '/');
  if (!separator) return -1;
  *separator = '\0';
  int written = snprintf(path, PATH_MAX, "%s/bwrap", executable);
  if (written < 0 || written >= PATH_MAX) return -1;
  char resolved[PATH_MAX];
  if (!realpath(path, resolved)) return -1;
  memcpy(path, resolved, strlen(resolved) + 1);
  return 0;
}

static int selected_bwrap_path(char path[PATH_MAX]) {
  const char *selected = getenv("PI_SANDBOX_BWRAP_PATH");
  if (!selected) return bundled_bwrap_path(path);
  char resolved[PATH_MAX];
  struct stat metadata;
  if (selected[0] != '/' || !realpath(selected, resolved) || strcmp(selected, resolved) != 0 ||
      stat(resolved, &metadata) != 0 || !S_ISREG(metadata.st_mode) || (metadata.st_mode & 0111) == 0) {
    errno = EINVAL;
    return -1;
  }
  memcpy(path, resolved, strlen(resolved) + 1);
  return 0;
}

#if defined(__x86_64__)
#define NATIVE_AUDIT_ARCH AUDIT_ARCH_X86_64
#define NATIVE_X32_SYSCALL_BIT 0x40000000U
#elif defined(__aarch64__)
#define NATIVE_AUDIT_ARCH AUDIT_ARCH_AARCH64
#else
#error "unsupported Linux architecture"
#endif

enum RuleKind { RULE_READ_FILE, RULE_READ_DIR, RULE_WRITE_FILE, RULE_WRITE_DIR, RULE_EXEC_FILE, RULE_EXEC_DIR };

struct Rule {
  char *path;
  uint64_t access;
  enum RuleKind kind;
};

struct Bind {
  char *path;
  int fd;
  int readonly;
};

struct Mask {
  char *path;
  int fd;
  int directory;
  int placeholder_fd;
};

struct Options {
  char *cwd;
  char *network;
  struct Rule rules[MAX_RULES];
  size_t rule_count;
  struct Bind binds[MAX_BINDS];
  size_t bind_count;
  struct Mask masks[MAX_MASKS];
  size_t mask_count;
  char *env[MAX_ENV * 2];
  size_t env_count;
  /** 0 = allow sockets, 1 = block sockets, 2 = proxy mode (family filter). */
  int socket_mode;
  /** Control-channel fd for the egress handoff; -1 when unused. */
  int egress_ctrl_fd;
  int deny_process_spawn;
  int quiet_ready;
  int virtual_dev;
  char **command;
};

static void fail(const char *message) {
  dprintf(STDERR_FILENO, "linux-sandbox: %s: %s\n", message, strerror(errno));
}

static int landlock_abi(void) {
#if defined(SYS_landlock_create_ruleset)
  return (int)syscall(SYS_landlock_create_ruleset, NULL, 0,
                      LANDLOCK_CREATE_RULESET_VERSION);
#else
  errno = ENOSYS;
  return -1;
#endif
}

static int open_verified_path(const char *path, int want_directory) {
  char resolved[PATH_MAX];
  if (!path || path[0] != '/') {
    errno = EINVAL;
    return -1;
  }
  if (!realpath(path, resolved) || strcmp(path, resolved) != 0) {
    errno = ELOOP;
    return -1;
  }
#if defined(SYS_openat2)
  struct open_how how = {
      .flags = O_PATH | O_CLOEXEC,
      .resolve = RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS,
  };
  int fd = (int)syscall(SYS_openat2, AT_FDCWD, path, &how, sizeof(how));
#else
  errno = ENOSYS;
  int fd = -1;
#endif
  if (fd < 0) return -1;
  struct stat info;
  if (fstat(fd, &info) != 0 ||
      (want_directory == 1 && !S_ISDIR(info.st_mode)) ||
      (want_directory == 0 && !S_ISREG(info.st_mode))) {
    int saved = errno ? errno : EINVAL;
    close(fd);
    errno = saved;
    return -1;
  }
  return fd;
}

static int parse_identity_value(const char *value, unsigned long long *identity) {
  if (!value || !value[0]) { errno = EINVAL; return -1; }
  for (const char *digit = value; *digit; digit++) {
    if (*digit < '0' || *digit > '9') { errno = EINVAL; return -1; }
  }
  char *end = NULL;
  errno = 0;
  unsigned long long parsed = strtoull(value, &end, 10);
  if (errno || end == value || *end) { if (!errno) errno = EINVAL; return -1; }
  *identity = parsed;
  return 0;
}

static int fd_matches_identity(int fd, unsigned long long device,
                               unsigned long long inode) {
  struct stat info;
  if (fstat(fd, &info) != 0) return -1;
  if ((unsigned long long)info.st_dev != device ||
      (unsigned long long)info.st_ino != inode) {
    errno = ESTALE;
    return -1;
  }
  return 0;
}

static uint64_t write_file_access(int abi) {
  uint64_t access = LANDLOCK_ACCESS_FS_WRITE_FILE;
  if (abi >= 3) access |= LANDLOCK_ACCESS_FS_TRUNCATE;
  return access;
}

static uint64_t write_dir_access(int abi) {
  uint64_t access = write_file_access(abi) |
      LANDLOCK_ACCESS_FS_REMOVE_DIR | LANDLOCK_ACCESS_FS_REMOVE_FILE |
      LANDLOCK_ACCESS_FS_MAKE_CHAR | LANDLOCK_ACCESS_FS_MAKE_DIR |
      LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_MAKE_SOCK |
      LANDLOCK_ACCESS_FS_MAKE_FIFO | LANDLOCK_ACCESS_FS_MAKE_BLOCK |
      LANDLOCK_ACCESS_FS_MAKE_SYM;
  if (abi >= 2) access |= LANDLOCK_ACCESS_FS_REFER;
  return access;
}

static int parse_process_spawn(const char *value, int *deny_process_spawn) {
  if (strcmp(value, "allow") == 0) {
    *deny_process_spawn = 0;
    return 0;
  }
  if (strcmp(value, "deny") == 0) {
    *deny_process_spawn = 1;
    return 0;
  }
  errno = EINVAL;
  return -1;
}

static volatile sig_atomic_t current_bwrap = -1;

static void stop_bwrap(int signal_number) {
  (void)signal_number;
  pid_t child = (pid_t)current_bwrap;
  if (child > 0) kill(child, SIGKILL);
}

static int add_rule(struct Options *options, const char *path,
                    enum RuleKind kind, uint64_t access) {
  for (size_t i = 0; i < options->rule_count; i++) {
    if (options->rules[i].kind == kind &&
        strcmp(options->rules[i].path, path) == 0) {
      options->rules[i].access |= access;
      return 0;
    }
  }
  if (options->rule_count == MAX_RULES) {
    errno = E2BIG;
    return -1;
  }
  options->rules[options->rule_count++] = (struct Rule){
      .path = strdup(path), .access = access, .kind = kind};
  return options->rules[options->rule_count - 1].path ? 0 : -1;
}

static int add_bind(struct Options *options, const char *path, int readonly,
                    int want_directory, const char *device,
                    const char *inode) {
  int verify_identity = device || inode;
  unsigned long long expected_device = 0, expected_inode = 0;
  if (verify_identity && (!device || !inode ||
      parse_identity_value(device, &expected_device) != 0 ||
      parse_identity_value(inode, &expected_inode) != 0)) return -1;
  int fd = -1;
  if (verify_identity) {
    fd = open_verified_path(path, want_directory);
    if (fd < 0 || fd_matches_identity(fd, expected_device, expected_inode) != 0) {
      int saved = errno;
      if (fd >= 0) close(fd);
      errno = saved;
      return -1;
    }
  }
  for (size_t i = 0; i < options->bind_count; i++) {
    if (strcmp(options->binds[i].path, path) == 0) {
      if (verify_identity && fd_matches_identity(options->binds[i].fd,
          expected_device, expected_inode) != 0) {
        int saved = errno;
        close(fd);
        errno = saved;
        return -1;
      }
      if (readonly) options->binds[i].readonly = 1;
      else if (!options->binds[i].readonly) options->binds[i].readonly = 0;
      if (fd >= 0) close(fd);
      return 0;
    }
  }
  if (options->bind_count == MAX_BINDS) {
    if (fd >= 0) close(fd);
    errno = E2BIG;
    return -1;
  }
  if (fd < 0) fd = open_verified_path(path, want_directory);
  if (fd < 0) return -1;
  char *copy = strdup(path);
  if (!copy) { close(fd); return -1; }
  options->binds[options->bind_count++] = (struct Bind){copy, fd, readonly};
  return 0;
}

static int add_mask(struct Options *options, const char *path, int directory,
                    const char *device, const char *inode) {
  if (options->mask_count == MAX_MASKS) { errno = E2BIG; return -1; }
  unsigned long long expected_device, expected_inode;
  if (parse_identity_value(device, &expected_device) != 0 ||
      parse_identity_value(inode, &expected_inode) != 0) return -1;
  int fd = open_verified_path(path, directory);
  if (fd < 0) return -1;
  if (fd_matches_identity(fd, expected_device, expected_inode) != 0) {
    int saved = errno;
    close(fd);
    errno = saved;
    return -1;
  }
  char *copy = strdup(path);
  if (!copy) { close(fd); return -1; }
  options->masks[options->mask_count++] = (struct Mask){copy, fd, directory, -1};
  return 0;
}

static int compare_masks(const void *left, const void *right) {
  const struct Mask *a = left, *b = right;
  size_t a_length = strlen(a->path), b_length = strlen(b->path);
  return a_length < b_length ? -1 : a_length > b_length ? 1 : strcmp(a->path, b->path);
}

static int mask_is_covered(const struct Options *options, size_t index) {
  const char *path = options->masks[index].path;
  for (size_t i = 0; i < index; i++) {
    const char *parent = options->masks[i].path;
    size_t length = strlen(parent);
    if (strcmp(parent, path) == 0 || (options->masks[i].directory &&
        strncmp(parent, path, length) == 0 &&
        (parent[length - 1] == '/' || path[length] == '/'))) return 1;
  }
  return 0;
}

static int add_runtime_rule(struct Options *options, const char *path,
                            enum RuleKind kind, uint64_t access) {
  char resolved[PATH_MAX];
  if (!realpath(path, resolved)) return 0;
  return add_rule(options, resolved, kind, access);
}

static int parse_rule(struct Options *options, const char *flag,
                      const char *path, int abi, int parent_mode) {
  enum RuleKind kind;
  uint64_t access;
  int directory;
  if (strcmp(flag, "--read-dir") == 0) {
    kind = RULE_READ_DIR;
    access = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;
    directory = 1;
  } else if (strcmp(flag, "--read-file") == 0) {
    kind = RULE_READ_FILE;
    access = LANDLOCK_ACCESS_FS_READ_FILE;
    directory = 0;
  } else if (strcmp(flag, "--execute-file") == 0) {
    kind = RULE_EXEC_FILE;
    access = LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE;
    directory = 0;
  } else if (strcmp(flag, "--execute-dir") == 0) {
    kind = RULE_EXEC_DIR;
    access = LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE |
        LANDLOCK_ACCESS_FS_READ_DIR;
    directory = 1;
  } else if (strcmp(flag, "--write-dir") == 0) {
    kind = RULE_WRITE_DIR;
    access = write_dir_access(abi);
    directory = 1;
  } else if (strcmp(flag, "--write-file") == 0) {
    kind = RULE_WRITE_FILE;
    access = write_file_access(abi);
    directory = 0;
  } else {
    errno = EINVAL;
    return -1;
  }
  if (add_rule(options, path, kind, access) != 0) return -1;
  if (parent_mode && (kind == RULE_WRITE_DIR || kind == RULE_WRITE_FILE)) {
    return add_bind(options, path, 0, directory, NULL, NULL);
  }
  return 0;
}

static int reserve_filter(size_t count, size_t additional) {
  if (count > MAX_SECCOMP_FILTER_INSNS ||
      additional > MAX_SECCOMP_FILTER_INSNS - count) {
    errno = E2BIG;
    return -1;
  }
  return 0;
}

static int add_bpf_block(int number, struct sock_filter *filter, size_t *count) {
  if (reserve_filter(*count, 2) != 0) return -1;
  filter[(*count)++] = (struct sock_filter)BPF_JUMP(
      BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)number, 0, 1);
  filter[(*count)++] = (struct sock_filter)BPF_STMT(
      BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA));
  return 0;
}

/*
 * Proxy-mode socket policy, self-contained BPF blocks that return ALLOW in
 * place so they need no shared landing target:
 *   - socket: only AF_INET/AF_INET6 stream sockets (no UDP, no raw, no
 *     netlink/vsock management paths);
 *   - socketpair: only anonymous AF_UNIX stream socketpairs.
 */
static int add_proxy_socket_policy(struct sock_filter *filter, size_t *count) {
  const uint32_t domain0 = (uint32_t)offsetof(struct seccomp_data, args[0]);
  const uint32_t domain1 = (uint32_t)offsetof(struct seccomp_data, args[1]);
  const uint32_t clear_cloexec = (uint32_t)~02000000;
  const uint32_t clear_nonblock = (uint32_t)~04000;
#ifdef __NR_socket
  if (reserve_filter(*count, 11) != 0) return -1;
  filter[(*count)++] = (struct sock_filter)BPF_JUMP(
      BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)__NR_socket, 0, 10);
  filter[(*count)++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, domain0);
  filter[(*count)++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 2 /* AF_INET */, 2, 0);
  filter[(*count)++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 10 /* AF_INET6 */, 1, 0);
  filter[(*count)++] = (struct sock_filter)BPF_STMT(
      BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA));
  filter[(*count)++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, domain1);
  filter[(*count)++] = (struct sock_filter)BPF_STMT(BPF_ALU | BPF_AND | BPF_K, clear_cloexec);
  filter[(*count)++] = (struct sock_filter)BPF_STMT(BPF_ALU | BPF_AND | BPF_K, clear_nonblock);
  filter[(*count)++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 1 /* SOCK_STREAM */, 1, 0);
  filter[(*count)++] = (struct sock_filter)BPF_STMT(
      BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA));
  filter[(*count)++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
#endif
#ifdef __NR_socketpair
  if (reserve_filter(*count, 10) != 0) return -1;
  filter[(*count)++] = (struct sock_filter)BPF_JUMP(
      BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)__NR_socketpair, 0, 9);
  filter[(*count)++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, domain0);
  filter[(*count)++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 1 /* AF_UNIX */, 1, 0);
  filter[(*count)++] = (struct sock_filter)BPF_STMT(
      BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA));
  filter[(*count)++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, domain1);
  filter[(*count)++] = (struct sock_filter)BPF_STMT(BPF_ALU | BPF_AND | BPF_K, clear_cloexec);
  filter[(*count)++] = (struct sock_filter)BPF_STMT(BPF_ALU | BPF_AND | BPF_K, clear_nonblock);
  filter[(*count)++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 1 /* SOCK_STREAM */, 1, 0);
  filter[(*count)++] = (struct sock_filter)BPF_STMT(
      BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA));
  filter[(*count)++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
#endif
  return 0;
}

static int add_bpf_errno(int number, int error, struct sock_filter *filter,
                         size_t *count) {
  if (reserve_filter(*count, 2) != 0) return -1;
  filter[(*count)++] = (struct sock_filter)BPF_JUMP(
      BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)number, 0, 1);
  filter[(*count)++] = (struct sock_filter)BPF_STMT(
      BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (error & SECCOMP_RET_DATA));
  return 0;
}

static uint32_t process_spawn_forbidden_flags(void) {
  uint32_t flags = (uint32_t)CLONE_VFORK;
#ifdef CLONE_NEWNS
  flags |= (uint32_t)CLONE_NEWNS;
#endif
#ifdef CLONE_NEWCGROUP
  flags |= (uint32_t)CLONE_NEWCGROUP;
#endif
#ifdef CLONE_NEWUTS
  flags |= (uint32_t)CLONE_NEWUTS;
#endif
#ifdef CLONE_NEWIPC
  flags |= (uint32_t)CLONE_NEWIPC;
#endif
#ifdef CLONE_NEWUSER
  flags |= (uint32_t)CLONE_NEWUSER;
#endif
#ifdef CLONE_NEWPID
  flags |= (uint32_t)CLONE_NEWPID;
#endif
#ifdef CLONE_NEWNET
  flags |= (uint32_t)CLONE_NEWNET;
#endif
  return flags;
}

static int add_clone_thread_only(struct sock_filter *filter, size_t *count) {
  if (reserve_filter(*count, 17) != 0) return -1;
  uint32_t required = (uint32_t)(CLONE_THREAD | CLONE_VM | CLONE_SIGHAND);
  uint32_t forbidden = process_spawn_forbidden_flags();
  const size_t syscall_offset = offsetof(struct seccomp_data, nr);
  const size_t flags_offset = offsetof(struct seccomp_data, args[0]);
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  const size_t high_flags_offset = flags_offset + sizeof(uint32_t);
#else
  const size_t high_flags_offset = flags_offset;
#endif
  const size_t low_flags_offset = flags_offset + (high_flags_offset == flags_offset ? sizeof(uint32_t) : 0);
  filter[(*count)++] = (struct sock_filter)BPF_JUMP(
      BPF_JMP | BPF_JEQ | BPF_K, __NR_clone, 0, 16);
  filter[(*count)++] = (struct sock_filter)BPF_STMT(
      BPF_LD | BPF_W | BPF_ABS, high_flags_offset);
  filter[(*count)++] = (struct sock_filter)BPF_JUMP(
      BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 0);
  filter[(*count)++] = (struct sock_filter)BPF_STMT(
      BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA));
  filter[(*count)++] = (struct sock_filter)BPF_STMT(
      BPF_LD | BPF_W | BPF_ABS, low_flags_offset);
  filter[(*count)++] = (struct sock_filter)BPF_STMT(
      BPF_ALU | BPF_AND | BPF_K, required);
  filter[(*count)++] = (struct sock_filter)BPF_JUMP(
      BPF_JMP | BPF_JEQ | BPF_K, required, 1, 0);
  filter[(*count)++] = (struct sock_filter)BPF_STMT(
      BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA));
  filter[(*count)++] = (struct sock_filter)BPF_STMT(
      BPF_LD | BPF_W | BPF_ABS, low_flags_offset);
  filter[(*count)++] = (struct sock_filter)BPF_STMT(
      BPF_ALU | BPF_AND | BPF_K, forbidden);
  filter[(*count)++] = (struct sock_filter)BPF_JUMP(
      BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 0);
  filter[(*count)++] = (struct sock_filter)BPF_STMT(
      BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA));
  filter[(*count)++] = (struct sock_filter)BPF_STMT(
      BPF_LD | BPF_W | BPF_ABS, low_flags_offset);
  filter[(*count)++] = (struct sock_filter)BPF_STMT(
      BPF_ALU | BPF_AND | BPF_K, 0xffU);
  filter[(*count)++] = (struct sock_filter)BPF_JUMP(
      BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 0);
  filter[(*count)++] = (struct sock_filter)BPF_STMT(
      BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA));
  filter[(*count)++] = (struct sock_filter)BPF_STMT(
      BPF_LD | BPF_W | BPF_ABS, syscall_offset);
  return 0;
}

static int install_seccomp(int socket_mode, int deny_process_spawn) {
  struct sock_filter filter[MAX_SECCOMP_FILTER_INSNS];
  size_t count = 0;
  if (reserve_filter(count, 4) != 0) return -1;
  filter[count++] = (struct sock_filter)BPF_STMT(
      BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch));
  filter[count++] = (struct sock_filter)BPF_JUMP(
      BPF_JMP | BPF_JEQ | BPF_K, NATIVE_AUDIT_ARCH, 1, 0);
  filter[count++] = (struct sock_filter)BPF_STMT(
      BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);
  filter[count++] = (struct sock_filter)BPF_STMT(
      BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr));
#if defined(__x86_64__)
  /* x32 shares AUDIT_ARCH_X86_64 but sets bit 30 on every syscall number. */
  if (reserve_filter(count, 2) != 0) return -1;
  filter[count++] = (struct sock_filter)BPF_JUMP(
      BPF_JMP | BPF_JSET | BPF_K, NATIVE_X32_SYSCALL_BIT, 0, 1);
  filter[count++] = (struct sock_filter)BPF_STMT(
      BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA));
#endif

  static const int blocked[] = {
#ifdef __NR_mount
      __NR_mount,
#endif
#ifdef __NR_umount2
      __NR_umount2,
#endif
#ifdef __NR_pivot_root
      __NR_pivot_root,
#endif
#ifdef __NR_ptrace
      __NR_ptrace,
#endif
#ifdef __NR_process_vm_readv
      __NR_process_vm_readv,
#endif
#ifdef __NR_process_vm_writev
      __NR_process_vm_writev,
#endif
#ifdef __NR_kexec_load
      __NR_kexec_load,
#endif
#ifdef __NR_kexec_file_load
      __NR_kexec_file_load,
#endif
#ifdef __NR_init_module
      __NR_init_module,
#endif
#ifdef __NR_finit_module
      __NR_finit_module,
#endif
#ifdef __NR_delete_module
      __NR_delete_module,
#endif
#ifdef __NR_reboot
      __NR_reboot,
#endif
#ifdef __NR_swapon
      __NR_swapon,
#endif
#ifdef __NR_swapoff
      __NR_swapoff,
#endif
#ifdef __NR_bpf
      __NR_bpf,
#endif
#ifdef __NR_perf_event_open
      __NR_perf_event_open,
#endif
#ifdef __NR_open_by_handle_at
      __NR_open_by_handle_at,
#endif
#ifdef __NR_name_to_handle_at
      __NR_name_to_handle_at,
#endif
#ifdef __NR_userfaultfd
      __NR_userfaultfd,
#endif
#ifdef __NR_keyctl
      __NR_keyctl,
#endif
#ifdef __NR_add_key
      __NR_add_key,
#endif
#ifdef __NR_request_key
      __NR_request_key,
#endif
#ifdef __NR_setns
      __NR_setns,
#endif
#ifdef __NR_unshare
      __NR_unshare,
#endif
#ifdef __NR_chroot
      __NR_chroot,
#endif
#ifdef __NR_mknod
      __NR_mknod,
#endif
#ifdef __NR_mknodat
      __NR_mknodat,
#endif
#ifdef __NR_io_uring_setup
      __NR_io_uring_setup,
#endif
#ifdef __NR_io_uring_enter
      __NR_io_uring_enter,
#endif
#ifdef __NR_io_uring_register
      __NR_io_uring_register,
#endif
  };
  for (size_t i = 0; i < sizeof(blocked) / sizeof(blocked[0]); i++) {
    if (add_bpf_block(blocked[i], filter, &count) != 0) return -1;
  }
  if (deny_process_spawn) {
#ifdef __NR_fork
    if (add_bpf_block(__NR_fork, filter, &count) != 0) return -1;
#endif
#ifdef __NR_vfork
    if (add_bpf_block(__NR_vfork, filter, &count) != 0) return -1;
#endif
#ifdef __NR_clone
    if (add_clone_thread_only(filter, &count) != 0) return -1;
#endif
#ifdef __NR_clone3
    if (add_bpf_errno(__NR_clone3, ENOSYS, filter, &count) != 0) return -1;
#endif
  }
  if (socket_mode == 1) {
#ifdef __NR_socket
    if (add_bpf_block(__NR_socket, filter, &count) != 0) return -1;
#endif
#ifdef __NR_socketpair
    /* libuv uses anonymous Unix stream pairs for child stdio. Keep those
       pipes while denying endpoint creation and all connection operations. */
    if (reserve_filter(count, 11) != 0) return -1;
    filter[count++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_socketpair, 0, 9);
    filter[count++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0]));
    filter[count++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AF_UNIX, 0, 6);
    filter[count++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[1]));
    filter[count++] = (struct sock_filter)BPF_STMT(BPF_ALU | BPF_AND | BPF_K, ~(SOCK_CLOEXEC | SOCK_NONBLOCK));
    filter[count++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SOCK_STREAM, 0, 3);
    filter[count++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[2]));
    filter[count++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 1);
    filter[count++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
    filter[count++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA));
    filter[count++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr));
#endif
#ifdef __NR_connect
    if (add_bpf_block(__NR_connect, filter, &count) != 0) return -1;
#endif
#ifdef __NR_bind
    if (add_bpf_block(__NR_bind, filter, &count) != 0) return -1;
#endif
#ifdef __NR_listen
    if (add_bpf_block(__NR_listen, filter, &count) != 0) return -1;
#endif
#ifdef __NR_accept
    if (add_bpf_block(__NR_accept, filter, &count) != 0) return -1;
#endif
#ifdef __NR_accept4
    if (add_bpf_block(__NR_accept4, filter, &count) != 0) return -1;
#endif
  } else if (socket_mode == 2) {
    if (add_proxy_socket_policy(filter, &count) != 0) return -1;
  }
  if (reserve_filter(count, 1) != 0) return -1;
  filter[count++] = (struct sock_filter)BPF_STMT(
      BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
  struct sock_fprog program = {.len = (unsigned short)count, .filter = filter};
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) return -1;
#if defined(SYS_seccomp)
  return (int)syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &program);
#else
  errno = ENOSYS;
  return -1;
#endif
}

static int seccomp_probe(void) {
  pid_t child = fork();
  if (child < 0) return 0;
  if (child == 0) {
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_getppid, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog program = {
        .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
        .filter = filter};
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) _exit(1);
#if defined(SYS_seccomp)
    if (syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &program) != 0)
      _exit(1);
#else
    _exit(1);
#endif
    errno = 0;
    long result = syscall(__NR_getppid);
    _exit(result == -1 && errno == EPERM ? 0 : 1);
  }
  int status = 0;
  while (waitpid(child, &status, 0) < 0) {
    if (errno != EINTR) return 0;
  }
  return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static int probe(void) {
  int abi = landlock_abi();
  int seccomp = seccomp_probe();
  printf("{\"landlockAbi\":%d,\"seccomp\":%s,\"planVersion\":3}\n", abi,
         seccomp ? "true" : "false");
  return abi >= 3 && seccomp ? 0 : 1;
}

static int add_landlock_rule(int ruleset, const struct Rule *rule) {
  int path_fd = open_verified_path(
      rule->path, rule->kind == RULE_READ_DIR || rule->kind == RULE_WRITE_DIR || rule->kind == RULE_EXEC_DIR);
  if (path_fd < 0) return -1;
  struct landlock_path_beneath_attr path_rule = {
      .allowed_access = rule->access, .parent_fd = path_fd};
  int result = (int)syscall(SYS_landlock_add_rule, ruleset,
                            LANDLOCK_RULE_PATH_BENEATH, &path_rule, 0);
  int saved = errno;
  close(path_fd);
  errno = saved;
  return result;
}

static int apply_restrictions(struct Options *options) {
  int abi = landlock_abi();
  if (abi < 3) {
    errno = ENOTSUP;
    return -1;
  }
  uint64_t handled = LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE |
      LANDLOCK_ACCESS_FS_READ_DIR | LANDLOCK_ACCESS_FS_WRITE_FILE |
      LANDLOCK_ACCESS_FS_REMOVE_DIR | LANDLOCK_ACCESS_FS_REMOVE_FILE |
      LANDLOCK_ACCESS_FS_MAKE_CHAR | LANDLOCK_ACCESS_FS_MAKE_DIR |
      LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_MAKE_SOCK |
      LANDLOCK_ACCESS_FS_MAKE_FIFO | LANDLOCK_ACCESS_FS_MAKE_BLOCK |
      LANDLOCK_ACCESS_FS_MAKE_SYM | LANDLOCK_ACCESS_FS_REFER |
      LANDLOCK_ACCESS_FS_TRUNCATE;
  struct landlock_ruleset_attr attributes = {
      .handled_access_fs = handled, .handled_access_net = 0};
  int ruleset = (int)syscall(SYS_landlock_create_ruleset, &attributes,
                             sizeof(attributes), 0);
  if (ruleset < 0) return -1;
  for (size_t i = 0; i < options->rule_count; i++) {
    if (add_landlock_rule(ruleset, &options->rules[i]) != 0) {
      int saved = errno;
      close(ruleset);
      errno = saved;
      return -1;
    }
  }
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 ||
      syscall(SYS_landlock_restrict_self, ruleset, 0) != 0) {
    int saved = errno;
    close(ruleset);
    errno = saved;
    return -1;
  }
  close(ruleset);
  if (install_seccomp(options->socket_mode, options->deny_process_spawn) != 0) return -1;
  static const char ready[] = "\x1ePI-LINUX-SANDBOX-READY\x1f";
  if (!options->quiet_ready && write(STDOUT_FILENO, ready, sizeof(ready) - 1) !=
      (ssize_t)(sizeof(ready) - 1)) return -1;
  return 0;
}

static int add_arg(char **args, size_t *count, char *value) {
  if (*count >= MAX_ARGS - 1) {
    errno = E2BIG;
    return -1;
  }
  args[(*count)++] = value;
  args[*count] = NULL;
  return 0;
}

static char *fd_string(int fd) {
  char *value = NULL;
  if (asprintf(&value, "%d", fd) < 0) return NULL;
  return value;
}

static int printable_token(const char *value, size_t max_length) {
  if (!value) return 0;
  size_t length = strlen(value);
  if (length == 0 || length > max_length) return 0;
  for (size_t index = 0; index < length; index += 1) {
    unsigned char character = (unsigned char)value[index];
    if (character <= 0x20 || character >= 0x7f) return 0;
  }
  return 1;
}

/* Split the fixed "host:port" policy proxy address handed over by the host. */
static int parse_egress_proxy(const char *value, char *host, size_t host_len,
                              char *port, size_t port_len) {
  if (!printable_token(value, 255)) return -1;
  const char *split = strrchr(value, ':');
  if (!split || split == value || split[1] == '\0') return -1;
  size_t host_size = (size_t)(split - value);
  size_t port_size = strlen(split + 1);
  if (host_size >= host_len || port_size >= port_len) return -1;
  memcpy(host, value, host_size);
  host[host_size] = '\0';
  memcpy(port, split + 1, port_size + 1);
  if (!printable_token(host, host_len - 1) ||
      !printable_token(port, port_len - 1))
    return -1;
  char *end = NULL;
  long port_number = strtol(port, &end, 10);
  if (!end || *end != '\0' || port_number <= 0 || port_number > 65535)
    return -1;
  return 0;
}

/* Send one fd plus a short note over a Unix control channel. */
static int send_fd_message(int fd, int payload_fd, const char *note) {
  char control[CMSG_SPACE(sizeof(int))];
  struct iovec iov = {.iov_base = (void *)note, .iov_len = strlen(note)};
  struct msghdr message;
  memset(&message, 0, sizeof(message));
  message.msg_iov = &iov;
  message.msg_iovlen = 1;
  message.msg_control = control;
  message.msg_controllen = sizeof(control);
  struct cmsghdr *header = CMSG_FIRSTHDR(&message);
  header->cmsg_level = SOL_SOCKET;
  header->cmsg_type = SCM_RIGHTS;
  header->cmsg_len = CMSG_LEN(sizeof(int));
  memcpy(CMSG_DATA(header), &payload_fd, sizeof(int));
  message.msg_controllen = header->cmsg_len;
  ssize_t sent;
  do {
    sent = sendmsg(fd, &message, 0);
  } while (sent < 0 && errno == EINTR);
  return sent < 0 ? -1 : 0;
}

/* Wait for the bridge's one-byte handoff acknowledgement. */
static int wait_egress_ack(int fd) {
  struct pollfd entry = {.fd = fd, .events = POLLIN};
  for (;;) {
    int ready = poll(&entry, 1, EGRESS_ACK_TIMEOUT_MS);
    if (ready < 0 && errno == EINTR) continue;
    if (ready <= 0) return -1;
    break;
  }
  char ack = 0;
  ssize_t received;
  do {
    received = read(fd, &ack, 1);
  } while (received < 0 && errno == EINTR);
  return received == 1 && ack == 'K' ? 0 : -1;
}

/*
 * Create the sandbox entry listener, hand it to the bridge over the control
 * channel, and publish the loopback port. The tool receives standard proxy
 * variables pointing at this entry; every other route out died with the
 * network namespace.
 */
static int egress_handoff(int ctrl_fd, char *port_out, size_t port_out_len) {
  int listen_fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (listen_fd < 0) return -1;
  struct sockaddr_in address = {0};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  address.sin_port = 0;
  if (bind(listen_fd, (struct sockaddr *)&address, sizeof(address)) != 0 ||
      listen(listen_fd, EGRESS_MAX_CONNECTIONS) != 0) {
    int saved = errno;
    close(listen_fd);
    errno = saved;
    return -1;
  }
  socklen_t length = sizeof(address);
  if (getsockname(listen_fd, (struct sockaddr *)&address, &length) != 0) {
    int saved = errno;
    close(listen_fd);
    errno = saved;
    return -1;
  }
  char note[64];
  int port = ntohs(address.sin_port);
  snprintf(note, sizeof(note), "port=%d", port);
  if (snprintf(port_out, port_out_len, "%d", port) < 0 ||
      send_fd_message(ctrl_fd, listen_fd, note) != 0 ||
      wait_egress_ack(ctrl_fd) != 0) {
    int saved = errno ? errno : EPROTO;
    close(listen_fd);
    errno = saved;
    return -1;
  }
  close(listen_fd);
  return 0;
}

/*
 * The tool must start with stdio only. Any surviving descriptor (control
 * channel, handoff leftovers, inherited pipes) means preparation is broken
 * and the tool must never run.
 */
static int unexpected_descriptors_present(void) {
  int unexpected = 0;
  DIR *directory = opendir("/proc/self/fd");
  if (!directory) return 1;
  int self_dir = dirfd(directory);
  int keep[64];
  size_t count = 0;
  struct dirent *entry;
  while ((entry = readdir(directory)) != NULL) {
    if (entry->d_name[0] == '.') continue;
    char *end = NULL;
    long fd = strtol(entry->d_name, &end, 10);
    if (!end || *end != '\0' || fd < 0) continue;
    if (fd <= 2 || (int)fd == self_dir) continue;
    if (count < sizeof(keep) / sizeof(keep[0])) keep[count++] = (int)fd;
    else unexpected += 1;
  }
  closedir(directory);
  for (size_t index = 0; index < count; index += 1) unexpected += 1;
  return unexpected;
}

/* Close every descriptor above stdio except an explicit keep list. The
 * launcher inherits arbitrary host fds; bwrap would pass surviving ones
 * through to the sandboxed tool, so they die here. */
static void close_unexpected_fds(const int *keep, size_t keep_count) {
  DIR *directory = opendir("/proc/self/fd");
  if (!directory) return;
  int self_dir = dirfd(directory);
  int found[256];
  size_t count = 0;
  struct dirent *entry;
  while ((entry = readdir(directory)) != NULL) {
    if (entry->d_name[0] == '.') continue;
    char *end = NULL;
    long fd = strtol(entry->d_name, &end, 10);
    if (!end || *end != '\0' || fd <= 2) continue;
    if ((int)fd == self_dir) continue;
    if (count < sizeof(found) / sizeof(found[0])) found[count++] = (int)fd;
  }
  closedir(directory);
  for (size_t index = 0; index < count; index += 1) {
    int fd = found[index];
    int kept = 0;
    for (size_t item = 0; item < keep_count; item += 1) {
      if (keep[item] == fd) {
        kept = 1;
        break;
      }
    }
    if (!kept) close(fd);
  }
}

static int read_content_fd(void) {
  int fd = (int)syscall(SYS_memfd_create, "plan13-content", MFD_CLOEXEC);
  if (fd < 0) return -1;
  size_t total = 0;
  char buffer[16 * 1024];
  for (;;) {
    ssize_t count = read(STDIN_FILENO, buffer, sizeof(buffer));
    if (count < 0 && errno == EINTR) continue;
    if (count < 0) {
      int saved = errno;
      close(fd);
      errno = saved;
      return -1;
    }
    if (count == 0) break;
    total += (size_t)count;
    if (total > MAX_FILE_BYTES) {
      close(fd);
      errno = EFBIG;
      return -1;
    }
    size_t offset = 0;
    while (offset < (size_t)count) {
      ssize_t written = write(fd, buffer + offset, (size_t)count - offset);
      if (written < 0 && errno == EINTR) continue;
      if (written <= 0) {
        int saved = errno ? errno : EIO;
        close(fd);
        errno = saved;
        return -1;
      }
      offset += (size_t)written;
    }
  }
  if (lseek(fd, 0, SEEK_SET) < 0) {
    int saved = errno;
    close(fd);
    errno = saved;
    return -1;
  }
  return fd;
}

static int parse_parent_options(int argc, char **argv, struct Options *options) {
  memset(options, 0, sizeof(*options));
  options->egress_ctrl_fd = -1;
  int abi = landlock_abi();
  if (abi < 3) {
    errno = ENOTSUP;
    return -1;
  }
  for (int i = 2; i < argc; i++) {
    if (strcmp(argv[i], "--") == 0) {
      options->command = &argv[i + 1];
      break;
    }
    if (i + 1 >= argc) {
      errno = EINVAL;
      return -1;
    }
    const char *flag = argv[i++];
    const char *value = argv[i];
    if (strcmp(flag, "--ready") == 0 && strcmp(value, "none") == 0) options->quiet_ready = 1;
    else if (strcmp(flag, "--process-spawn") == 0) {
      if (parse_process_spawn(value, &options->deny_process_spawn) != 0) return -1;
    }
    else if (strcmp(flag, "--cwd") == 0) options->cwd = (char *)value;
    else if (strcmp(flag, "--network") == 0) options->network = (char *)value;
    else if (strcmp(flag, "--virtual-dev") == 0 && strcmp(value, "yes") == 0) options->virtual_dev = 1;
    else if (strcmp(flag, "--env") == 0) {
      if (i + 1 >= argc || options->env_count >= MAX_ENV * 2) {
        errno = E2BIG;
        return -1;
      }
      options->env[options->env_count++] = (char *)value;
      options->env[options->env_count++] = argv[++i];
    } else if (strcmp(flag, "--protected") == 0) {
      if (i + 3 >= argc) { errno = EINVAL; return -1; }
      int directory;
      if (strcmp(argv[i + 1], "directory") == 0) directory = 1;
      else if (strcmp(argv[i + 1], "file") == 0) directory = 0;
      else { errno = EINVAL; return -1; }
      if (add_bind(options, value, 1, directory, argv[i + 2], argv[i + 3]) != 0) return -1;
      i += 3;
    } else if (strcmp(flag, "--mask-file") == 0 || strcmp(flag, "--mask-dir") == 0) {
      if (i + 2 >= argc) { errno = EINVAL; return -1; }
      if (add_mask(options, value, strcmp(flag, "--mask-dir") == 0, argv[i + 1], argv[i + 2]) != 0) return -1;
      i += 2;
    } else if (parse_rule(options, flag, value, abi, 1) != 0) {
      return -1;
    }
  }
  if (!options->cwd || options->cwd[0] != '/' || !options->command ||
      !options->command[0] || !options->network) {
    errno = EINVAL;
    return -1;
  }
  int destinations = strcmp(options->network, "destinations") == 0;
  if (!destinations && strcmp(options->network, "none") != 0 &&
      strcmp(options->network, "all") != 0) {
    errno = EINVAL;
    return -1;
  }
  if (destinations) {
    /*
     * The private values arrive through the host-only launcher environment.
     * They are consumed before bwrap starts and never reach the tool: bwrap
     * clears the environment, the parent unsets them, and the inner process
     * starts from a swept descriptor table.
     */
    char proxy_host[256];
    char proxy_port[32];
    if (parse_egress_proxy(getenv(EGRESS_ENV_PROXY), proxy_host,
                           sizeof(proxy_host), proxy_port,
                           sizeof(proxy_port)) != 0 ||
        !printable_token(getenv(EGRESS_ENV_LEASE), 255) ||
        !printable_token(getenv(EGRESS_ENV_CREDENTIAL), 255)) {
      errno = EINVAL;
      return -1;
    }
  }
  return 0;
}

static int run_parent(int argc, char **argv) {
  /*
   * Nothing the launcher inherited may survive: the option parser opens the
   * verified bind descriptors afterwards, and bwrap would forward any
   * earlier stray descriptor into the sandbox.
   */
  close_unexpected_fds(NULL, 0);
  struct Options options;
  if (parse_parent_options(argc, argv, &options) != 0) {
    fail("invalid or unsupported launch plan");
    return 125;
  }
  int destinations = strcmp(options.network, "destinations") == 0;
  int ctrl[2] = {-1, -1};
  char bridge_path[PATH_MAX];
  if (destinations) {
    /*
     * Start the standalone bridge before the sandbox. It receives the
     * control channel end and the fixed proxy address, then waits for the
     * sandboxed inner to hand over the entry listener.
     */
    ssize_t self_length = readlink("/proc/self/exe", bridge_path,
                                   sizeof(bridge_path) - 1);
    if (self_length < 0) {
      fail("bridge path could not be resolved");
      return 125;
    }
    bridge_path[self_length] = '\0';
    char *last_slash = strrchr(bridge_path, '/');
    if (!last_slash) {
      fail("bridge path could not be resolved");
      return 125;
    }
    strcpy(last_slash + 1, EGRESS_BRIDGE_NAME);
    if (access(bridge_path, X_OK) != 0) {
      fail("egress bridge binary is missing");
      return 125;
    }
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, ctrl) != 0) {
      fail("could not create the egress control channel");
      return 125;
    }
    int bridge_ctrl = ctrl[0];
    int flags = fcntl(ctrl[1], F_GETFD);
    if (flags < 0 || fcntl(ctrl[1], F_SETFD, flags & ~FD_CLOEXEC) != 0) {
      fail("could not prepare the egress control channel");
      close(ctrl[0]);
      close(ctrl[1]);
      return 125;
    }
    char *ctrl_number = NULL;
    char *max_number = NULL;
    if (asprintf(&ctrl_number, "%d", bridge_ctrl) < 0 ||
        asprintf(&max_number, "%d", EGRESS_MAX_CONNECTIONS) < 0) {
      fail("could not prepare the bridge launch");
      return 125;
    }
    /*
     * The credential travels only through the inherited environment. The
     * lease id and proxy address are fixed launch values, not tool input.
     */
    char *proxy_value = getenv(EGRESS_ENV_PROXY);
    char *split = strrchr(proxy_value, ':');
    *split = '\0';
    const char *proxy_host = proxy_value;
    const char *proxy_port = split + 1;
    pid_t bridge_pid = fork();
    if (bridge_pid < 0) {
      fail("could not fork the egress bridge");
      close(bridge_ctrl);
      close(ctrl[1]);
      return 125;
    }
    if (bridge_pid == 0) {
      int bridge_flags = fcntl(bridge_ctrl, F_GETFD);
      if (bridge_flags >= 0)
        fcntl(bridge_ctrl, F_SETFD, bridge_flags & ~FD_CLOEXEC);
      char *const bridge_argv[] = {
          bridge_path, ctrl_number, (char *)proxy_host,
          (char *)proxy_port, max_number, NULL};
      execv(bridge_path, bridge_argv);
      fail("could not start the egress bridge");
      _exit(125);
    }
    close(bridge_ctrl);
    /* The launcher forgets the private values; the tool never sees them. */
    unsetenv(EGRESS_ENV_PROXY);
    unsetenv(EGRESS_ENV_LEASE);
    unsetenv(EGRESS_ENV_CREDENTIAL);
  }
  int content_fd = -1;
  if (strcmp(options.command[0], "write-file") == 0) {
    content_fd = read_content_fd();
    if (content_fd < 0) {
      fail("could not receive approved file content");
      return 125;
    }
  }
  char bwrap[PATH_MAX];
  if (selected_bwrap_path(bwrap) != 0) {
    fail("selected bubblewrap is unavailable");
    return 125;
  }
  char *bwrap_args[MAX_ARGS];
  size_t count = 0;
  add_arg(bwrap_args, &count, bwrap);
  add_arg(bwrap_args, &count, "--die-with-parent");
  add_arg(bwrap_args, &count, "--unshare-user");
  add_arg(bwrap_args, &count, "--unshare-pid");
  add_arg(bwrap_args, &count, "--unshare-ipc");
  add_arg(bwrap_args, &count, "--unshare-uts");
  if (strcmp(options.network, "none") == 0 ||
      strcmp(options.network, "destinations") == 0)
    add_arg(bwrap_args, &count, "--unshare-net");
  add_arg(bwrap_args, &count, "--disable-userns");
  add_arg(bwrap_args, &count, "--assert-userns-disabled");
  add_arg(bwrap_args, &count, "--ro-bind");
  add_arg(bwrap_args, &count, "/");
  add_arg(bwrap_args, &count, "/");
  add_arg(bwrap_args, &count, "--dev");
  add_arg(bwrap_args, &count, "/dev");
  add_arg(bwrap_args, &count, "--proc");
  add_arg(bwrap_args, &count, "/proc");
  for (size_t i = 0; i < options.bind_count; i++) {
    char *number = fd_string(options.binds[i].fd);
    if (!number) return 125;
    add_arg(bwrap_args, &count,
            options.binds[i].readonly ? "--ro-bind-fd" : "--bind-fd");
    add_arg(bwrap_args, &count, number);
    add_arg(bwrap_args, &count, options.binds[i].path);
  }
  qsort(options.masks, options.mask_count, sizeof(options.masks[0]), compare_masks);
  for (size_t i = 0; i < options.mask_count; i++) {
    if (mask_is_covered(&options, i)) continue;
    if (options.masks[i].directory) {
      add_arg(bwrap_args, &count, "--tmpfs");
      add_arg(bwrap_args, &count, options.masks[i].path);
      add_arg(bwrap_args, &count, "--remount-ro");
      add_arg(bwrap_args, &count, options.masks[i].path);
    } else {
      options.masks[i].placeholder_fd = (int)syscall(SYS_memfd_create, "sandbox-mask", MFD_CLOEXEC);
      if (options.masks[i].placeholder_fd < 0) return 125;
      char *number = fd_string(options.masks[i].placeholder_fd);
      if (!number) return 125;
      add_arg(bwrap_args, &count, "--perms");
      add_arg(bwrap_args, &count, "0000");
      add_arg(bwrap_args, &count, "--ro-bind-data");
      add_arg(bwrap_args, &count, number);
      add_arg(bwrap_args, &count, options.masks[i].path);
    }
  }
  if (content_fd >= 0) {
    char *number = fd_string(content_fd);
    if (!number) return 125;
    add_arg(bwrap_args, &count, "--tmpfs");
    add_arg(bwrap_args, &count, "/run");
    add_arg(bwrap_args, &count, "--dir");
    add_arg(bwrap_args, &count, "/run/plan13");
    add_arg(bwrap_args, &count, "--file");
    add_arg(bwrap_args, &count, number);
    add_arg(bwrap_args, &count, "/run/plan13/content");
  }
  add_arg(bwrap_args, &count, "--clearenv");
  add_arg(bwrap_args, &count, "--setenv");
  add_arg(bwrap_args, &count, "PATH");
  add_arg(bwrap_args, &count, "/usr/bin:/bin");
  for (size_t i = 0; i < options.env_count; i += 2) {
    add_arg(bwrap_args, &count, "--setenv");
    add_arg(bwrap_args, &count, options.env[i]);
    add_arg(bwrap_args, &count, options.env[i + 1]);
  }
  add_arg(bwrap_args, &count, "--chdir");
  add_arg(bwrap_args, &count, options.cwd);
  add_arg(bwrap_args, &count, "--");

  char executable[PATH_MAX];
  if (!realpath(argv[0], executable)) {
    fail("native launcher path could not be resolved");
    return 125;
  }
  add_arg(bwrap_args, &count, executable);
  add_arg(bwrap_args, &count, "inner");
  add_arg(bwrap_args, &count, "--process-spawn");
  add_arg(bwrap_args, &count, options.deny_process_spawn ? "deny" : "allow");
  if (options.quiet_ready) add_arg(bwrap_args, &count, "--quiet-ready");
  if (options.virtual_dev) add_arg(bwrap_args, &count, "--virtual-dev");
  if (strcmp(options.network, "none") == 0)
    add_arg(bwrap_args, &count, "--block-sockets");
  if (destinations) {
    char *number = fd_string(ctrl[1]);
    if (!number) return 125;
    add_arg(bwrap_args, &count, "--egress");
    add_arg(bwrap_args, &count, number);
  }
  for (size_t i = 0; i < options.rule_count; i++) {
    const char *flag = NULL;
    switch (options.rules[i].kind) {
      case RULE_READ_FILE: flag = "--read-file"; break;
      case RULE_READ_DIR: flag = "--read-dir"; break;
      case RULE_WRITE_FILE: flag = "--write-file"; break;
      case RULE_WRITE_DIR: flag = "--write-dir"; break;
      case RULE_EXEC_FILE: flag = "--execute-file"; break;
      case RULE_EXEC_DIR: flag = "--execute-dir"; break;
    }
    add_arg(bwrap_args, &count, (char *)flag);
    add_arg(bwrap_args, &count, options.rules[i].path);
  }
  add_arg(bwrap_args, &count, "--");
  for (size_t i = 0; options.command[i]; i++) add_arg(bwrap_args, &count, options.command[i]);

  pid_t child = fork();
  if (child < 0) {
    fail("could not fork bubblewrap");
    return 125;
  }
  if (child == 0) {
    for (size_t i = 0; i < options.mask_count; i++) {
      int fd = options.masks[i].placeholder_fd;
      if (fd < 0) continue;
      int flags = fcntl(fd, F_GETFD);
      if (flags >= 0) fcntl(fd, F_SETFD, flags & ~FD_CLOEXEC);
    }
    if (content_fd >= 0) {
      int flags = fcntl(content_fd, F_GETFD);
      if (flags >= 0) fcntl(content_fd, F_SETFD, flags & ~FD_CLOEXEC);
    }
    for (size_t i = 0; i < options.bind_count; i++) {
      int flags = fcntl(options.binds[i].fd, F_GETFD);
      if (flags >= 0) fcntl(options.binds[i].fd, F_SETFD, flags & ~FD_CLOEXEC);
    }
    execv(bwrap, bwrap_args);
    fail("could not start bubblewrap");
    _exit(125);
  }
  if (destinations) close(ctrl[1]);
  current_bwrap = (sig_atomic_t)child;
  struct sigaction action = {.sa_handler = stop_bwrap};
  sigemptyset(&action.sa_mask);
  sigaction(SIGTERM, &action, NULL);
  sigaction(SIGINT, &action, NULL);
  int status = 0;
  while (waitpid(child, &status, 0) < 0) {
    if (errno != EINTR) {
      fail("could not wait for bubblewrap");
      return 125;
    }
  }
  current_bwrap = -1;
  if (content_fd >= 0) close(content_fd);
  if (WIFEXITED(status)) return WEXITSTATUS(status);
  if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
  return 125;
}

static int parse_inner_options(int argc, char **argv, struct Options *options) {
  memset(options, 0, sizeof(*options));
  options->egress_ctrl_fd = -1;
  int abi = landlock_abi();
  if (abi < 3) {
    errno = ENOTSUP;
    return -1;
  }
  for (int i = 2; i < argc; i++) {
    if (strcmp(argv[i], "--") == 0) {
      options->command = &argv[i + 1];
      break;
    }
    if (strcmp(argv[i], "--quiet-ready") == 0) { options->quiet_ready = 1; continue; }
    if (strcmp(argv[i], "--virtual-dev") == 0) { options->virtual_dev = 1; continue; }
    if (strcmp(argv[i], "--block-sockets") == 0) {
      options->socket_mode = 1;
      continue;
    }
    if (strcmp(argv[i], "--egress") == 0) {
      if (i + 1 >= argc) {
        errno = EINVAL;
        return -1;
      }
      options->egress_ctrl_fd = atoi(argv[++i]);
      if (options->egress_ctrl_fd < 3) {
        errno = EINVAL;
        return -1;
      }
      continue;
    }
    if (strcmp(argv[i], "--process-spawn") == 0) {
      if (i + 1 >= argc || parse_process_spawn(argv[i + 1], &options->deny_process_spawn) != 0) return -1;
      i++;
      continue;
    }
    if (i + 1 >= argc || parse_rule(options, argv[i], argv[i + 1], abi, 0) != 0)
      return -1;
    i++;
  }
  if (!options->command || !options->command[0]) {
    errno = EINVAL;
    return -1;
  }
  if (options->virtual_dev &&
      (add_runtime_rule(options, "/dev", RULE_READ_DIR, LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR) != 0 ||
       add_runtime_rule(options, "/dev", RULE_WRITE_DIR, write_dir_access(abi)) != 0)) return -1;
  if (strcmp(options->command[0], "write-file") == 0 &&
      add_runtime_rule(options, "/run/plan13/content", RULE_READ_FILE,
                       LANDLOCK_ACCESS_FS_READ_FILE) != 0) {
    return -1;
  }
  return 0;
}

static int operation_error(const char *reason) {
  const char *code = errno == ENOENT || errno == ENOTDIR ? "missing" :
      errno == EACCES || errno == EPERM ? "denied" : "io";
  dprintf(STDERR_FILENO, "PI-LINUX-OP-ERROR:%s:%s\n", code, reason);
  return 1;
}

static int open_existing_file(const char *path, int flags) {
  struct open_how how = {
      .flags = (uint64_t)(flags | O_CLOEXEC),
      .resolve = RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS,
  };
  int fd = (int)syscall(SYS_openat2, AT_FDCWD, path, &how, sizeof(how));
  if (fd < 0) return -1;
  struct stat info;
  if (fstat(fd, &info) != 0 || !S_ISREG(info.st_mode)) {
    int saved = errno ? errno : EINVAL;
    close(fd);
    errno = saved;
    return -1;
  }
  return fd;
}

static int open_write_target(const char *path) {
  char parent[PATH_MAX];
  size_t length = strlen(path);
  if (length == 0 || length >= sizeof(parent)) {
    errno = ENAMETOOLONG;
    return -1;
  }
  memcpy(parent, path, length + 1);
  char *leaf = strrchr(parent, '/');
  if (!leaf || leaf[1] == '\0' || strcmp(leaf + 1, ".") == 0 ||
      strcmp(leaf + 1, "..") == 0) {
    errno = EINVAL;
    return -1;
  }
  char *name = strdup(leaf + 1);
  if (!name) return -1;
  if (leaf == parent) leaf[1] = '\0';
  else *leaf = '\0';
  int parent_fd = open_verified_path(parent, 1);
  if (parent_fd < 0) {
    free(name);
    return -1;
  }
  struct open_how how = {
      .flags = O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW,
      .mode = 0666,
      .resolve = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS,
  };
  int fd = (int)syscall(SYS_openat2, parent_fd, name, &how, sizeof(how));
  int saved = errno;
  close(parent_fd);
  free(name);
  errno = saved;
  return fd;
}

static int make_directory_tree(const char *path) {
  if (!path || path[0] != '/') {
    errno = EINVAL;
    return -1;
  }
  int current = open("/", O_PATH | O_DIRECTORY | O_CLOEXEC);
  if (current < 0) return -1;
  const char *cursor = path + 1;
  while (*cursor) {
    while (*cursor == '/') cursor++;
    if (!*cursor) break;
    const char *end = strchr(cursor, '/');
    size_t length = end ? (size_t)(end - cursor) : strlen(cursor);
    if (length == 0 || length >= NAME_MAX) {
      close(current);
      errno = ENAMETOOLONG;
      return -1;
    }
    char name[NAME_MAX + 1];
    memcpy(name, cursor, length);
    name[length] = '\0';
    if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) {
      close(current);
      errno = EINVAL;
      return -1;
    }
    struct open_how how = {
        .flags = O_PATH | O_DIRECTORY | O_CLOEXEC,
        .resolve = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS,
    };
    int next = (int)syscall(SYS_openat2, current, name, &how, sizeof(how));
    if (next < 0 && errno == ENOENT) {
      if (mkdirat(current, name, 0777) != 0 && errno != EEXIST) {
        int saved = errno;
        close(current);
        errno = saved;
        return -1;
      }
      next = (int)syscall(SYS_openat2, current, name, &how, sizeof(how));
    }
    if (next < 0) {
      int saved = errno;
      close(current);
      errno = saved;
      return -1;
    }
    close(current);
    current = next;
    cursor = end ? end + 1 : cursor + length;
  }
  close(current);
  return 0;
}

static int run_file_operation(char **command) {
  if (strcmp(command[0], "read-file") == 0 && command[1]) {
    int fd = open_existing_file(command[1], O_RDONLY);
    if (fd < 0) return operation_error("could not read approved file");
    size_t total = 0;
    char buffer[16 * 1024];
    for (;;) {
      ssize_t count = read(fd, buffer, sizeof(buffer));
      if (count < 0 && errno == EINTR) continue;
      if (count < 0) {
        int saved = errno;
        close(fd);
        errno = saved;
        return operation_error("could not read approved file");
      }
      if (count == 0) break;
      total += (size_t)count;
      if (total > MAX_FILE_BYTES) {
        close(fd);
        dprintf(STDERR_FILENO, "PI-LINUX-OP-ERROR:unsupported:file exceeds the native result limit\n");
        return 1;
      }
      size_t offset = 0;
      while (offset < (size_t)count) {
        ssize_t written = write(STDOUT_FILENO, buffer + offset, (size_t)count - offset);
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) {
          close(fd);
          return 1;
        }
        offset += (size_t)written;
      }
    }
    close(fd);
    return 0;
  }
  if (strcmp(command[0], "write-file") == 0 && command[1]) {
    int source = open_existing_file("/run/plan13/content", O_RDONLY);
    if (source < 0) return operation_error("approved content could not be staged");
    int target = open_write_target(command[1]);
    if (target < 0) {
      int saved = errno;
      close(source);
      errno = saved;
      return operation_error("could not write approved file");
    }
    size_t total = 0;
    char buffer[16 * 1024];
    for (;;) {
      ssize_t count = read(source, buffer, sizeof(buffer));
      if (count < 0 && errno == EINTR) continue;
      if (count < 0) {
        int saved = errno;
        close(source);
        close(target);
        errno = saved;
        return operation_error("could not read approved content");
      }
      if (count == 0) break;
      total += (size_t)count;
      if (total > MAX_FILE_BYTES) {
        close(source);
        close(target);
        errno = EFBIG;
        return operation_error("approved content exceeds the native result limit");
      }
      size_t offset = 0;
      while (offset < (size_t)count) {
        ssize_t written = write(target, buffer + offset, (size_t)count - offset);
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) {
          int saved = errno ? errno : EIO;
          close(source);
          close(target);
          errno = saved;
          return operation_error("could not write approved file");
        }
        offset += (size_t)written;
      }
    }
    close(source);
    close(target);
    return 0;
  }
  if (strcmp(command[0], "access-file") == 0 && command[1] && command[2]) {
    int flags = strcmp(command[2], "read-write") == 0 ? O_RDWR : O_RDONLY;
    int fd = open_existing_file(command[1], flags);
    if (fd < 0) return operation_error("approved file access was denied");
    close(fd);
    return 0;
  }
  if (strcmp(command[0], "access-dir") == 0 && command[1]) {
    int fd = open_verified_path(command[1], 1);
    if (fd < 0) return operation_error("approved directory does not exist");
    close(fd);
    return 0;
  }
  if (strcmp(command[0], "mkdir") == 0 && command[1]) {
    if (make_directory_tree(command[1]) != 0) {
      return operation_error("could not create approved directory");
    }
    return 0;
  }
  dprintf(STDERR_FILENO, "PI-LINUX-OP-ERROR:unsupported:operation is not supported\n");
  return 1;
}

static int run_inner(int argc, char **argv) {
  struct Options options;
  if (parse_inner_options(argc, argv, &options) != 0) {
    fail("invalid Landlock rule");
    return 125;
  }
  if (options.egress_ctrl_fd >= 0) {
    /*
     * Establish the controlled entry before any restriction applies: create
     * the loopback listener inside the isolated network, hand it to the
     * bridge, and wait for the bridge's acknowledgement. A failed handoff
     * aborts here, so the tool never starts without its only network exit.
     */
    char port[16];
    if (egress_handoff(options.egress_ctrl_fd, port, sizeof(port)) != 0) {
      fail("could not establish the controlled network entry");
      return 125;
    }
    close(options.egress_ctrl_fd);
    options.egress_ctrl_fd = -1;
    char http_value[64];
    char socks_value[72];
    snprintf(http_value, sizeof(http_value), "http://127.0.0.1:%s", port);
    snprintf(socks_value, sizeof(socks_value), "socks5h://127.0.0.1:%s", port);
    /*
     * Point the standard client hints at the sandbox entry and clear every
     * alternate route hint. These are only client hints: direct sockets
     * still die in the isolated network.
     */
    setenv("HTTP_PROXY", http_value, 1);
    setenv("http_proxy", http_value, 1);
    setenv("HTTPS_PROXY", http_value, 1);
    setenv("https_proxy", http_value, 1);
    setenv("ALL_PROXY", socks_value, 1);
    setenv("all_proxy", socks_value, 1);
    setenv("NO_PROXY", "", 1);
    setenv("no_proxy", "", 1);
    unsetenv(EGRESS_ENV_PROXY);
    unsetenv(EGRESS_ENV_LEASE);
    unsetenv(EGRESS_ENV_CREDENTIAL);
    if (unexpected_descriptors_present()) {
      fail("unexpected descriptor survived preparation");
      return 125;
    }
    options.socket_mode = 2;
  }
  if (apply_restrictions(&options) != 0) {
    fail("could not apply Landlock and seccomp restrictions");
    return 125;
  }
  if (options.command[0][0] == '/') {
    execv(options.command[0], options.command);
    fail("could not start the approved command");
    return 127;
  }
  return run_file_operation(options.command);
}

int main(int argc, char **argv) {
  if (argc == 2 && strcmp(argv[1], "probe") == 0) return probe();
  if (argc >= 2 && strcmp(argv[1], "run") == 0) return run_parent(argc, argv);
  if (argc >= 2 && strcmp(argv[1], "inner") == 0) return run_inner(argc, argv);
  dprintf(STDERR_FILENO, "usage: linux-sandbox probe|run|inner\n");
  return 2;
}
