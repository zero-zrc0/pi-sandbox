/*
 * Standalone egress bridge for the Linux sandbox.
 *
 * The launcher creates a Unix control socketpair and forks this process
 * before the sandbox starts. The sandboxed inner process hands over one TCP
 * listen socket that lives in the isolated network namespace; this bridge
 * holds that fd, accepts tool connections on it, and forwards each one to the
 * fixed Pi policy proxy with the lease's source-authentication frame.
 *
 * The bridge parses no tool intent, evaluates no permissions and never falls
 * back to a direct connection. It exits when its parent dies (PDEATHSIG) or
 * when the handed-over listener breaks.
 *
 * argv: linux-egress-bridge <ctrl-fd> <proxy-host> <proxy-port> <max-conn>
 * env:  PI_EGRESS_LEASE, PI_EGRESS_CREDENTIAL (private; never on argv)
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define RELAY_BUFFER_BYTES (16 * 1024)
#define MAX_PENDING_CONN 64

static void fail(const char *message) {
  dprintf(STDERR_FILENO, "linux-egress-bridge: %s: %s\n", message,
           strerror(errno));
}

static int wait_writable(int fd, int timeout_ms) {
  struct pollfd entry = {.fd = fd, .events = POLLOUT};
  for (;;) {
    int result = poll(&entry, 1, timeout_ms);
    if (result < 0 && errno == EINTR) continue;
    return result;
  }
}

static int write_all(int fd, const char *buffer, size_t length) {
  size_t offset = 0;
  while (offset < length) {
    ssize_t written = write(fd, buffer + offset, length - offset);
    if (written < 0 && errno == EINTR) continue;
    if (written < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
      if (wait_writable(fd, 5000) <= 0) return -1;
      continue;
    }
    if (written <= 0) return -1;
    offset += (size_t)written;
  }
  return 0;
}

/* One accepted tool connection: authenticate upstream, then relay both ways. */
static int run_connection(int tool_fd, const char *proxy_host,
                          const char *proxy_port, const char *lease,
                          const char *credential) {
  struct addrinfo hints;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  struct addrinfo *addresses = NULL;
  if (getaddrinfo(proxy_host, proxy_port, &hints, &addresses) != 0 ||
      !addresses) {
    fail("could not resolve the fixed policy proxy address");
    return 1;
  }
  int proxy_fd = -1;
  for (struct addrinfo *item = addresses; item; item = item->ai_next) {
    int candidate =
        socket(item->ai_family, item->ai_socktype, item->ai_protocol);
    if (candidate < 0) continue;
    if (connect(candidate, item->ai_addr, item->ai_addrlen) == 0) {
      proxy_fd = candidate;
      break;
    }
    close(candidate);
  }
  freeaddrinfo(addresses);
  if (proxy_fd < 0) {
    fail("could not connect to the fixed policy proxy");
    return 1;
  }

  char frame[4096];
  int frame_length =
      snprintf(frame, sizeof(frame), "PIEGRESS1 %s %s\n", lease, credential);
  if (frame_length <= 0 || frame_length >= (int)sizeof(frame) ||
      write_all(proxy_fd, frame, (size_t)frame_length) != 0) {
    fail("could not send the source authentication frame");
    close(proxy_fd);
    return 1;
  }

  char buffer[RELAY_BUFFER_BYTES];
  int tool_open = 1;
  int proxy_open = 1;
  while (tool_open || proxy_open) {
    struct pollfd entries[2];
    size_t count = 0;
    size_t tool_index = 0;
    size_t proxy_index = 0;
    if (tool_open) {
      tool_index = count;
      entries[count++] = (struct pollfd){.fd = tool_fd, .events = POLLIN};
    }
    if (proxy_open) {
      proxy_index = count;
      entries[count++] = (struct pollfd){.fd = proxy_fd, .events = POLLIN};
    }
    int ready = poll(entries, count, -1);
    if (ready < 0) {
      if (errno == EINTR) continue;
      break;
    }
    for (size_t index = 0; index < count; index += 1) {
      if (!(entries[index].revents & (POLLIN | POLLHUP | POLLERR))) continue;
      int source = entries[index].fd;
      int destination = source == tool_fd ? proxy_fd : tool_fd;
      ssize_t received = read(source, buffer, sizeof(buffer));
      if (received < 0) {
        if (errno == EINTR) continue;
        received = 0;
      }
      if (received == 0) {
        if (source == tool_fd) {
          tool_open = 0;
          shutdown(proxy_fd, SHUT_WR);
        } else {
          proxy_open = 0;
          shutdown(tool_fd, SHUT_WR);
        }
        continue;
      }
      if (write_all(destination, buffer, (size_t)received) != 0) {
        tool_open = 0;
        proxy_open = 0;
      }
    }
    (void)tool_index;
    (void)proxy_index;
  }
  close(proxy_fd);
  close(tool_fd);
  return 0;
}

static volatile sig_atomic_t child_died = 0;

static void on_sigchld(int signal_number) {
  (void)signal_number;
  child_died = 1;
}

static void reap_children(void) {
  for (;;) {
    pid_t child = waitpid(-1, NULL, WNOHANG);
    if (child <= 0) break;
  }
  child_died = 0;
}

int main(int argc, char **argv) {
  if (argc != 5) {
    dprintf(STDERR_FILENO,
            "usage: linux-egress-bridge <ctrl-fd> <proxy-host> <proxy-port> "
            "<max-connections>\n");
    return 2;
  }
  int ctrl_fd = atoi(argv[1]);
  const char *proxy_host = argv[2];
  const char *proxy_port = argv[3];
  int max_connections = atoi(argv[4]);
  const char *lease = getenv("PI_EGRESS_LEASE");
  const char *credential = getenv("PI_EGRESS_CREDENTIAL");
  if (ctrl_fd < 3 || !proxy_host || !proxy_port || max_connections < 1 ||
      max_connections > MAX_PENDING_CONN || !lease || !credential ||
      strchr(lease, '\n') || strchr(credential, '\n')) {
    dprintf(STDERR_FILENO, "linux-egress-bridge: invalid launch environment\n");
    return 2;
  }

  /* Die with the launcher; handle the race where the parent already exited. */
  if (prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) != 0) {
    fail("could not set the parent death signal");
    return 1;
  }
  if (getppid() == 1) return 1;
  if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0) {
    fail("could not disable core dumps");
    return 1;
  }

  /* Receive the sandbox listen socket over the control channel. */
  char control[CMSG_SPACE(sizeof(int))];
  char note[64];
  struct iovec iov = {.iov_base = note, .iov_len = sizeof(note) - 1};
  struct msghdr message;
  memset(&message, 0, sizeof(message));
  message.msg_iov = &iov;
  message.msg_iovlen = 1;
  message.msg_control = control;
  message.msg_controllen = sizeof(control);
  ssize_t received;
  do {
    received = recvmsg(ctrl_fd, &message, 0);
  } while (received < 0 && errno == EINTR);
  if (received < 0) {
    fail("could not receive the listen socket");
    return 1;
  }
  struct cmsghdr *header = CMSG_FIRSTHDR(&message);
  if (!header || header->cmsg_level != SOL_SOCKET ||
      header->cmsg_type != SCM_RIGHTS) {
    dprintf(STDERR_FILENO, "linux-egress-bridge: control message carried no fd\n");
    return 1;
  }
  int listen_fd;
  memcpy(&listen_fd, CMSG_DATA(header), sizeof(int));
  if (message.msg_flags & MSG_CTRUNC) {
    dprintf(STDERR_FILENO, "linux-egress-bridge: truncated control message\n");
    close(listen_fd);
    return 1;
  }

  /* Validate what was handed over: a TCP listening socket on loopback. */
  int type = 0;
  socklen_t type_length = sizeof(type);
  int accepting = 0;
  socklen_t accepting_length = sizeof(accepting);
  struct sockaddr_storage local;
  socklen_t local_length = sizeof(local);
  if (getsockopt(listen_fd, SOL_SOCKET, SO_TYPE, &type, &type_length) != 0 ||
      type != SOCK_STREAM ||
      getsockopt(listen_fd, SOL_SOCKET, SO_ACCEPTCONN, &accepting,
                 &accepting_length) != 0 ||
      accepting == 0 ||
      getsockname(listen_fd, (struct sockaddr *)&local, &local_length) != 0 ||
      local.ss_family != AF_INET ||
      ntohs(((struct sockaddr_in *)&local)->sin_port) == 0) {
    dprintf(STDERR_FILENO,
            "linux-egress-bridge: handed fd is not a loopback TCP listener\n");
    close(listen_fd);
    return 1;
  }
  struct in_addr loopback = {.s_addr = htonl(INADDR_LOOPBACK)};
  if (((struct sockaddr_in *)&local)->sin_addr.s_addr != loopback.s_addr) {
    dprintf(STDERR_FILENO,
            "linux-egress-bridge: listener must live on sandbox loopback\n");
    close(listen_fd);
    return 1;
  }

  /* Acknowledge so the sandboxed inner can finish preparing. */
  if (write_all(ctrl_fd, "K", 1) != 0) {
    fail("could not acknowledge the handoff");
    close(listen_fd);
    return 1;
  }
  close(ctrl_fd);

  /* The bridge keeps exactly one descriptor: the handed-over listener. */
  {
    DIR *directory = opendir("/proc/self/fd");
    if (directory) {
      int self_dir = dirfd(directory);
      int found[256];
      size_t count = 0;
      struct dirent *entry;
      while ((entry = readdir(directory)) != NULL) {
        if (entry->d_name[0] == '.') continue;
        char *end = NULL;
        long fd = strtol(entry->d_name, &end, 10);
        if (!end || *end != '\0' || fd <= 2) continue;
        if ((int)fd == self_dir || (int)fd == listen_fd) continue;
        if (count < sizeof(found) / sizeof(found[0])) found[count++] = (int)fd;
      }
      closedir(directory);
      for (size_t index = 0; index < count; index += 1)
        close(found[index]);
    }
  }

  struct sigaction action;
  memset(&action, 0, sizeof(action));
  action.sa_handler = on_sigchld;
  sigemptyset(&action.sa_mask);
  sigaction(SIGCHLD, &action, NULL);

  int active = 0;
  for (;;) {
    if (child_died) reap_children();
    while (active >= max_connections) {
      int status = 0;
      pid_t done = waitpid(-1, &status, 0);
      if (done > 0) active -= 1;
      else if (done < 0 && errno != EINTR) break;
      if (child_died) reap_children();
    }
    int tool_fd = accept4(listen_fd, NULL, NULL, SOCK_CLOEXEC);
    if (tool_fd < 0) {
      if (errno == EINTR) continue;
      /* The sandbox is gone (or the listener broke): exit quietly. */
      break;
    }
    pid_t child = fork();
    if (child == 0) {
      close(listen_fd);
      int result = run_connection(tool_fd, proxy_host, proxy_port, lease,
                                  credential);
      _exit(result);
    }
    close(tool_fd);
    if (child < 0) continue;
    active += 1;
  }
  /* The listen fd is the only bridge-held resource; closing ends everything. */
  close(listen_fd);
  while (waitpid(-1, NULL, 0) > 0) {
    /* Reap every in-flight connection before exiting. */
  }
  return 0;
}
