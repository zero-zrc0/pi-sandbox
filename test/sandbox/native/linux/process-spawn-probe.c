#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/sched.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define STACK_SIZE (1024U * 1024U)

static void mark_and_exit(const char *path) {
  long fd = syscall(SYS_openat, AT_FDCWD, path,
                    O_CREAT | O_TRUNC | O_WRONLY, 0600);
  if (fd >= 0) {
    syscall(SYS_write, fd, "child", 5);
    syscall(SYS_close, fd);
    syscall(SYS_exit, 0);
  }
  syscall(SYS_exit, 91);
}

static int write_marker(const char *path) {
  int fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0600);
  if (fd < 0) return -1;
  int result = write(fd, "child", 5) == 5 ? 0 : -1;
  close(fd);
  return result;
}

static void report_errno(void) {
  printf("error=%d\n", errno);
}

static void report_child(long child, const char *path) {
  if (child == 0) mark_and_exit(path);
  if (child < 0) {
    report_errno();
    return;
  }
  int status = 0;
  if (waitpid((pid_t)child, &status, 0) == child &&
      WIFEXITED(status) && WEXITSTATUS(status) == 0) {
    puts("spawned");
  } else {
    puts("child-failed");
  }
}

static int marker_child(void *arg) {
  return write_marker((const char *)arg) == 0 ? 0 : 91;
}

static void *thread_write_marker(void *arg) {
  return (void *)(intptr_t)(write_marker((const char *)arg) == 0 ? 0 : 1);
}

static void run_clone(unsigned long flags, const char *path) {
  char *stack = mmap(NULL, STACK_SIZE, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (stack == MAP_FAILED) {
    report_errno();
    return;
  }
  int child = clone(marker_child, stack + STACK_SIZE, (int)flags, (void *)path);
  if (child < 0) {
    report_errno();
    munmap(stack, STACK_SIZE);
    return;
  }
  int status = 0;
  if (waitpid(child, &status, 0) == child &&
      WIFEXITED(status) && WEXITSTATUS(status) == 0) {
    puts("spawned");
  } else {
    puts("child-failed");
  }
  munmap(stack, STACK_SIZE);
}

static void run_thread(const char *path) {
  pthread_t thread;
  int error = pthread_create(&thread, NULL, thread_write_marker, (void *)path);
  if (error != 0) {
    printf("error=%d\n", error);
    return;
  }
  void *result = NULL;
  error = pthread_join(thread, &result);
  if (error != 0) {
    printf("error=%d\n", error);
    return;
  }
  puts((intptr_t)result == 0 ? "thread" : "thread-failed");
}

static void run_vfork(const char *path) {
  pid_t child = vfork();
  if (child == 0) _exit(0);
  if (child < 0) {
    report_errno();
    return;
  }
  int status = 0;
  if (waitpid(child, &status, 0) == child &&
      WIFEXITED(status) && WEXITSTATUS(status) == 0 && write_marker(path) == 0) {
    puts("spawned");
  } else {
    puts("child-failed");
  }
}

int main(int argc, char **argv) {
  if (argc != 3) return 2;
  const char *mode = argv[1];
  const char *path = argv[2];
  if (strcmp(mode, "fork") == 0) {
#ifdef SYS_fork
    report_child(syscall(SYS_fork), path);
#else
    report_child(fork(), path);
#endif
  } else if (strcmp(mode, "vfork") == 0) {
    run_vfork(path);
  } else if (strcmp(mode, "clone-process") == 0) {
    run_clone(SIGCHLD, path);
  } else if (strcmp(mode, "clone-vm-process") == 0) {
    run_clone(CLONE_VM | SIGCHLD, path);
  } else if (strcmp(mode, "clone-vfork") == 0) {
    run_clone(CLONE_VM | CLONE_VFORK | SIGCHLD, path);
  } else if (strcmp(mode, "clone-namespace") == 0) {
    run_clone(CLONE_NEWUSER | SIGCHLD, path);
  } else if (strcmp(mode, "clone-thread-missing") == 0) {
    run_clone(CLONE_THREAD | SIGCHLD, path);
  } else if (strcmp(mode, "clone-thread-signal") == 0) {
    run_clone(CLONE_VM | CLONE_SIGHAND | CLONE_THREAD | SIGCHLD, path);
  } else if (strcmp(mode, "clone-high") == 0) {
    unsigned long long flags = (1ULL << 32) | SIGCHLD;
    report_child(syscall(SYS_clone, flags, NULL, NULL, NULL, NULL), path);
  } else if (strcmp(mode, "clone3") == 0) {
#ifdef SYS_clone3
    struct clone_args args = {.exit_signal = SIGCHLD};
    report_child(syscall(SYS_clone3, &args, sizeof(args)), path);
#else
    errno = ENOSYS;
    report_errno();
#endif
  } else if (strcmp(mode, "thread") == 0) {
    run_thread(path);
  } else {
    return 2;
  }
  return 0;
}
