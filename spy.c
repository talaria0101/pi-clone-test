// Minimal raw-syscall spy for sober: log openat/statx/execve/getenv via write to fd
#define _GNU_SOURCE
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <dlfcn.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>

static int logfd(void) {
    static int fd = -2;
    if (fd == -2) {
        fd = (int)syscall(SYS_openat, AT_FDCWD, "/tmp/spy2.log", O_WRONLY|O_CREAT|O_APPEND|O_CLOEXEC, 0644);
    }
    return fd;
}
static void put(const char *s, long n) { int fd = logfd(); if (fd >= 0) syscall(SYS_write, fd, s, n); }
static void puts_(const char *s) { put(s, strlen(s)); }
static void puthex(unsigned long v) {
    char b[19]; b[0] = '0'; b[1] = 'x';
    for (int i = 0; i < 16; i++) {
        int d = (v >> (60 - 4*i)) & 0xf;
        b[2+i] = d < 10 ? '0'+d : 'a'+d-10;
    }
    b[18] = 0; puts_(b);
}

int openat(int dirfd, const char *path, int flags, ...) {
    static int (*real)(int, const char*, int, ...);
    if (!real) real = dlsym(RTLD_NEXT, "openat");
    int r = real(dirfd, path, flags, 0);
    puts_("[openat] "); puts_(path); puts_(" -> "); puthex((unsigned long)r); puts_("\n");
    return r;
}
int open64(const char *path, int flags, ...) {
    static int (*real)(const char*, int, ...);
    if (!real) real = dlsym(RTLD_NEXT, "open64");
    int r = real(path, flags, 0);
    puts_("[open64] "); puts_(path); puts_(" -> "); puthex((unsigned long)r); puts_("\n");
    return r;
}
int open(const char *path, int flags, ...) {
    static int (*real)(const char*, int, ...);
    if (!real) real = dlsym(RTLD_NEXT, "open");
    int r = real(path, flags, 0);
    puts_("[open] "); puts_(path); puts_(" -> "); puthex((unsigned long)r); puts_("\n");
    return r;
}
int stat64(const char *path, void *st) {
    static int (*real)(const char*, void*);
    if (!real) real = dlsym(RTLD_NEXT, "stat64");
    int r = real(path, st);
    puts_("[stat64] "); puts_(path); puts_(" -> "); puthex((unsigned long)r); puts_("\n");
    return r;
}
int statx(int dirfd, const char *path, int flags, unsigned mask, void *stx) {
    static int (*real)(int, const char*, int, unsigned, void*);
    if (!real) real = dlsym(RTLD_NEXT, "statx");
    int r = real(dirfd, path, flags, mask, stx);
    puts_("[statx] "); puts_(path); puts_(" -> "); puthex((unsigned long)r); puts_("\n");
    return r;
}
char *getenv(const char *name) {
    static char *(*real)(const char*);
    if (!real) real = dlsym(RTLD_NEXT, "getenv");
    char *r = real(name);
    puts_("[getenv] "); puts_(name); puts_(" -> "); puts_(r ? r : "(nil)"); puts_("\n");
    return r;
}
int execve(const char *path, char *const argv[], char *const envp[]) {
    puts_("[execve] "); puts_(path); puts_("\n");
    for (char *const *e = envp; e && *e; e++) { puts_("  env: "); puts_(*e); puts_("\n"); }
    static int (*real)(const char*, char *const[], char *const[]);
    if (!real) real = dlsym(RTLD_NEXT, "execve");
    return real(path, argv, envp);
}
ssize_t readlink(const char *path, char *buf, size_t n) {
    static ssize_t (*real)(const char*, char*, size_t);
    if (!real) real = dlsym(RTLD_NEXT, "readlink");
    ssize_t r = real(path, buf, n);
    puts_("[readlink] "); puts_(path); puts_("\n");
    return r;
}
