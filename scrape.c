// v2: walk all descendant pids; dump status (TracerPid!), maps; scrape writable/anon-exec memory.
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <signal.h>
#include <sys/wait.h>
#include <errno.h>
#include <dirent.h>

static int round_no = 0;

static int is_descendant(pid_t root, pid_t p) {
    // walk /proc/p/stat ppid chain up to root
    for (int depth = 0; depth < 12 && p > 1; depth++) {
        if (p == root) return 1;
        char path[64]; snprintf(path, sizeof path, "/proc/%d/stat", p);
        FILE *f = fopen(path, "r");
        if (!f) return 0;
        int pid_, ppid_ = 0;
        char comm[128];
        if (fscanf(f, "%d (%127[^)]) %*c %d", &pid_, comm, &ppid_) < 3) { fclose(f); return 0; }
        fclose(f);
        if (ppid_ <= 1) break;
        p = ppid_;
    }
    return p == root;
}

static void dump_proc(pid_t root, pid_t pid) {
    char path[128], out[256];
    snprintf(path, sizeof path, "/proc/%d/status", pid);
    FILE *s = fopen(path, "r");
    snprintf(out, sizeof out, "r%d_%d.status", round_no, pid);
    FILE *o = fopen(out, "w");
    if (s && o) {
        char line[512];
        while (fgets(line, sizeof line, s)) {
            if (strncmp(line, "Name:", 5)==0 || strncmp(line, "Pid:", 4)==0 ||
                strncmp(line, "PPid:", 5)==0 || strncmp(line, "State:", 6)==0 ||
                strncmp(line, "TracerPid:", 10)==0 || strncmp(line, "Seccomp:", 8)==0 ||
                strncmp(line, "Seccomp_filters:", 16)==0 || strncmp(line, "Threads:", 8)==0)
                fputs(line, o);
        }
    }
    if (s) fclose(s);
    if (o) fclose(o);

    snprintf(path, sizeof path, "/proc/%d/cmdline", pid);
    o = fopen(out, "a");
    if (o) {
        FILE *c = fopen(path, "r");
        if (c) { char buf[1024]; size_t n = fread(buf, 1, sizeof buf-1, c); fclose(c);
                 for (size_t i = 0; i < n; i++) if (buf[i]==0) buf[i]=' ';
                 fprintf(o, "Cmdline: %.*s\n", (int)n, buf); }
        snprintf(path, sizeof path, "/proc/%d/maps", pid);
        FILE *m = fopen(path, "r");
        if (m) {
            fprintf(o, "--- maps:\n");
            char l[512];
            while (fgets(l, sizeof l, m)) fputs(l, o);
            fclose(m);
        }
        fclose(o);
    }

    // memory scrape
    snprintf(path, sizeof path, "/proc/%d/mem", pid);
    int mem = open(path, O_RDONLY);
    if (mem < 0) return;
    snprintf(path, sizeof path, "/proc/%d/maps", pid);
    FILE *m = fopen(path, "r");
    if (!m) { close(mem); return; }
    snprintf(out, sizeof out, "r%d_%d.mem", round_no, pid);
    o = fopen(out, "wb");
    char line[512];
    while (fgets(line, sizeof line, m)) {
        unsigned long lo, hi; char perms[8], name[256] = "";
        if (sscanf(line, "%lx-%lx %4s %*s %*s %*s %255[^\n]", &lo, &hi, perms, name) < 3) continue;
        int anon = (name[0] == 0);
        int want = (perms[1] == 'w') || (perms[2] == 'x');
        if (!want) continue;
        size_t len = hi - lo;
        if (len > 64*1024*1024) len = 64*1024*1024;
        unsigned char *buf = malloc(len);
        ssize_t r = pread(mem, buf, len, (off_t)lo);
        if (r > 0) {
            unsigned long hdr[3] = {lo, (unsigned long)r, 0};
            fwrite(hdr, 8, 3, o);
            fwrite(buf, 1, r, o);
        }
        free(buf);
    }
    fclose(o); fclose(m); close(mem);
}

int main(int argc, char **argv) {
    pid_t pid = fork();
    if (pid == 0) {
        setsid();
        int dn = open("/dev/null", O_RDONLY);
        dup2(dn, 0);
        char **nargv = calloc(argc, sizeof(char*));
        for (int i = 1; i < argc; i++) nargv[i-1] = argv[i];
        nargv[argc-1] = NULL;
        execv(argv[1], nargv);
        _exit(127);
    }
    fprintf(stderr, "[scrape] child %d\n", pid);
    for (round_no = 0; round_no < 30; round_no++) {
        DIR *d = opendir("/proc");
        struct dirent *de;
        while ((de = readdir(d))) {
            pid_t p = atoi(de->d_name);
            if (p > 1 && (p == pid || is_descendant(pid, p)))
                dump_proc(pid, p);
        }
        closedir(d);
        usleep(200000);
        if (kill(pid, 0) != 0) break;
    }
    // final wait
    int st; waitpid(pid, &st, 0);
    fprintf(stderr, "[scrape] child exit status %d\n", st);
    return 0;
}
