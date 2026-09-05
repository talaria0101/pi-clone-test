// Continuous /proc/pid/mem scraper: runs target as child, periodically dumps
// writable+exec mappings and greps memory for decoded-looking strings.
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

static int dump_round = 0;

static void dump_maps(pid_t pid) {
    char path[64];
    snprintf(path, sizeof path, "/proc/%d/maps", pid);
    FILE *f = fopen(path, "r");
    if (!f) return;
    snprintf(path, sizeof path, "/proc/%d/mem", pid);
    int mem = open(path, O_RDONLY);
    char line[512];
    char out[256];
    snprintf(out, sizeof out, "round%d_%d", dump_round, (int)pid);
    FILE *o = fopen(out, "wb");
    while (fgets(line, sizeof line, f)) {
        unsigned long lo, hi;
        char perms[8], name[256] = "";
        if (sscanf(line, "%lx-%lx %4s %*s %*s %*s %255[^\n]", &lo, &hi, perms, name) < 3) continue;
        // dump writable OR anonymous-exec regions (where decrypted code/strings live)
        int anon = (name[0] == 0);
        int want = (perms[1] == 'w') || (anon && perms[2] == 'x');
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
    fclose(o);
    fclose(f);
    close(mem);
}

int main(int argc, char **argv) {
    // argv[1] = exe, rest = args; env from SOBERENV_* not needed, pass through
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
    for (int round = 0; round < 40; round++) {
        dump_round = round;
        dump_maps(pid);
        usleep(200000);
        if (kill(pid, 0) != 0) break;  // dead
    }
    kill(pid, SIGKILL);
    waitpid(pid, NULL, 0);
    return 0;
}
