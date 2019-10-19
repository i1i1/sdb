#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <ctype.h>

//#include <asm/unistd.h>

#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>

#include "macro.h"
#include "utils.h"
#include "obj.h"
#include "dwarf.h"
#include "vector.h"


int target_pid = -1;
int insyscall = 0;

void
usage(void)
{
    fprintf(stderr, "USAGE:\n"
            "\n"
            "program debugee [debugee-args]\n");
}

void
ptrace_traceme() {
    int ret;

    ret = ptrace(PTRACE_TRACEME, 0, NULL, NULL);
    if (ret != 0)
        error("TRACEME error");
    kill(getpid(), SIGSTOP);
}

pid_t
start_debugee(const char **argv)
{
    pid_t pid;
    int st;

    pid = fork();
    switch (pid) {
    case 0:
        printf("executing %s\n", argv[0]);
        ptrace_traceme();
        execvp(argv[0], (char * const *)argv);
        exit(0);
    case -1:
        error("fork error");
    default:
        break;
    }

    waitpid(pid, &st, WSTOPPED);
    ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD);

    return pid;
}

void
test_dwarf(const char *fn)
{
    struct obj *o;

    if ((o = obj_init(fn)) == NULL)
        error("Not an object\n");

    for (;;) {
        char *buf;
        size_t len;

        printf(">> ");
        getline(&buf, &len, stdin);

        if (STREQ(buf, "end\n"))
            break;

        size_t addr = 0;
        int i;

        for (i = 0; buf[i] && isxdigit(buf[i]); i++) {
            addr *= 16;
            if ('0' <= buf[i] && buf[i] <= '9')
                addr += buf[i] - '0';
            else if ('A' <= buf[i] && buf[i] <= 'F')
                addr += buf[i] - 'A' + 10;
            else// if ('a' <= buf[i] && buf[i] <= 'f')
                addr += buf[i] - 'a' + 10;
        }

        if (buf[i] != '\n') {
            printf("Error!\n");
            free(buf);
        }

        struct line ln = dwarf_addr2line(o, addr);

        printf("\t%s:%d\n", ln.fn, ln.nu);
        free(buf);
    }

    printf("File size = %ld\n", o->sz);
    obj_deinit(o);
}

int
main(int argc, const char *argv[])
{
    long ret;
    int st;
    pid_t pid;
    struct user_regs_struct regs;

    if (argc < 2) {
        usage();
        exit(1);
    }

    argv++;

    test_dwarf(argv[0]);
    pid = start_debugee(argv);

    return 0;

    printf("after attach\n");

    while (true) {
        ret = ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
        if (ret)
            error("PTRACE_SYSCALL error");

        ret = waitpid(pid, &st, 0);
        if (ret < 0)
            error("waitpid error");

        if (WIFEXITED(st)) {
            printf("child exited\n");
            break;
        }
        if (WIFSTOPPED(st) && (WSTOPSIG(st) == (SIGTRAP | 0x80))) {
            insyscall = !insyscall;

            printf("syscall %s ", insyscall ? "entering" : "exiting");
            ret = ptrace(PTRACE_GETREGS, pid, NULL, &regs);
            if (ret)
                printf("can't get regs\n");
            if (!insyscall) {
//                print_ret_status(&regs);
            } else {
//                print_regs(&regs);
            }
            printf("\n");
        }
    }

    ptrace(PTRACE_DETACH, pid, NULL, NULL);

    return 0;
}

