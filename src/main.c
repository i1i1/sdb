#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

#include <asm/unistd.h>

#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>

#include "macro.h"
#include "obj.h"
#include "dwarf2.h"

#define VECTOR_IMPLEMENTATION
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
load_debug_info(const char *fn)
{
    struct obj *o;
    struct sect dinfo, dabbrev;

    if ((o = obj_init(fn)) == NULL)
        error("Not an object\n");

    dinfo    = obj_get_sect_by_name(o, ".debug_info");
    dabbrev  = obj_get_sect_by_name(o, ".debug_abbrev");

    if (dinfo.name == NULL)
        error("No `.debug_info' section\n");
    if (dabbrev.name == NULL)
        error("No `.debug_abbrev' section\n");

    printf("dinfo_len   = 0x%lx\n", dinfo.size);
    printf("dabbrev_len = 0x%lx\n", dabbrev.size);
    printf("\n");

    struct dwarf2_cuh cuh = dwarf2_cuh_decode(&dinfo);

    if (cuh.ver != 2)
        error("Not a dwarf2 format. Instead dwarf%d\n", cuh.ver);

    printf("Compilation unit\n");
    printf("contrib_len = 0x%x\n", cuh.contrib_len);
    printf("abbrev_off  = 0x%x\n", cuh.abbrev_off);
    printf("uleb        = 0x%lx\n", cuh.uleb);
    printf("\n");

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

    load_debug_info(argv[0]);
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

