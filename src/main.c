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

#define VECTOR_IMPLEMENTATION
#include "vector.h"

#define error(args...) do { fprintf(stderr, args); exit(1); } while(0)


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
    struct sect dloc, dinfo;
    struct sect *stabs = NULL;

    if ((o = obj_init(fn)) == NULL)
        error("Not an object\n");

    for (int i = 0; i < (int)obj_get_sect_num(o); i++) {
        struct sect s = obj_get_sect(o, i);
        char *sec_name = s.name;

        if (STREQ(sec_name, ".debug_loc"))
            dloc = s;
        else if (STREQ(sec_name, ".debug_info"))
            dinfo = s;
        /* if starts with .debug */
        else if (strncmp(sec_name, ".debug", sizeof(".debug")-1) == 0)
            vector_push(&stabs, s);
    }

    printf("debug sections num %ld\n", vector_nmemb(&stabs));

    for (int i = 0; i < (int)vector_nmemb(&stabs); i++)
        printf("Section `%s' of %ld bytes\n", stabs[i].name, stabs[i].size);

    printf("\n");
    printf("File size = %ld\n", o->sz);

    obj_deinit(o);
    vector_free(&stabs);
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

