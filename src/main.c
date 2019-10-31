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

    wait(&st);

    return pid;
}

uint64_t
parse_addr(char *str)
{
    uint64_t addr = 0;
    int i;

    for (i = 2; str[i] && isxdigit(str[i]); i++) {
        addr *= 16;
        if ('0' <= str[i] && str[i] <= '9')
            addr += str[i] - '0';
        else if ('A' <= str[i] && str[i] <= 'F')
            addr += str[i] - 'A' + 10;
        else// if ('a' <= str[i] && str[i] <= 'f')
            addr += str[i] - 'a' + 10;
    }

    return addr;
}

void
debug_file(const char *fn, pid_t pid)
{
    struct obj *o;
    vector_decl(char, dir);
    (void) pid;

    if ((o = obj_init(fn)) == NULL)
        error("Not an object\n");

    vector_of(struct dwarf_cu) cus = dwarf_cus_decode(o);

    for (;;) {
        char *buf = NULL;
        size_t len = 0;

        printf(">> ");

        if (getline(&buf, &len, stdin) == -1 || STREQ(buf, "end\n")) {
            vector_free(&dir);
            free(buf);
            break;
        }

        switch (buf[0]) {
        case 'a': {
            size_t addr = parse_addr(buf + 2);
            struct line ln = dwarf_addr2line(o, cus, addr);

            printf("\t%s/%s:%d\n", ln.dir, ln.file, ln.nu);
            break;
        }
        case 'd':
            vector_free(&dir);
            for (int i = 2; buf[i] != '\n'; i++)
                vector_push(&dir, buf[i]);
            vector_push(&dir, '\0');
            break;
        case 'l': {
            int i;
            vector_decl(char, file);

            for (i = 2; buf[i] != ':'; i++)
                vector_push(&file, buf[i]);
            vector_push(&file, '\0');

            struct line ln = {
                .dir  = dir,
                .file = file,
                .nu   = atoi(buf + i + 1),
            };

            printf("\tpc = %p\n", (void *)dwarf_line2addr(o, cus, &ln));
            vector_free(&file);
            break;
        }
        default:
            printf("Error\n");
        }

        free(buf);
    }

    printf("File size = %ld\n", o->sz);
    dwarf_cus_free(cus);
    obj_deinit(o);

#if 0
    long ret;
    int st;
    struct user_regs_struct regs;

    for (;;) {
        ret = ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
        if (ret)
            error("PTRACE_SYSCALL error");

        ret = waitpid(pid, &st, 0);
        if (ret < 0)
            error("waitpid error");

        ret = ptrace(PTRACE_GETREGS, pid, NULL, &regs);
        printf("pc = %llx rax = %llx %llx\n", regs.rip, regs.orig_rax, regs.rbx);

        if (WIFEXITED(st)) {
            printf("child exited\n");
            break;
        }
        if (WIFSTOPPED(st) && (WSTOPSIG(st) == (SIGTRAP | 0x80))) {
            insyscall = !insyscall;

            printf("syscall %s ", insyscall ? "entering" : "exiting\n");
            fflush(stdout);
            ret = ptrace(PTRACE_GETREGS, pid, NULL, &regs);
            if (ret)
                printf("can't get regs\n");
            if (!insyscall) {
//                print_ret_status(&regs);
            } else {
                printf("pc = %llx rax = %llx %llx", regs.rip, regs.orig_rax, regs.rbx);
            }
            printf("\n");
            fflush(stdout);
        }
    }

    ptrace(PTRACE_DETACH, pid, NULL, NULL);
#endif
}

int
main(int argc, const char *argv[])
{
    pid_t pid;

    if (argc < 2) {
        usage();
        exit(1);
    }

    argv++;
    pid = start_debugee(argv);
    debug_file(argv[0], pid);

    return 0;
}

