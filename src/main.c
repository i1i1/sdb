#include <assert.h>
#include <ctype.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dbg.h"
#include "dwarf.h"
#include "macro.h"
#include "obj.h"
#include "utils.h"
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

#define DBG_PRINT_REGS()                                            \
    do {                                                            \
        size_t pc      = dbg_getreg_by_name(pid, DBG_REG_PC);       \
        size_t ir      = dbg_getw(pid, pc);                         \
        size_t syscall = dbg_getreg_by_name(pid, DBG_REG_SYSCALL);  \
        size_t r2      = dbg_getreg_by_name(pid, DBG_REG_R2);       \
                                                                    \
        printf("pc: %lx [pc]: %016lx rax: %016lx rbx: %016lx\n",    \
               pc, ir, syscall, r2);                                \
        fflush(stdout);                                             \
    } while (0)

    int st;
    int insyscall = 0;

    printf("start at %p\n", (void *)obj_get_start(o));

    dbg_continue(pid, &st);
    DBG_PRINT_REGS();

    if (WIFSTOPPED(st)) {
        insyscall = !insyscall;
        printf("syscall %s\n", insyscall ? "entering" : "exiting");
    }

//    while (!WIFEXITED(st)) {
//        DBG_PRINT_REGS();
//        dbg_singlestep(pid, &st);
//    }

    printf("child exited\n");
    obj_deinit(o);
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
    pid = dbg_openfile(argv);
    debug_file(argv[0], pid);

    return 0;
}

