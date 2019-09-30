#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

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

static struct dwarf_abbrev *
abbrev_lookup(struct dwarf_abbrev *atbl, uintmax_t id)
{
    if (atbl->id == id)
        return atbl;

    for (unsigned i = 0; i < vector_nmemb(&atbl->children); i++) {
        struct dwarf_abbrev *ret = abbrev_lookup(atbl->children + i, id);
        if (ret)
            return ret;
    }

    return NULL;
}

void
load_debug_info(const char *fn)
{
    struct obj *o;
    struct sect dinfo, dabbrev, dstr;

    if ((o = obj_init(fn)) == NULL)
        error("Not an object\n");

    dinfo   = obj_get_sect_by_name(o, ".debug_info");
    dabbrev = obj_get_sect_by_name(o, ".debug_abbrev");
    dstr    = obj_get_sect_by_name(o, ".debug_str");

    if (dinfo.name == NULL)
        error("No `.debug_info' section\n");
    if (dabbrev.name == NULL)
        error("No `.debug_abbrev' section\n");
    if (dstr.name == NULL)
        error("No `.debug_str' section\n");

    printf("dinfo_len   = 0x%lx\n", dinfo.size);
    printf("dabbrev_len = 0x%lx\n", dabbrev.size);
    printf("dstr_len    = 0x%lx\n", dstr.size);
    printf("\n");

    vector_of(struct dwarf_cu) cus = dwarf_cus_decode(&dinfo);

    if (cus[0].ver > 3)
        error("Not a dwarf format. Instead dwarf%d\n", cus[0].ver);
    word_size = cus[0].word_sz;

    for (unsigned i = 0; i < vector_nmemb(&cus); i++) {
        size_t len;
        struct dwarf_abbrev atbl = dwarf_abbrevtbl_decode(dabbrev.buf + cus[i].abbrev_off, &len);

        printf("Compilation unit [%u]\n", i);
        printf("cu_len     = 0x%lx\n",  cus[i].cu_len);
        printf("abbrev_off = 0x%lx\n",  cus[i].abbrev_off);
        printf("\n");

        uint8_t *die = cus[i].dies;
        size_t die_len = cus[i].dies_len;

        while (die_len > 0) {
            struct dwarf_abbrev *abbrev =
                abbrev_lookup(&atbl, uleb_decode(die));

            die_len -= leb_len(die);
            die += leb_len(die);

            if (!abbrev) {
                printf("    Abbrev 0\n");
                continue;
            }

            printf("   %ld      DW_TAG_%s    [%s children]\n",
                   abbrev->id, dwarf_tag_lookup(abbrev->tag),
                   abbrev->children ? "has" : "no");

            vector_foreach(a, &abbrev->attrs) {
                size_t len;

                printf("    DW_AT_%-8s\tDW_FORM_%s\t%s\n",
                       dwarf_attrib_lookup(a.name),
                       dwarf_form_lookup(a.form),
                       dwarf_describe_attrib(die, a, dstr.buf, &len));
                die_len -= len;
                die     += len;
            }
        }
    }

    printf("File size = %ld\n", o->sz);
    obj_deinit(o);
    vector_free(&cus);
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

