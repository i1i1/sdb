#include <stdbool.h>
#include <unistd.h>

#include <asm/unistd.h>

#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/ptrace.h>

#include "dbg.h"
#include "macro.h"
#include "utils.h"

#define DBG_NUM_REGS (sizeof(struct user_regs_struct) / sizeof(size_t))


struct dbg_reg {
    char  *name;
    size_t val; /* let's debug only our own architecture */
};


/*
 * Assuming that we have x86_64.
 */
struct dbg_reg regs_def[DBG_NUM_REGS] = {
    { "r15", 0 },
    { "r14", 0 },
    { "r13", 0 },
    { "r12", 0 },
    { "rbp", 0 },
    { "rbx", 0 },
    { "r11", 0 },
    { "r10", 0 },
    { "r9", 0 },
    { "r8", 0 },
    { "rax", 0 },
    { "rcx", 0 },
    { "rdx", 0 },
    { "rsi", 0 },
    { "rdi", 0 },
    { "orig_rax", 0 },
    { "rip", 0 },
    { "cs", 0 },
    { "eflags", 0 },
    { "rsp", 0 },
    { "ss", 0 },
    { "fs_base", 0 },
    { "gs_base", 0 },
    { "ds", 0 },
    { "es", 0 },
    { "fs", 0 },
    { "gs", 0 },
};


static void
xptrace(int request, pid_t pid, void *addr, void *data)
{
    int ret = ptrace(request, pid, addr, data);
    if (ret)
        error("PTRACE error %d", request);
}

static pid_t
xwaitpid(pid_t pid, int *wstatus, int options)
{
    pid_t ret = waitpid(pid, wstatus, options);
    if (ret < 0)
        error("waitpid error");
    return ret;
}

static void
ptrace_traceme() {
    int ret;

    ret = ptrace(PTRACE_TRACEME, 0, NULL, NULL);
    if (ret != 0)
        error("TRACEME error");
}

pid_t
dbg_openfile(const char **argv)
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

    xwaitpid(pid, &st, 0);

    return pid;
}

void
dbg_singlestep(pid_t pid, int *st)
{
    xptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
    xwaitpid(pid, st, 0);
}

size_t
dbg_getreg_by_name(pid_t pid, char *reg)
{
    struct user_regs_struct r;
    size_t *arr = (void *)&r;

    xptrace(PTRACE_GETREGS, pid, NULL, &r);

    for (unsigned i = 0; i < DBG_NUM_REGS; i++) {
        if (STREQ(regs_def[i].name, reg))
            return arr[i];
    }

    return 0;
}

void
dbg_detach(pid_t pid)
{
    xptrace(PTRACE_DETACH, pid, NULL, NULL);
}

long
dbg_getw(pid_t pid, size_t addr)
{
    /*
     * No xptrace here!
     */
    return ptrace(PTRACE_PEEKTEXT, pid, (void *)addr, NULL);
}

void
dbg_setw(pid_t pid, size_t addr, size_t val)
{
    ptrace(PTRACE_POKETEXT, pid, (void *)addr, val);
}

void
dbg_continue(pid_t pid, int *st)
{
    xptrace(PTRACE_CONT, pid, NULL, NULL);
    xwaitpid(pid, st, 0);
}

void
dbg_enable_breakpoint(pid_t pid, struct dbg_breakpoint *bp)
{
    if (!bp->is_enabled) {
        int int3_x86 = 0xCC;

        bp->is_enabled = true;
        bp->orig_data = dbg_getw(pid, bp->addr);

        size_t changed_data = (bp->orig_data & 0xFFFFFFFFFFFFFF00) | int3_x86;
        dbg_setw(pid, bp->addr, changed_data);
    }
}

struct dbg_breakpoint
dbg_add_breakpoint(pid_t pid, size_t addr)
{
    struct dbg_breakpoint bp = {
        .addr       = addr,
        .is_enabled = false,
    };
    dbg_enable_breakpoint(pid, &bp);
    return bp;
}

