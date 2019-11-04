#include <stdbool.h>
#include <unistd.h>

#include <asm/unistd.h>

#include <sys/personality.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>

#include "dbg.h"
#include "macro.h"
#include "utils.h"

#include "arch/dbg.h"

int bp_id = 0;


static void
disable_randomization(void)
{
    int old = personality(0xffffffff);
    if (personality(old | ADDR_NO_RANDOMIZE) == -1)
        error("Personality isn't working");
}

static struct dbg_process_state
get_state(int st)
{
    if (WIFEXITED(st)) {
        return (struct dbg_process_state) {
            .type   = DBG_STATE_EXIT,
            .un.code = WEXITSTATUS(st),
        };
    }
    if (WIFSIGNALED(st)) {
        return (struct dbg_process_state) {
            .type  = DBG_STATE_TERM,
            .un.sig = WTERMSIG(st),
        };
    }
    if (WSTOPSIG(st)) {
        return (struct dbg_process_state) {
            .type  = (WSTOPSIG(st) == SIGTRAP ? DBG_STATE_BREAK : DBG_STATE_STOP),
            .un.sig = WSTOPSIG(st),
        };
    }
    return (struct dbg_process_state) {
        .type = DBG_STATE_NONE,
    };
}

static bool
dbg_is_at_breakpoint(struct dbg_process *dp, const struct dbg_breakpoint *bp)
{
    return (dbg_getreg_by_name(dp, DBG_REG_PC) == bp->addr + 1);
}


struct dbg_process
dbg_openfile(const char **argv)
{
    struct dbg_process ret;
    int st;

    disable_randomization();

    ret.pid = fork();
    switch (ret.pid) {
    case 0:
        printf("executing %s\n", argv[0]);
        xptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execvp(argv[0], (char * const *)argv);
        exit(0);
    case -1:
        error("fork error");
    default:
        break;
    }

    xwaitpid(ret.pid, &st, 0);
    ret.st = get_state(st);
    ret.bps = NULL;

    return ret;
}

size_t
dbg_get_pc(struct dbg_process *dp)
{
    return dbg_getreg_by_name(dp, DBG_REG_PC) - 0x555555554000;
}

void
dbg_singlestep(struct dbg_process *dp)
{
    int st;

    ptrace(PTRACE_SINGLESTEP, dp->pid, NULL, NULL);
    xwaitpid(dp->pid, &st, 0);
    dp->st = get_state(st);
}

void
dbg_setreg_by_name(struct dbg_process *dp, char *reg, size_t val)
{
    for (unsigned i = 0; i < DBG_NUM_REGS; i++) {
        if (STREQ(regs_def[i].name, reg)) {
            ptrace(PTRACE_POKEUSER, dp->pid, i * sizeof(size_t), val);
            return;
        }
    }
}

size_t
dbg_getreg_by_name(struct dbg_process *dp, char *reg)
{
    for (unsigned i = 0; i < DBG_NUM_REGS; i++) {
        if (STREQ(regs_def[i].name, reg))
            return ptrace(PTRACE_PEEKUSER, dp->pid, i * sizeof(size_t), NULL);
    }

    return 0;
}

void
dbg_detach(struct dbg_process *dp)
{
    xptrace(PTRACE_DETACH, dp->pid, NULL, NULL);
}

long
dbg_getw(struct dbg_process *dp, size_t addr)
{
    /*
     * No xptrace here!
     */
    return ptrace(PTRACE_PEEKTEXT, dp->pid, (void *)addr, NULL);
}

void
dbg_setw(struct dbg_process *dp, size_t addr, size_t val)
{
    /*
     * No xptrace here!
     */
    ptrace(PTRACE_POKETEXT, dp->pid, (void *)addr, val);
}

static void
dbg_enable_breakpoint(struct dbg_process *dp, struct dbg_breakpoint *bp)
{
    if (!bp->is_enabled) {
        int int3_x86 = 0xCC;

        bp->is_enabled = true;
        bp->orig_data = dbg_getw(dp, bp->addr);

        size_t changed_data = (bp->orig_data & 0xFFFFFFFFFFFFFF00) | int3_x86;
        dbg_setw(dp, bp->addr, changed_data);
    }
}

static void
dbg_disable_breakpoint(struct dbg_process *dp, struct dbg_breakpoint *bp)
{
    if (bp->is_enabled) {
        bp->is_enabled = false;
        dbg_setw(dp, bp->addr, bp->orig_data);
    }
}

static void
dbg_continue_breakpoint(struct dbg_process *dp, struct dbg_breakpoint *bp)
{
    if (dbg_is_at_breakpoint(dp, bp)) {
        dbg_disable_breakpoint(dp, bp);
        dbg_setreg_by_name(dp, DBG_REG_PC,
                           dbg_getreg_by_name(dp, DBG_REG_PC) - 1);
        dbg_singlestep(dp);
        dbg_enable_breakpoint(dp, bp);
    }
}

void
dbg_continue(struct dbg_process *dp)
{
    int st;

    xptrace(PTRACE_CONT, dp->pid, NULL, NULL);
    xwaitpid(dp->pid, &st, 0);
    dp->st = get_state(st);

    if (dp->st.type == DBG_STATE_BREAK) {
        vector_foreach(bp, &dp->bps) {
            if (dbg_is_at_breakpoint(dp, &bp)) {
                dbg_continue_breakpoint(dp, &bp);
                return;
            }
        }
    }
}

int
dbg_add_breakpoint(struct dbg_process *dp, size_t addr)
{
    struct dbg_breakpoint bp = {
        .id         = bp_id++,
        .addr       = addr + 0x555555554000, // Hard coded offset
        .is_enabled = false,
    };
    dbg_enable_breakpoint(dp, &bp);
    vector_push(&dp->bps, bp);
    return bp.id;
}

void
dbg_remove_breakpoint(struct dbg_process *dp, int id)
{
    for (unsigned i = 0; i < vector_nmemb(&dp->bps); i++) {
        if (dp->bps[i].id == id) {
            if (dp->bps[i].is_enabled)
                dbg_disable_breakpoint(dp, &dp->bps[i]);
            dp->bps[i] = vector_pop(&dp->bps);
            return;
        }
    }
}

void
dbg_deinit(struct dbg_process *dp)
{
    vector_free(&dp->bps);
}

