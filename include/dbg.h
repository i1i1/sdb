#ifndef _DBG_H_
#define _DBG_H_

#include <stdbool.h>
#include <unistd.h>

#include <asm/unistd.h>

#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/ptrace.h>

#include "arch/dbg.h"
#include "vector.h"


struct dbg_reg {
    char  *name;
    size_t val; /* let's debug only our own architecture */
};

struct dbg_breakpoint {
    int id;
    size_t addr;
    size_t orig_data;
    bool is_enabled;
};

enum DBG_STATES {
    DBG_STATE_NONE,
    DBG_STATE_BREAK,

    DBG_STATE_EXIT,
    DBG_STATE_STOP,
    DBG_STATE_TERM,
};

struct dbg_process_state {
    enum DBG_STATES type;
    union {
        int sig;
        int code;
    } un;
};

struct dbg_process {
    pid_t pid;
    vector_of(struct dbg_breakpoint) bps;
    struct dbg_process_state st;
};

extern struct dbg_reg regs_def[DBG_NUM_REGS];


struct dbg_process dbg_openfile(const char **argv);
void dbg_deinit(struct dbg_process *dp);

void dbg_detach(struct dbg_process *dp);

long dbg_getw(struct dbg_process *dp, size_t addr);
void dbg_setw(struct dbg_process *dp, size_t addr, size_t val);

void dbg_continue(struct dbg_process *dp);
void dbg_singlestep(struct dbg_process *dp);

size_t dbg_getreg_by_name(struct dbg_process *dp, char *reg);
size_t dbg_get_pc(struct dbg_process *dp);
void dbg_setreg_by_name(struct dbg_process *dp, char *reg, size_t val);

int dbg_add_breakpoint(struct dbg_process *dp, size_t addr);
void dbg_remove_breakpoint(struct dbg_process *dp, int id);


#endif /* _DBG_H_ */

