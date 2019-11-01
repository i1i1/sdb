#ifndef _DBG_H_
#define _DBG_H_

#include <unistd.h>

#include <asm/unistd.h>

#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/ptrace.h>

/*
 * Assuming that we have x86_64.
 */
#define DBG_REG_PC      "rip"
#define DBG_REG_SYSCALL "orig_rax"
#define DBG_REG_R1      "rax"
#define DBG_REG_R2      "rbx"

struct dbg_breakpoint {
    size_t addr;
    size_t orig_data;
    bool is_enabled;
};


pid_t dbg_openfile(const char **argv);

void dbg_singlestep(pid_t pid, int *st);

long dbg_getw(pid_t pid, size_t addr);

void dbg_setw(pid_t pid, size_t addr, size_t val);

void dbg_continue(pid_t pid, int *st);

size_t dbg_getreg_by_name(pid_t pid, char *reg);

struct dbg_breakpoint dbg_add_breakpoint(pid_t pid, size_t addr);

void dbg_detach(pid_t pid);


#endif /* _DBG_H_ */

