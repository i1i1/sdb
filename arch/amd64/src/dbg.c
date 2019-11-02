#include <sys/user.h>

#include "dbg.h"
#include "arch/dbg.h"


#define DBG_NUM_REGS (sizeof(struct user_regs_struct) / sizeof(size_t))


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

