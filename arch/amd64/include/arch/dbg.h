#ifndef _AMD64_DBG_H_
#define _AMD64_DBG_H_

#include <stdlib.h>
#include <sys/user.h>

#define DBG_NUM_REGS (sizeof(struct user_regs_struct) / sizeof(size_t))

#define DBG_REG_PC      "rip"
#define DBG_REG_SYSCALL "orig_rax"
#define DBG_REG_R1      "rax"
#define DBG_REG_R2      "rbx"

#endif /* _AMD64_DBG_H_ */

