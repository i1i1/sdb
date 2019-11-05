#include <stdlib.h>
#include <stdint.h>

#include <sys/ptrace.h>
#include <sys/wait.h>

#include "utils.h"
#include "macro.h"

#define VECTOR_IMPLEMENTATION
#include "vector.h"


size_t
leb_len(uint8_t *buf)
{
    size_t ret = 1;
    while ((*buf++) & 0x80)
        ret++;
    return ret;
}

uintmax_t
uleb_decode(uint8_t *buf)
{
    uintmax_t res = 0;
    int shift = 0;
    int maxshift = sizeof(res) * 8 - 7;

    do {
        uint8_t b = (*buf) & 0x7F;

        res |= (b << shift);
        shift += 7;

        if (shift > maxshift)
            error("Too large unsigned leb128 number\n");

    } while ((*buf++) & 0x80);

    return res;
}

intmax_t
sleb_decode(uint8_t *buf)
{
    intmax_t res = 0;
    int shift = 0;
    int maxshift = sizeof(res) * 8 - 7;

    do {
        uint8_t b = (*buf) & 0x7F;

        res |= (b << shift);
        shift += 7;

        if (shift > maxshift)
            error("Too large unsigned leb128 number\n");

    } while ((*buf++) & 0x80);

    buf--;

    /* sign bit of byte is second high order bit (0x40) */
    if (*buf & 0x40)
        /* sign extend */
        res |= (~0 << shift);

    return res;
}

void *
xmalloc(size_t sz)
{
    void *ret = malloc(sz);
    if (!ret)
        error("malloc error\n");
    return ret;
}

void *
xrealloc(void *a, size_t sz)
{
    void *ret = realloc(a, sz);
    if (!ret)
        error("realloc error\n");
    return ret;
}

void
xptrace(int request, pid_t pid, void *addr, void *data)
{
    char *errors[] = {
        [ 0] = "PTRACE_TRACEME",
        [ 1] = "PTRACE_PEEKTEXT",
        [ 2] = "PTRACE_PEEKDATA",
        [ 3] = "PTRACE_PEEKUSR",
        [ 4] = "PTRACE_POKETEXT",
        [ 5] = "PTRACE_POKEDATA",
        [ 6] = "PTRACE_POKEUSR",
        [ 7] = "PTRACE_CONT",
        [ 8] = "PTRACE_KILL",
        [ 9] = "PTRACE_SINGLESTEP",
        [12] = "PTRACE_GETREGS",
        [16] = "PTRACE_ATTACH",
        [17] = "PTRACE_DETACH",
        [24] = "PTRACE_SYSCALL",
    };

    int ret = ptrace(request, pid, addr, data);
    if (ret)
        error("error in %s %d", errors[request], request);
}

pid_t
xwaitpid(pid_t pid, int *wstatus, int options)
{
    pid_t ret = waitpid(pid, wstatus, options);
    if (ret < 0)
        error("waitpid error");
    return ret;
}

