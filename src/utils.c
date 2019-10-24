#include <stdlib.h>
#include <stdint.h>

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
            error("To large unsigned leb128 number\n");

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
            error("To large unsigned leb128 number\n");

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

