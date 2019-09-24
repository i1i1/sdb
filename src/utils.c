#include <stdint.h>

#include "utils.h"
#include "macro.h"


uintmax_t
uleb_extract(uint8_t *buf)
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
sleb_extract(uint8_t *buf)
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

    return res;
}

