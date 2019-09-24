#include <stdint.h>

#include "macro.h"
#include "dwarf2.h"
#include "obj.h"
#include "utils.h"


struct dwarf2_cuh
dwarf2_cuh_decode(struct sect *dinfo)
{
    return (struct dwarf2_cuh) {
        .contrib_len = *(uint32_t *)(dinfo->buf + 0),
        .ver         = *(uint16_t *)(dinfo->buf + 4),
        .abbrev_off  = *(uint32_t *)(dinfo->buf + 6),
        .word_sz     = *(uint8_t  *)(dinfo->buf + 10),
        .die         = dinfo->buf + 11,
        .uleb        = uleb_extract(dinfo->buf + 11),
    };
}

