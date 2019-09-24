#ifndef _DWARF2_H_
#define _DWARF2_H_

#include <stdint.h>

#include "obj.h"


struct dwarf2_cuh {
    uint32_t contrib_len;
    uint16_t ver;
    uint32_t abbrev_off;
    uint8_t word_sz;
    uint8_t *die;
    uintmax_t uleb;
};


struct dwarf2_cuh dwarf2_cuh_decode(struct sect *dinfo);


#endif /* _DWARF2_H_ */

