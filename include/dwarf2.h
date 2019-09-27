#ifndef _DWARF2_H_
#define _DWARF2_H_

#include <stdint.h>

#include "obj.h"
#include "vector.h"

#define DWARF2_CUH_SIZE 11


struct dwarf2_attr {
    uintmax_t name;
    uintmax_t form;
};

struct dwarf2_die {
    uintmax_t abbrev_idx;
    vector_of(struct dwarf2_attr) attrs;
};

struct dwarf2_cu {
    uint32_t cu_len;
    uint32_t dies_len;
    uint16_t ver;
    uint32_t abbrev_off;
    uint8_t word_sz;
    uint8_t *dies;
};

struct dwarf2_abbrev {
    size_t id;
    uintmax_t tag;
    uint8_t child;
    vector_of(struct dwarf2_attr) attrs;
};

enum dwarf2_class {
    dwarf2_class_ref   = 1 << 0,
    dwarf2_class_block = 1 << 1,
    dwarf2_class_const = 1 << 2,
    dwarf2_class_str   = 1 << 3,
    dwarf2_class_addr  = 1 << 4,
    dwarf2_class_flag  = 1 << 5,
};

extern int word_size;


struct dwarf2_cu dwarf2_cu_decode(uint8_t *buf);
vector_of(struct dwarf2_abbrev) dwarf2_abbrevtbl_decode(uint8_t *buf, size_t *len);

vector_of(struct dwarf2_cu) dwarf2_cus_decode(struct sect *dinfo);

const char *dwarf2_tag_lookup(uintmax_t tag);
const char *dwarf2_attrib_lookup(uintmax_t nm);
const char *dwarf2_form_lookup(uintmax_t nm);

const char *dwarf2_describe_attrib(uint8_t *die, struct dwarf2_attr attr, uint8_t *dstr, size_t *len);

#endif /* _DWARF2_H_ */

