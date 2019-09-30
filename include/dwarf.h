#ifndef _DWARF_H_
#define _DWARF_H_

#include <stdint.h>
#include <stdbool.h>

#include "obj.h"
#include "vector.h"


struct dwarf_attr {
    uintmax_t name;
    uintmax_t form;
    uint8_t  *addr;
};

struct dwarf_die {
    uintmax_t abbrev_idx;
    vector_of(struct dwarf_attr) attrs;
};

struct dwarf_cu {
    uint64_t cu_len;
    uint32_t dies_len;
    uint16_t ver;
    uint64_t abbrev_off;
    uint8_t word_sz;
    uint8_t *dies;
    bool is_64;
};

struct dwarf_abbrev {
    size_t id;
    uintmax_t tag;
    vector_of(struct dwarf_abbrev) children;
    vector_of(struct dwarf_attr) attrs;
};

enum dwarf_class {
    dwarf_class_ref   = 1 << 0,
    dwarf_class_block = 1 << 1,
    dwarf_class_const = 1 << 2,
    dwarf_class_str   = 1 << 3,
    dwarf_class_addr  = 1 << 4,
    dwarf_class_flag  = 1 << 5,
};

extern int word_size;


struct dwarf_cu dwarf_cu_decode(uint8_t *buf);
struct dwarf_abbrev dwarf_abbrevtbl_decode(uint8_t *buf, size_t *len);

vector_of(struct dwarf_cu) dwarf_cus_decode(struct sect *dinfo);

const char *dwarf_tag_lookup(uintmax_t tag);
const char *dwarf_attrib_lookup(uintmax_t nm);
const char *dwarf_form_lookup(uintmax_t nm);

const char *dwarf_describe_attrib(uint8_t *die, struct dwarf_attr attr, uint8_t *dstr, size_t *len);

#endif /* _DWARF_H_ */

