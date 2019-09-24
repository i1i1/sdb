#ifndef _DWARF2_H_
#define _DWARF2_H_

#include <stdint.h>

#include "obj.h"
#include "vector.h"

#define DWARF2_CUH_SIZE 11


struct dwarf2_cuh {
    uint32_t cuh_len;
    uint16_t ver;
    uint32_t abbrev_off;
    uint8_t word_sz;
    uint8_t *die;
    uintmax_t uleb;
};

struct dwarf2_attr {
    uintmax_t name;
    uintmax_t form;
};

struct dwarf2_abbrevtbl {
    size_t id;
    uintmax_t tag;
    uint8_t child;
    uint32_t abbrev_len;
    vector_of(struct dwarf2_attr) attrs;
};


vector_of(struct dwarf2_cuh) dwarf2_cuhs_decode(struct sect *dinfo);
vector_of(struct dwarf2_abbrevtbl) dwarf2_abbrevtbls_decode(struct sect *dabbrev);

const char *dwarf2_tag_lookup(uintmax_t tag);
const char *dwarf2_attrib_lookup(uintmax_t nm);
const char *dwarf2_attrib_lookup_class(uintmax_t nm);
const char *dwarf2_form_lookup(uintmax_t nm);
const char *dwarf2_form_lookup_class(uintmax_t nm);

#endif /* _DWARF2_H_ */

