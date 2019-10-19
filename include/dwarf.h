#ifndef _DWARF_H_
#define _DWARF_H_

#include <stdint.h>
#include <stdbool.h>

#include "obj.h"
#include "vector.h"


enum dwarf_class {
    dwarf_class_ref   = 1 << 0,
    dwarf_class_block = 1 << 1,
    dwarf_class_const = 1 << 2,
    dwarf_class_str   = 1 << 3,
    dwarf_class_addr  = 1 << 4,
    dwarf_class_flag  = 1 << 5,
};

struct dwarf_obj {
    enum dwarf_class class;
    union {
        uintmax_t ref;
        struct {
            uint32_t len;
            uint8_t *ptr;
        } block;
        uintmax_t const_;
        char *str;
        uint64_t addr;
        bool flag;
    } un;
};

struct dwarf_attr {
    uintmax_t name;
    uintmax_t form;
    struct dwarf_obj val;
};

struct dwarf_die {
    uintmax_t tag;
    vector_of(struct dwarf_attr) attrs;
};

struct dwarf_cu {
    uint64_t cu_len;
    uint32_t dies_len;
    uint16_t ver;
    uint64_t abbrev_off;
    uint8_t word_sz;
    bool is_64;

    vector_of(struct dwarf_die) dies;
};

struct dwarf_abbrev {
    size_t id;
    uintmax_t tag;
    vector_of(struct dwarf_abbrev) children;
    vector_of(struct dwarf_attr) attrs;
};

struct dwarf_prol_file {
    char *fn;
    uintmax_t dir_idx;
    uintmax_t last_mod_time;
    uintmax_t flen;
};

struct dwarf_prol {
    uint64_t unit_len;
    uint16_t ver;
    uint64_t header_len;
    uint8_t  inst_len;
    uint8_t  def_is_stmt;
    int8_t   line_base;
    uint8_t  line_range;
    uint8_t  op_base;
    vector_of(uint8_t) std_op_lens;
    vector_of(char *)  inc_dirs;
    vector_of(struct dwarf_prol_file) fnames;

    bool is_64;
};

struct dwarf_machine {
    uint64_t addr;
    unsigned file;
    unsigned line;
};

struct line {
    vector_of(char) fn;
    int nu;
};

extern int word_size;


struct line dwarf_addr2line(struct obj *o, size_t addr);
size_t dwarf_line2addr(struct obj *o, struct line *ln);

struct dwarf_cu dwarf_cu_decode(uint8_t *buf, struct obj *o);
struct dwarf_abbrev dwarf_abbrevtbl_decode(uint8_t *buf, size_t *len);

vector_of(struct dwarf_cu) dwarf_cus_decode(struct obj *o);

const char *dwarf_tag_lookup(uintmax_t tag);
const char *dwarf_attrib_lookup(uintmax_t nm);
const char *dwarf_form_lookup(uintmax_t nm);

const char *dwarf_describe_attrib(uint8_t *die, struct dwarf_attr attr, uint8_t *dstr, size_t *len);

#endif /* _DWARF_H_ */

