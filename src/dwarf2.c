#include <stdint.h>

#include "macro.h"
#include "dwarf2.h"
#include "obj.h"
#include "utils.h"
#include "vector.h"


#define DW_TAG(str_, tag_) { .str = STRINGIFY(str_), .tag = tag_ },
static struct {
    uintmax_t tag;
    char *str;
} tags[] = {
DW_TAG(array_type,             0x01)
DW_TAG(class_type,             0x02)
DW_TAG(entry_point,            0x03)
DW_TAG(enumeration_type,       0x04)
DW_TAG(formal_parameter,       0x05)
DW_TAG(imported_declaration,   0x08)
DW_TAG(label,                  0x0a)
DW_TAG(lexical_block,          0x0b)
DW_TAG(member,                 0x0d)
DW_TAG(pointer_type,           0x0f)
DW_TAG(reference_type,         0x10)
DW_TAG(compile_unit,           0x11)
DW_TAG(string_type,            0x12)
DW_TAG(structure_type,         0x13)
DW_TAG(subroutine_type,        0x15)
DW_TAG(typedef,                0x16)
DW_TAG(union_type,             0x17)
DW_TAG(unspecified_parameters, 0x18)
DW_TAG(variant,                0x19)
DW_TAG(common_block,           0x1a)
DW_TAG(common_inclusion,       0x1b)
DW_TAG(inheritance,            0x1c)
DW_TAG(inlined_subroutine,     0x1d)
DW_TAG(module,                 0x1e)
DW_TAG(ptr_to_member_type,     0x1f)
DW_TAG(set_type,               0x20)
DW_TAG(subrange_type,          0x21)
DW_TAG(with_stmt,              0x22)
DW_TAG(access_declaration,     0x23)
DW_TAG(base_type,              0x24)
DW_TAG(catch_block,            0x25)
DW_TAG(const_type,             0x26)
DW_TAG(constant,               0x27)
DW_TAG(enumerator,             0x28)
DW_TAG(file_type,              0x29)
DW_TAG(friend,                 0x2a)
DW_TAG(namelist,               0x2b)
DW_TAG(namelist_item,          0x2c)
DW_TAG(packed_type,            0x2d)
DW_TAG(subprogram,             0x2e)
DW_TAG(template_type_param,    0x2f)
DW_TAG(template_value_param,   0x30)
DW_TAG(thrown_type,            0x31)
DW_TAG(try_block,              0x32)
DW_TAG(variant_part,           0x33)
DW_TAG(variable,               0x34)
DW_TAG(volatile_type,          0x35)
DW_TAG(lo_user,                0x4080)
DW_TAG(hi_user,                0xffff)
};

const char *
dwarf2_tag_lookup(uintmax_t tag)
{
    for (unsigned i = 0; i < ARRAY_SIZE(tags); i++) {
        if (tags[i].tag == tag)
            return tags[i].str;
    }
    return NULL;
}

static struct dwarf2_abbrevtbl
dwarf2_abbrevtbl_decode(uint8_t *buf)
{
    size_t id_len  = leb_len(buf);
    size_t tag_len = leb_len(buf+id_len);

    return (struct dwarf2_abbrevtbl) {
        .id         = uleb_decode(buf),
        .tag        = uleb_decode(buf+id_len),
        .child      = buf[id_len+tag_len],
        .abbrev_len = id_len + tag_len + 1,
    };
}

vector_of(struct dwarf2_abbrevtbl)
dwarf2_abbrevtbls_decode(struct sect *dabbrev)
{
    vector_decl(struct dwarf2_abbrevtbl, ret);
    uint8_t *buf = dabbrev->buf;
    int remain   = dabbrev->size;

    while (remain > 0) {
        struct dwarf2_abbrevtbl v = dwarf2_abbrevtbl_decode(buf);

        remain -= v.abbrev_len;
        buf    += v.abbrev_len;
        vector_push(&ret, v);
    }

    return ret;
}

static struct dwarf2_cuh
dwarf2_cuh_decode(uint8_t *buf)
{
    return (struct dwarf2_cuh) {
        .cuh_len    = *(uint32_t *)(buf + 0) + 4, /* 4 is sizeof this field itself  */
        .ver        = *(uint16_t *)(buf + 4),
        .abbrev_off = *(uint32_t *)(buf + 6),
        .word_sz    = *(uint8_t  *)(buf + 10),
        .die        = buf + 4,
        .uleb       = uleb_decode(buf + DWARF2_CUH_SIZE),
    };
}

vector_of(struct dwarf2_cuh)
dwarf2_cuhs_decode(struct sect *dinfo)
{
    vector_decl(struct dwarf2_cuh, ret);
    uint8_t *buf = dinfo->buf;
    int remain   = dinfo->size;

    while (remain > 0) {
        struct dwarf2_cuh v = dwarf2_cuh_decode(buf);

        remain -= v.cuh_len;
        buf    += v.cuh_len;
        vector_push(&ret, v);
    }

    return ret;
}

