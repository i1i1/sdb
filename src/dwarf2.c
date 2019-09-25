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
#undef DW_TAG

#define DW_AT(str_, attr_, class_) \
    {                              \
        .attr = attr_,             \
        .str = STRINGIFY(str_),    \
        .class = class_            \
    },
static struct {
    uintmax_t attr;
    char *str;
    char *class;
} attribs[] = {
    DW_AT(sibling,                0x01, "reference")
    DW_AT(location,               0x02, "block, constant")
    DW_AT(name,                   0x03, "string")
    DW_AT(ordering,               0x09, "constant")
    DW_AT(byte_size,              0x0b, "constant")
    DW_AT(bit_offset,             0x0c, "constant")
    DW_AT(bit_size,               0x0d, "constant")
    DW_AT(stmt_list,              0x10, "constant")
    DW_AT(low_pc,                 0x11, "address")
    DW_AT(high_pc,                0x12, "address")
    DW_AT(language,               0x13, "constant")
    DW_AT(discr,                  0x15, "reference")
    DW_AT(discr_value,            0x16, "constant")
    DW_AT(visibility,             0x17, "constant")
    DW_AT(import,                 0x18, "reference")
    DW_AT(string_length,          0x19, "block, constant")
    DW_AT(common_reference,       0x1a, "reference")
    DW_AT(comp_dir,               0x1b, "string")
    DW_AT(const_value,            0x1c, "string, constant, block")
    DW_AT(containing_type,        0x1d, "reference")
    DW_AT(default_value,          0x1e, "reference")
    DW_AT(inline,                 0x20, "constant")
    DW_AT(is_optional,            0x21, "flag")
    DW_AT(lower_bound,            0x22, "constant, reference")
    DW_AT(producer,               0x25, "string")
    DW_AT(prototyped,             0x27, "flag")
    DW_AT(return_addr,            0x2a, "block, constant")
    DW_AT(start_scope,            0x2c, "constant")
    DW_AT(stride_size,            0x2e, "constant")
    DW_AT(upper_bound,            0x2f, "constant, reference")
    DW_AT(abstract_origin,        0x31, "reference")
    DW_AT(accessibility,          0x32, "constant")
    DW_AT(address_class,          0x33, "constant")
    DW_AT(artificial,             0x34, "flag")
    DW_AT(base_types,             0x35, "reference")
    DW_AT(calling_convention,     0x36, "constant")
    DW_AT(count,                  0x37, "constant, reference")
    DW_AT(data_member_location,   0x38, "block, reference")
    DW_AT(decl_column,            0x39, "constant")
    DW_AT(decl_file,              0x3a, "constant")
    DW_AT(decl_line,              0x3b, "constant")
    DW_AT(declaration,            0x3c, "flag")
    DW_AT(discr_list,             0x3d, "block")
    DW_AT(encoding,               0x3e, "constant")
    DW_AT(external,               0x3f, "flag")
    DW_AT(frame_base,             0x40, "block, constant")
    DW_AT(friend,                 0x41, "reference")
    DW_AT(identifier_case,        0x42, "constant")
    DW_AT(macro_info,             0x43, "constant")
    DW_AT(namelist_item,          0x44, "block")
    DW_AT(priority,               0x45, "reference")
    DW_AT(segment,                0x46, "block, constant")
    DW_AT(specification,          0x47, "reference")
    DW_AT(static_link,            0x48, "block, constant")
    DW_AT(type,                   0x49, "reference")
    DW_AT(use_location,           0x4a, "block, constant")
    DW_AT(variable_parameter,     0x4b, "flag")
    DW_AT(virtuality,             0x4c, "constant")
    DW_AT(vtable_elem_location,   0x4d, "block, reference")
    DW_AT(lo_user,                0x2000, "—")
    DW_AT(hi_user,                0x3fff, "_" )
};
#undef DW_AT

#define DW_FORM(str_, form_, class_) \
    {                                \
        .form = form_,               \
        .str = STRINGIFY(str_),      \
        .class = class_              \
    },
struct {
    char *str;
    uintmax_t form;
    char *class;
} forms[] = {
    DW_FORM(addr,        0x01, "address")
    DW_FORM(block2,      0x03, "block")
    DW_FORM(block4,      0x04, "block")
    DW_FORM(data2,       0x05, "constant")
    DW_FORM(data4,       0x06, "constant")
    DW_FORM(data8,       0x07, "constant")
    DW_FORM(string,      0x08, "string")
    DW_FORM(block,       0x09, "block")
    DW_FORM(block1,      0x0a, "block")
    DW_FORM(data1,       0x0b, "constant")
    DW_FORM(flag,        0x0c, "flag")
    DW_FORM(sdata,       0x0d, "constant")
    DW_FORM(strp,        0x0e, "string")
    DW_FORM(udata,       0x0f, "constant")
    DW_FORM(ref_addr,    0x10, "reference")
    DW_FORM(ref1,        0x11, "reference")
    DW_FORM(ref2,        0x12, "reference")
    DW_FORM(ref4,        0x13, "reference")
    DW_FORM(ref8,        0x14, "reference")
    DW_FORM(ref_udata,   0x15, "reference")
    DW_FORM(indirect,    0x16, "(see section 7.5.3)")
};
#undef DW_FORM


const char *
dwarf2_tag_lookup(uintmax_t tag)
{
    for (unsigned i = 0; i < ARRAY_SIZE(tags); i++) {
        if (tags[i].tag == tag)
            return tags[i].str;
    }
    return NULL;
}

const char *
dwarf2_attrib_lookup(uintmax_t nm)
{
    for (unsigned i = 0; i < ARRAY_SIZE(attribs); i++) {
        if (attribs[i].attr == nm)
            return attribs[i].str;
    }
    return NULL;
}

const char *
dwarf2_attrib_lookup_class(uintmax_t nm)
{
    for (unsigned i = 0; i < ARRAY_SIZE(attribs); i++) {
        if (attribs[i].attr == nm)
            return attribs[i].class;
    }
    return NULL;
}

const char *
dwarf2_form_lookup(uintmax_t nm)
{
    for (unsigned i = 0; i < ARRAY_SIZE(forms); i++) {
        if (forms[i].form == nm)
            return forms[i].str;
    }
    return NULL;
}

const char *
dwarf2_form_lookup_class(uintmax_t nm)
{
    for (unsigned i = 0; i < ARRAY_SIZE(forms); i++) {
        if (forms[i].form == nm)
            return forms[i].class;
    }
    return NULL;
}

static vector_of(struct dwarf2_attr)
    dwarf2_attrs_decode(uint8_t *buf, size_t *attrs_len)
{
    vector_decl(struct dwarf2_attr, attrs);
    struct dwarf2_attr v;
    size_t len = 0;

    do {
        v.name = uleb_decode(buf);
        len += leb_len(buf);
        buf += leb_len(buf);
        v.form = uleb_decode(buf);
        len += leb_len(buf);
        buf += leb_len(buf);

        vector_push(&attrs, v);
    } while (v.name != 0 && v.form != 0);

    vector_pop(&attrs);

    *attrs_len = len;
    return attrs;
}

static struct dwarf2_abbrevtbl
dwarf2_abbrevtbl_decode(uint8_t *buf)
{
    size_t attrs_len;
    size_t id_len  = leb_len(buf);
    size_t tag_len = leb_len(buf+id_len);
    vector_of(struct dwarf2_attr) attrs =
        dwarf2_attrs_decode(buf + id_len + tag_len + 1, &attrs_len);

    return (struct dwarf2_abbrevtbl) {
        .id         = uleb_decode(buf),
        .tag        = uleb_decode(buf+id_len),
        .child      = buf[id_len+tag_len],
        /* 1 is length of field child */
        .abbrev_len = id_len + tag_len + 1 + attrs_len,
        .attrs      = attrs,
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

static vector_of(struct dwarf2_die)
dwarf2_dies_decode(uint8_t *buf, size_t bufsz)
{
    vector_decl(struct dwarf2_die, dies);
    int sz = bufsz;

    while (sz > 0) {
        size_t attrs_len, len = leb_len(buf);
        struct dwarf2_die v = {
            .abbrev_idx = uleb_decode(buf),
            .attrs      = dwarf2_attrs_decode(buf+len, &attrs_len)
        };

        vector_push(&dies, v);
        buf += (len + attrs_len);
        sz  -= (len + attrs_len);
    }

    printf("sz = %d\n", sz);

    return dies;
}

static struct dwarf2_cuh
dwarf2_cuh_decode(uint8_t *buf)
{
    return (struct dwarf2_cuh) {
        .cuh_len    = *(uint32_t *)buf + 4, /* 4 is sizeof this field itself  */
        .ver        = *(uint16_t *)(buf + 4),
        .abbrev_off = *(uint32_t *)(buf + 6),
        .word_sz    = *(uint8_t  *)(buf + 10),
        .dies       = dwarf2_dies_decode(buf + DWARF2_CUH_SIZE,
                                         *(uint32_t *)buf + 4 - DWARF2_CUH_SIZE),
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

