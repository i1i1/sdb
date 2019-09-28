#include <stdint.h>

#include "macro.h"
#include "dwarf2.h"
#include "obj.h"
#include "utils.h"
#include "vector.h"


int word_size;

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
    enum dwarf2_class class;
} attribs[] = {
    DW_AT(sibling,                0x01, dwarf2_class_ref)
    DW_AT(location,               0x02, dwarf2_class_block|dwarf2_class_const)
    DW_AT(name,                   0x03, dwarf2_class_str)
    DW_AT(ordering,               0x09, dwarf2_class_const)
    DW_AT(byte_size,              0x0b, dwarf2_class_const)
    DW_AT(bit_offset,             0x0c, dwarf2_class_const)
    DW_AT(bit_size,               0x0d, dwarf2_class_const)
    DW_AT(stmt_list,              0x10, dwarf2_class_const)
    DW_AT(low_pc,                 0x11, dwarf2_class_addr)
    DW_AT(high_pc,                0x12, dwarf2_class_addr)
    DW_AT(language,               0x13, dwarf2_class_const)
    DW_AT(discr,                  0x15, dwarf2_class_ref)
    DW_AT(discr_value,            0x16, dwarf2_class_const)
    DW_AT(visibility,             0x17, dwarf2_class_const)
    DW_AT(import,                 0x18, dwarf2_class_ref)
    DW_AT(string_length,          0x19, dwarf2_class_block|dwarf2_class_const)
    DW_AT(common_reference,       0x1a, dwarf2_class_ref)
    DW_AT(comp_dir,               0x1b, dwarf2_class_str)
    DW_AT(const_value,            0x1c, dwarf2_class_str|dwarf2_class_block|dwarf2_class_const)
    DW_AT(containing_type,        0x1d, dwarf2_class_ref)
    DW_AT(default_value,          0x1e, dwarf2_class_ref)
    DW_AT(inline,                 0x20, dwarf2_class_const)
    DW_AT(is_optional,            0x21, dwarf2_class_flag)
    DW_AT(lower_bound,            0x22, dwarf2_class_ref|dwarf2_class_const)
    DW_AT(producer,               0x25, dwarf2_class_str)
    DW_AT(prototyped,             0x27, dwarf2_class_flag)
    DW_AT(return_addr,            0x2a, dwarf2_class_block|dwarf2_class_const)
    DW_AT(start_scope,            0x2c, dwarf2_class_const)
    DW_AT(stride_size,            0x2e, dwarf2_class_const)
    DW_AT(upper_bound,            0x2f, dwarf2_class_ref|dwarf2_class_const)
    DW_AT(abstract_origin,        0x31, dwarf2_class_ref)
    DW_AT(accessibility,          0x32, dwarf2_class_const)
    DW_AT(address_class,          0x33, dwarf2_class_const)
    DW_AT(artificial,             0x34, dwarf2_class_flag)
    DW_AT(base_types,             0x35, dwarf2_class_ref)
    DW_AT(calling_convention,     0x36, dwarf2_class_const)
    DW_AT(count,                  0x37, dwarf2_class_ref|dwarf2_class_const)
    DW_AT(data_member_location,   0x38, dwarf2_class_block|dwarf2_class_ref)
    DW_AT(decl_column,            0x39, dwarf2_class_const)
    DW_AT(decl_file,              0x3a, dwarf2_class_const)
    DW_AT(decl_line,              0x3b, dwarf2_class_const)
    DW_AT(declaration,            0x3c, dwarf2_class_flag)
    DW_AT(discr_list,             0x3d, dwarf2_class_block)
    DW_AT(encoding,               0x3e, dwarf2_class_const)
    DW_AT(external,               0x3f, dwarf2_class_flag)
    DW_AT(frame_base,             0x40, dwarf2_class_block|dwarf2_class_const)
    DW_AT(friend,                 0x41, dwarf2_class_ref)
    DW_AT(identifier_case,        0x42, dwarf2_class_const)
    DW_AT(macro_info,             0x43, dwarf2_class_const)
    DW_AT(namelist_item,          0x44, dwarf2_class_block)
    DW_AT(priority,               0x45, dwarf2_class_ref)
    DW_AT(segment,                0x46, dwarf2_class_block|dwarf2_class_const)
    DW_AT(specification,          0x47, dwarf2_class_ref)
    DW_AT(static_link,            0x48, dwarf2_class_block|dwarf2_class_const)
    DW_AT(type,                   0x49, dwarf2_class_ref)
    DW_AT(use_location,           0x4a, dwarf2_class_block|dwarf2_class_const)
    DW_AT(variable_parameter,     0x4b, dwarf2_class_flag)
    DW_AT(virtuality,             0x4c, dwarf2_class_const)
    DW_AT(vtable_elem_location,   0x4d, dwarf2_class_block|dwarf2_class_ref)
};
#undef DW_AT


static const char *
desc_dwarf2_class_addr(uint8_t *die, uint8_t *dstr, char buf[BUFSIZ], size_t *len)
{
    (void) buf;
    (void) dstr;

    if (word_size == 4)
        snprintf(buf, BUFSIZ, "0x%x", *(uint32_t *)die);
    else if (word_size == 8)
        snprintf(buf, BUFSIZ, "0x%lx", *(uint64_t *)die);
    else
        error("Unknown word size");

    *len = word_size;
    return buf;
}

static const char *
desc_dwarf2_class_str(uint8_t *die, uint8_t *dstr, char buf[BUFSIZ], size_t *len)
{
    (void) buf;
    (void) dstr;

    *len = strlen((char *)die) + 1;
    return (char *)die;
}

static const char *
desc_dwarf2_class_strp(uint8_t *die, uint8_t *dstr, char buf[BUFSIZ], size_t *len)
{
    (void) buf;
    uint32_t off = *(uint32_t *)die;

    *len = 4;
    return (char *)dstr + off;
}

static const char *
desc_dwarf2_class_data1(uint8_t *die, uint8_t *dstr, char buf[BUFSIZ], size_t *len)
{
    (void) dstr;

    snprintf(buf, BUFSIZ, "%d", *(uint8_t *)die);
    *len = 1;

    return buf;
}

static const char *
desc_dwarf2_class_data2(uint8_t *die, uint8_t *dstr, char buf[BUFSIZ], size_t *len)
{
    (void) dstr;

    snprintf(buf, BUFSIZ, "%d", *(uint16_t *)die);
    *len = 2;

    return buf;
}

static const char *
desc_dwarf2_class_data4(uint8_t *die, uint8_t *dstr, char buf[BUFSIZ], size_t *len)
{
    (void) dstr;

    snprintf(buf, BUFSIZ, "%d", *(uint32_t *)die);
    *len = 4;

    return buf;
}

static const char *
desc_dwarf2_class_data8(uint8_t *die, uint8_t *dstr, char buf[BUFSIZ], size_t *len)
{
    (void) dstr;

    snprintf(buf, BUFSIZ, "%ld", *(uint64_t *)die);
    *len = 8;

    return buf;
}

static const char *
desc_dwarf2_class_udata(uint8_t *die, uint8_t *dstr, char buf[BUFSIZ], size_t *len)
{
    (void) dstr;

    *len = leb_len(die);
    snprintf(buf, BUFSIZ, "%ld", uleb_decode(die));

    return buf;
}

static const char *
desc_dwarf2_class_sdata(uint8_t *die, uint8_t *dstr, char buf[BUFSIZ], size_t *len)
{
    (void) dstr;

    *len = leb_len(die);
    snprintf(buf, BUFSIZ, "%ld", sleb_decode(die));

    return buf;
}

static const char *
desc_dwarf2_class_ref1(uint8_t *die, uint8_t *dstr, char buf[BUFSIZ], size_t *len)
{
    (void) dstr;

    snprintf(buf, BUFSIZ, "<0x%x>", *(uint8_t *)die);
    *len = 1;

    return buf;
}

static const char *
desc_dwarf2_class_ref2(uint8_t *die, uint8_t *dstr, char buf[BUFSIZ], size_t *len)
{
    (void) dstr;

    snprintf(buf, BUFSIZ, "<0x%x>", *(uint16_t *)die);
    *len = 2;

    return buf;
}

static const char *
desc_dwarf2_class_ref4(uint8_t *die, uint8_t *dstr, char buf[BUFSIZ], size_t *len)
{
    (void) dstr;

    snprintf(buf, BUFSIZ, "<0x%x>", *(uint32_t *)die);
    *len = 4;

    return buf;
}

static const char *
desc_dwarf2_class_ref8(uint8_t *die, uint8_t *dstr, char buf[BUFSIZ], size_t *len)
{
    (void) dstr;

    snprintf(buf, BUFSIZ, "<0x%lx>", *(uint64_t *)die);
    *len = 8;

    return buf;
}

static const char *
desc_dwarf2_class_block1(uint8_t *die, uint8_t *dstr, char buf[BUFSIZ], size_t *len)
{
    (void) dstr;

    snprintf(buf, BUFSIZ, "block of size %d", *(uint8_t *)die);
    *len = 1 + *(uint8_t *)die;

    return buf;
}

static const char *
desc_dwarf2_class_flag(uint8_t *die, uint8_t *dstr, char buf[BUFSIZ], size_t *len)
{
    (void) dstr;

    snprintf(buf, BUFSIZ, "%d", *(uint8_t *)die);
    *len = 1;

    return buf;
}


#define DW_FORM(str_, form_, desc_, class_) \
    {                                       \
        .str = STRINGIFY(str_),             \
        .form = form_,                      \
        .class = class_,                    \
        .desc = desc_,                      \
    },
struct dwarf2_form {
    char *str;
    uintmax_t form;
    enum dwarf2_class class;
    const char *(*desc)(uint8_t *die, uint8_t *dstr, char buf[BUFSIZ], size_t *len);
} forms[] = {
    DW_FORM(addr,        0x01, desc_dwarf2_class_addr, dwarf2_class_addr)
    DW_FORM(block2,      0x03, NULL, dwarf2_class_block)
    DW_FORM(block4,      0x04, NULL, dwarf2_class_block)
    DW_FORM(data2,       0x05, desc_dwarf2_class_data2, dwarf2_class_const)
    DW_FORM(data4,       0x06, desc_dwarf2_class_data4, dwarf2_class_const)
    DW_FORM(data8,       0x07, desc_dwarf2_class_data8, dwarf2_class_const)
    DW_FORM(string,      0x08, desc_dwarf2_class_str, dwarf2_class_str)
    DW_FORM(block,       0x09, NULL, dwarf2_class_block)
    DW_FORM(block1,      0x0a, desc_dwarf2_class_block1, dwarf2_class_block)
    DW_FORM(data1,       0x0b, desc_dwarf2_class_data1, dwarf2_class_const)
    DW_FORM(flag,        0x0c, desc_dwarf2_class_flag, dwarf2_class_flag)
    DW_FORM(sdata,       0x0d, desc_dwarf2_class_sdata, dwarf2_class_const)
    DW_FORM(strp,        0x0e, desc_dwarf2_class_strp, dwarf2_class_str)
    DW_FORM(udata,       0x0f, desc_dwarf2_class_udata, dwarf2_class_const)
    DW_FORM(ref_addr,    0x10, NULL, dwarf2_class_ref)
    DW_FORM(ref1,        0x11, desc_dwarf2_class_ref1, dwarf2_class_ref)
    DW_FORM(ref2,        0x12, desc_dwarf2_class_ref2, dwarf2_class_ref)
    DW_FORM(ref4,        0x13, desc_dwarf2_class_ref4, dwarf2_class_ref)
    DW_FORM(ref8,        0x14, desc_dwarf2_class_ref8, dwarf2_class_ref)
    DW_FORM(ref_udata,   0x15, NULL, dwarf2_class_ref)
    DW_FORM(indirect,    0x16, NULL, 0)
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

static const struct dwarf2_form *
dwarf2_form_struct_lookup(uintmax_t nm)
{
    for (unsigned i = 0; i < ARRAY_SIZE(forms); i++) {
        if (forms[i].form == nm)
            return forms + i;
    }
    return NULL;
}
 
const char *
dwarf2_form_lookup(uintmax_t nm)
{
    const struct dwarf2_form *f = dwarf2_form_struct_lookup(nm);
    return f ? f->str : NULL;
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

struct dwarf2_abbrev
dwarf2_abbrevtbl_decode(uint8_t *buf, size_t *len)
{
    size_t id_len  = leb_len(buf);

    if (uleb_decode(buf) == 0) {
        *len = id_len;
        return (struct dwarf2_abbrev) {
            .id = 0,
        };
    }

    size_t tag_len = leb_len(buf+id_len);
    size_t attrs_len;
    vector_of(struct dwarf2_attr) attrs =
        dwarf2_attrs_decode(buf + id_len + tag_len + 1, &attrs_len);
    int has_children = buf[id_len+tag_len];
    vector_decl(struct dwarf2_abbrev, children);

    *len = attrs_len + id_len + tag_len + 1; /* 1 is length of field child */

    if (has_children) {
        struct dwarf2_abbrev atbl;
        size_t children_len = 0;
        uint8_t *tbl = buf + *len;
        size_t alen;

        do {
            atbl = dwarf2_abbrevtbl_decode(tbl, &alen);
            children_len += alen;
            tbl += alen;

            vector_push(&children, atbl);
        } while (atbl.id != 0);

        *len += children_len;
    }

    return (struct dwarf2_abbrev) {
        .id       = uleb_decode(buf),
        .tag      = uleb_decode(buf+id_len),
        .children = children,
        .attrs    = attrs,
    };
}

struct dwarf2_cu
dwarf2_cu_decode(uint8_t *buf)
{
    return (struct dwarf2_cu) {
        /* 4 is sizeof this field itself  */
        .cu_len     = *(uint32_t *)buf + 4,
        .dies_len   = *(uint32_t *)buf - (DWARF2_CUH_SIZE - 4),
        .ver        = *(uint16_t *)(buf + 4),
        .abbrev_off = *(uint32_t *)(buf + 6),
        .word_sz    = *(uint8_t  *)(buf + 10),
        .dies       = buf + DWARF2_CUH_SIZE,
    };
}

vector_of(struct dwarf2_cu)
dwarf2_cus_decode(struct sect *dinfo)
{
    vector_decl(struct dwarf2_cu, ret);
    uint8_t *buf = dinfo->buf;
    int remain   = dinfo->size;

    while (remain > 0) {
        struct dwarf2_cu v = dwarf2_cu_decode(buf);

        remain -= v.cu_len;
        buf    += v.cu_len;
        vector_push(&ret, v);
    }

    return ret;
}

const char *
dwarf2_describe_attrib(uint8_t *die, struct dwarf2_attr attr, uint8_t *dstr, size_t *len)
{
    static char buf[BUFSIZ] = "";
    const struct dwarf2_form *f = dwarf2_form_struct_lookup(attr.form);

    *len = 0;

    if (f->desc)
        return f->desc(die, dstr, buf, len);
    printf("Todo %s\n", f->str);
    todo();
    return NULL;
}

