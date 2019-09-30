#include <stdint.h>

#include "macro.h"
#include "dwarf.h"
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
    enum dwarf_class class;
} attribs[] = {
    DW_AT(sibling,                0x01, dwarf_class_ref)
    DW_AT(location,               0x02, dwarf_class_block|dwarf_class_const)
    DW_AT(name,                   0x03, dwarf_class_str)
    DW_AT(ordering,               0x09, dwarf_class_const)
    DW_AT(byte_size,              0x0b, dwarf_class_const)
    DW_AT(bit_offset,             0x0c, dwarf_class_const)
    DW_AT(bit_size,               0x0d, dwarf_class_const)
    DW_AT(stmt_list,              0x10, dwarf_class_const)
    DW_AT(low_pc,                 0x11, dwarf_class_addr)
    DW_AT(high_pc,                0x12, dwarf_class_addr)
    DW_AT(language,               0x13, dwarf_class_const)
    DW_AT(discr,                  0x15, dwarf_class_ref)
    DW_AT(discr_value,            0x16, dwarf_class_const)
    DW_AT(visibility,             0x17, dwarf_class_const)
    DW_AT(import,                 0x18, dwarf_class_ref)
    DW_AT(string_length,          0x19, dwarf_class_block|dwarf_class_const)
    DW_AT(common_reference,       0x1a, dwarf_class_ref)
    DW_AT(comp_dir,               0x1b, dwarf_class_str)
    DW_AT(const_value,            0x1c, dwarf_class_str|dwarf_class_block|dwarf_class_const)
    DW_AT(containing_type,        0x1d, dwarf_class_ref)
    DW_AT(default_value,          0x1e, dwarf_class_ref)
    DW_AT(inline,                 0x20, dwarf_class_const)
    DW_AT(is_optional,            0x21, dwarf_class_flag)
    DW_AT(lower_bound,            0x22, dwarf_class_ref|dwarf_class_const)
    DW_AT(producer,               0x25, dwarf_class_str)
    DW_AT(prototyped,             0x27, dwarf_class_flag)
    DW_AT(return_addr,            0x2a, dwarf_class_block|dwarf_class_const)
    DW_AT(start_scope,            0x2c, dwarf_class_const)
    DW_AT(stride_size,            0x2e, dwarf_class_const)
    DW_AT(upper_bound,            0x2f, dwarf_class_ref|dwarf_class_const)
    DW_AT(abstract_origin,        0x31, dwarf_class_ref)
    DW_AT(accessibility,          0x32, dwarf_class_const)
    DW_AT(address_class,          0x33, dwarf_class_const)
    DW_AT(artificial,             0x34, dwarf_class_flag)
    DW_AT(base_types,             0x35, dwarf_class_ref)
    DW_AT(calling_convention,     0x36, dwarf_class_const)
    DW_AT(count,                  0x37, dwarf_class_ref|dwarf_class_const)
    DW_AT(data_member_location,   0x38, dwarf_class_block|dwarf_class_ref)
    DW_AT(decl_column,            0x39, dwarf_class_const)
    DW_AT(decl_file,              0x3a, dwarf_class_const)
    DW_AT(decl_line,              0x3b, dwarf_class_const)
    DW_AT(declaration,            0x3c, dwarf_class_flag)
    DW_AT(discr_list,             0x3d, dwarf_class_block)
    DW_AT(encoding,               0x3e, dwarf_class_const)
    DW_AT(external,               0x3f, dwarf_class_flag)
    DW_AT(frame_base,             0x40, dwarf_class_block|dwarf_class_const)
    DW_AT(friend,                 0x41, dwarf_class_ref)
    DW_AT(identifier_case,        0x42, dwarf_class_const)
    DW_AT(macro_info,             0x43, dwarf_class_const)
    DW_AT(namelist_item,          0x44, dwarf_class_block)
    DW_AT(priority,               0x45, dwarf_class_ref)
    DW_AT(segment,                0x46, dwarf_class_block|dwarf_class_const)
    DW_AT(specification,          0x47, dwarf_class_ref)
    DW_AT(static_link,            0x48, dwarf_class_block|dwarf_class_const)
    DW_AT(type,                   0x49, dwarf_class_ref)
    DW_AT(use_location,           0x4a, dwarf_class_block|dwarf_class_const)
    DW_AT(variable_parameter,     0x4b, dwarf_class_flag)
    DW_AT(virtuality,             0x4c, dwarf_class_const)
    DW_AT(vtable_elem_location,   0x4d, dwarf_class_block|dwarf_class_ref)
    DW_AT(allocated,              0x4e, dwarf_class_block|dwarf_class_const|dwarf_class_ref)
    DW_AT(associated,             0x4f, dwarf_class_block|dwarf_class_const|dwarf_class_ref)
    DW_AT(data_location,          0x50, dwarf_class_block)
    DW_AT(byte_stride,            0x51, dwarf_class_block|dwarf_class_const|dwarf_class_ref)
    DW_AT(entry_pc,               0x52, dwarf_class_addr)
    DW_AT(use_UTF8,               0x53, dwarf_class_flag)
    DW_AT(extension,              0x54, dwarf_class_ref)
    DW_AT(ranges,                 0x55, 0) /* rangelistptr */
    DW_AT(trampoline,             0x56, dwarf_class_addr|dwarf_class_flag|dwarf_class_ref|dwarf_class_str)
    DW_AT(call_column,            0x57, dwarf_class_const)
    DW_AT(call_file,              0x58, dwarf_class_const)
    DW_AT(call_line,              0x59, dwarf_class_const)
    DW_AT(description,            0x5a, dwarf_class_str)
    DW_AT(binary_scale,           0x5b, dwarf_class_const)
    DW_AT(decimal_scale,          0x5c, dwarf_class_const)
    DW_AT(small,                  0x5d, dwarf_class_ref)
    DW_AT(decimal_sign,           0x5e, dwarf_class_const)
    DW_AT(digit_count,            0x5f, dwarf_class_const)
    DW_AT(picture_string,         0x60, dwarf_class_str)
    DW_AT(mutable,                0x61, dwarf_class_flag)
    DW_AT(threads_scaled,         0x62, dwarf_class_flag)
    DW_AT(explicit,               0x63, dwarf_class_flag)
    DW_AT(object_pointer,         0x64, dwarf_class_ref)
    DW_AT(endianity,              0x65, dwarf_class_const)
    DW_AT(elemental,              0x66, dwarf_class_flag)
    DW_AT(pure,                   0x67, dwarf_class_flag)
    DW_AT(recursive,              0x68, dwarf_class_flag)
};
#undef DW_AT


static const char *
desc_dwarf_class_addr(uint8_t *die, uint8_t *dstr, char buf[BUFSIZ], size_t *len)
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
desc_dwarf_class_str(uint8_t *die, uint8_t *dstr, char buf[BUFSIZ], size_t *len)
{
    (void) buf;
    (void) dstr;

    *len = strlen((char *)die) + 1;
    return (char *)die;
}

static const char *
desc_dwarf_class_strp(uint8_t *die, uint8_t *dstr, char buf[BUFSIZ], size_t *len)
{
    (void) buf;
    uint32_t off = *(uint32_t *)die;

    *len = 4;
    return (char *)dstr + off;
}

static const char *
desc_dwarf_class_data1(uint8_t *die, uint8_t *dstr, char buf[BUFSIZ], size_t *len)
{
    (void) dstr;

    snprintf(buf, BUFSIZ, "%d", *(uint8_t *)die);
    *len = 1;

    return buf;
}

static const char *
desc_dwarf_class_data2(uint8_t *die, uint8_t *dstr, char buf[BUFSIZ], size_t *len)
{
    (void) dstr;

    snprintf(buf, BUFSIZ, "%d", *(uint16_t *)die);
    *len = 2;

    return buf;
}

static const char *
desc_dwarf_class_data4(uint8_t *die, uint8_t *dstr, char buf[BUFSIZ], size_t *len)
{
    (void) dstr;

    snprintf(buf, BUFSIZ, "%d", *(uint32_t *)die);
    *len = 4;

    return buf;
}

static const char *
desc_dwarf_class_data8(uint8_t *die, uint8_t *dstr, char buf[BUFSIZ], size_t *len)
{
    (void) dstr;

    snprintf(buf, BUFSIZ, "%ld", *(uint64_t *)die);
    *len = 8;

    return buf;
}

static const char *
desc_dwarf_class_udata(uint8_t *die, uint8_t *dstr, char buf[BUFSIZ], size_t *len)
{
    (void) dstr;

    *len = leb_len(die);
    snprintf(buf, BUFSIZ, "%ld", uleb_decode(die));

    return buf;
}

static const char *
desc_dwarf_class_sdata(uint8_t *die, uint8_t *dstr, char buf[BUFSIZ], size_t *len)
{
    (void) dstr;

    *len = leb_len(die);
    snprintf(buf, BUFSIZ, "%ld", sleb_decode(die));

    return buf;
}

static const char *
desc_dwarf_class_ref1(uint8_t *die, uint8_t *dstr, char buf[BUFSIZ], size_t *len)
{
    (void) dstr;

    snprintf(buf, BUFSIZ, "<0x%x>", *(uint8_t *)die);
    *len = 1;

    return buf;
}

static const char *
desc_dwarf_class_ref2(uint8_t *die, uint8_t *dstr, char buf[BUFSIZ], size_t *len)
{
    (void) dstr;

    snprintf(buf, BUFSIZ, "<0x%x>", *(uint16_t *)die);
    *len = 2;

    return buf;
}

static const char *
desc_dwarf_class_ref4(uint8_t *die, uint8_t *dstr, char buf[BUFSIZ], size_t *len)
{
    (void) dstr;

    snprintf(buf, BUFSIZ, "<0x%x>", *(uint32_t *)die);
    *len = 4;

    return buf;
}

static const char *
desc_dwarf_class_ref8(uint8_t *die, uint8_t *dstr, char buf[BUFSIZ], size_t *len)
{
    (void) dstr;

    snprintf(buf, BUFSIZ, "<0x%lx>", *(uint64_t *)die);
    *len = 8;

    return buf;
}

static const char *
desc_dwarf_class_block1(uint8_t *die, uint8_t *dstr, char buf[BUFSIZ], size_t *len)
{
    (void) dstr;

    snprintf(buf, BUFSIZ, "block of size %d", *(uint8_t *)die);
    *len = 1 + *(uint8_t *)die;

    return buf;
}

static const char *
desc_dwarf_class_flag(uint8_t *die, uint8_t *dstr, char buf[BUFSIZ], size_t *len)
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
struct dwarf_form {
    char *str;
    uintmax_t form;
    enum dwarf_class class;
    const char *(*desc)(uint8_t *die, uint8_t *dstr, char buf[BUFSIZ], size_t *len);
} forms[] = {
    DW_FORM(addr,        0x01, desc_dwarf_class_addr, dwarf_class_addr)
    DW_FORM(block2,      0x03, NULL, dwarf_class_block)
    DW_FORM(block4,      0x04, NULL, dwarf_class_block)
    DW_FORM(data2,       0x05, desc_dwarf_class_data2, dwarf_class_const)
    DW_FORM(data4,       0x06, desc_dwarf_class_data4, dwarf_class_const)
    DW_FORM(data8,       0x07, desc_dwarf_class_data8, dwarf_class_const)
    DW_FORM(string,      0x08, desc_dwarf_class_str, dwarf_class_str)
    DW_FORM(block,       0x09, NULL, dwarf_class_block)
    DW_FORM(block1,      0x0a, desc_dwarf_class_block1, dwarf_class_block)
    DW_FORM(data1,       0x0b, desc_dwarf_class_data1, dwarf_class_const)
    DW_FORM(flag,        0x0c, desc_dwarf_class_flag, dwarf_class_flag)
    DW_FORM(sdata,       0x0d, desc_dwarf_class_sdata, dwarf_class_const)
    DW_FORM(strp,        0x0e, desc_dwarf_class_strp, dwarf_class_str)
    DW_FORM(udata,       0x0f, desc_dwarf_class_udata, dwarf_class_const)
    DW_FORM(ref_addr,    0x10, NULL, dwarf_class_ref)
    DW_FORM(ref1,        0x11, desc_dwarf_class_ref1, dwarf_class_ref)
    DW_FORM(ref2,        0x12, desc_dwarf_class_ref2, dwarf_class_ref)
    DW_FORM(ref4,        0x13, desc_dwarf_class_ref4, dwarf_class_ref)
    DW_FORM(ref8,        0x14, desc_dwarf_class_ref8, dwarf_class_ref)
    DW_FORM(ref_udata,   0x15, NULL, dwarf_class_ref)
    DW_FORM(indirect,    0x16, NULL, 0)
};
#undef DW_FORM


const char *
dwarf_tag_lookup(uintmax_t tag)
{
    for (unsigned i = 0; i < ARRAY_SIZE(tags); i++) {
        if (tags[i].tag == tag)
            return tags[i].str;
    }
    return NULL;
}

const char *
dwarf_attrib_lookup(uintmax_t nm)
{
    for (unsigned i = 0; i < ARRAY_SIZE(attribs); i++) {
        if (attribs[i].attr == nm)
            return attribs[i].str;
    }
    return NULL;
}

static const struct dwarf_form *
dwarf_form_struct_lookup(uintmax_t nm)
{
    for (unsigned i = 0; i < ARRAY_SIZE(forms); i++) {
        if (forms[i].form == nm)
            return forms + i;
    }
    return NULL;
}
 
const char *
dwarf_form_lookup(uintmax_t nm)
{
    const struct dwarf_form *f = dwarf_form_struct_lookup(nm);
    return f ? f->str : NULL;
}

static vector_of(struct dwarf_attr)
dwarf_attrs_decode(uint8_t *buf, size_t *attrs_len)
{
    vector_decl(struct dwarf_attr, attrs);
    struct dwarf_attr v;
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

struct dwarf_abbrev
dwarf_abbrevtbl_decode(uint8_t *buf, size_t *len)
{
    size_t id_len = leb_len(buf);

    if (uleb_decode(buf) == 0) {
        *len = id_len;
        return (struct dwarf_abbrev) {
            .id = 0,
        };
    }

    size_t tag_len = leb_len(buf+id_len);
    size_t attrs_len;
    vector_of(struct dwarf_attr) attrs =
        dwarf_attrs_decode(buf + id_len + tag_len + 1, &attrs_len);
    bool has_children = buf[id_len+tag_len] ? true : false;
    vector_decl(struct dwarf_abbrev, children);

    *len = attrs_len + id_len + tag_len + 1; /* 1 is length of field child */

    if (has_children) {
        struct dwarf_abbrev atbl;
        size_t children_len = 0;
        uint8_t *tbl = buf + *len;
        size_t alen;

        do {
            atbl = dwarf_abbrevtbl_decode(tbl, &alen);
            children_len += alen;
            tbl += alen;

            vector_push(&children, atbl);
        } while (atbl.id != 0);

        *len += children_len;
    }

    return (struct dwarf_abbrev) {
        .id       = uleb_decode(buf),
        .tag      = uleb_decode(buf+id_len),
        .children = children,
        .attrs    = attrs,
    };
}

struct dwarf_cu
dwarf_cu_decode(uint8_t *buf)
{
    struct dwarf_cu ret;

#define BUF_READ(buf_, var_, type_) do {                \
           (var_)  = *(type_ *)(buf_);                  \
           (buf_) += sizeof(type_);                     \
    } while (0)

    BUF_READ(buf, ret.cu_len, uint32_t);
    ret.is_64 = (ret.cu_len == 0xFFFFFFFF) ? true : false;

    if (ret.is_64)
        BUF_READ(buf, ret.cu_len, uint64_t);

    ret.dies_len = ret.cu_len;
    ret.cu_len += ret.is_64 ? 12 : 4;

    BUF_READ(buf, ret.ver, uint16_t);
    ret.dies_len -= sizeof(uint16_t);

    if (ret.is_64) {
        BUF_READ(buf, ret.abbrev_off, uint64_t);
        ret.dies_len -= sizeof(uint64_t);
    } else {
        BUF_READ(buf, ret.abbrev_off, uint32_t);
        ret.dies_len -= sizeof(uint32_t);
    }

    BUF_READ(buf, ret.word_sz, uint8_t);
    ret.dies_len -= sizeof(uint8_t);
    ret.dies = buf;

#undef BUF_READ
    return ret;
}

vector_of(struct dwarf_cu)
dwarf_cus_decode(struct sect *dinfo)
{
    vector_decl(struct dwarf_cu, ret);
    uint8_t *buf = dinfo->buf;
    int remain   = dinfo->size;

    while (remain > 0) {
        struct dwarf_cu v = dwarf_cu_decode(buf);

        remain -= v.cu_len;
        buf    += v.cu_len;
        vector_push(&ret, v);
    }

    return ret;
}

const char *
dwarf_describe_attrib(uint8_t *die, struct dwarf_attr attr, uint8_t *dstr, size_t *len)
{
    static char buf[BUFSIZ] = "";
    const struct dwarf_form *f = dwarf_form_struct_lookup(attr.form);

    *len = 0;

    if (f->desc)
        return f->desc(die, dstr, buf, len);
    printf("Todo %s\n", f->str);
    todo();
    return NULL;
}

