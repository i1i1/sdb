#include <stdint.h>

#include "macro.h"
#include "dwarf.h"
#include "obj.h"
#include "utils.h"
#include "vector.h"

#include "dwarf_db.h"

#define BUF_READ(buf_, var_, type_) do {                \
           (var_)  = *(type_ *)(buf_);                  \
           (buf_) += sizeof(type_);                     \
    } while (0)


int word_size;


void op_ext(struct dwarf_machine *m, uint8_t *buf, size_t *size);

struct opcode {
    char *type;
    char *name;
    void (*handler)(struct dwarf_machine *, uint8_t *, size_t *);
} ops[] = {
    [0x00] = { "extended", "extended", op_ext },
};


static struct dwarf_obj
obj_dwarf_class_addr(uint8_t *die, struct obj *o, size_t *len)
{
    (void) o;
    struct dwarf_obj ret;

    ret.class = dwarf_class_addr;

    if (word_size == 4)
        ret.un.addr = *(uint32_t *)die;
    else if (word_size == 8)
        ret.un.addr = *(uint64_t *)die;
    else
        error("Unknown word size %d\n", word_size);

    *len = word_size;
    return ret;
}

static struct dwarf_obj
obj_dwarf_class_str(uint8_t *die, struct obj *o, size_t *len)
{
    (void) o;
    *len = strlen((char *)die) + 1;
    return (struct dwarf_obj) {
        .class  = dwarf_class_str,
        .un.str = (char *)die,
    };
}

static struct dwarf_obj
obj_dwarf_class_strp(uint8_t *die, struct obj *o, size_t *len)
{
    struct sect dstr = obj_get_sect_by_name(o, ".debug_str");
    uint32_t off = *(uint32_t *)die;

    *len = 4;

    return (struct dwarf_obj) {
        .class  = dwarf_class_str,
        .un.str = (char *)(dstr.buf + off),
    };
}

static struct dwarf_obj
obj_dwarf_class_data1(uint8_t *die, struct obj *o, size_t *len)
{
    (void) o;
    *len = 1;
    return (struct dwarf_obj) {
        .class     = dwarf_class_const,
        .un.const_ = *(uint8_t *)die,
    };
}

static struct dwarf_obj
obj_dwarf_class_data2(uint8_t *die, struct obj *o, size_t *len)
{
    (void) o;
    *len = 2;
    return (struct dwarf_obj) {
        .class     = dwarf_class_const,
        .un.const_ = *(uint16_t *)die,
    };
}

static struct dwarf_obj
obj_dwarf_class_data4(uint8_t *die, struct obj *o, size_t *len)
{
    (void) o;
    *len = 4;
    return (struct dwarf_obj) {
        .class     = dwarf_class_const,
        .un.const_ = *(uint32_t *)die,
    };
}

static struct dwarf_obj
obj_dwarf_class_data8(uint8_t *die, struct obj *o, size_t *len)
{
    (void) o;
    *len = 8;
    return (struct dwarf_obj) {
        .class     = dwarf_class_const,
        .un.const_ = *(uint64_t *)die,
    };
}

static struct dwarf_obj
obj_dwarf_class_udata(uint8_t *die, struct obj *o, size_t *len)
{
    (void) o;
    *len = leb_len(die);
    return (struct dwarf_obj) {
        .class     = dwarf_class_const,
        .un.const_ = uleb_decode(die),
    };
}

static struct dwarf_obj
obj_dwarf_class_sdata(uint8_t *die, struct obj *o, size_t *len)
{
    (void) o;
    *len = leb_len(die);
    return (struct dwarf_obj) {
        .class     = dwarf_class_const,
        .un.const_ = sleb_decode(die),
    };
}

static struct dwarf_obj
obj_dwarf_class_ref1(uint8_t *die, struct obj *o, size_t *len)
{
    (void) o;
    *len = 1;
    return (struct dwarf_obj) {
        .class  = dwarf_class_ref,
        .un.ref = *(uint8_t *)die,
    };
}

static struct dwarf_obj
obj_dwarf_class_ref2(uint8_t *die, struct obj *o, size_t *len)
{
    (void) o;
    *len = 2;
    return (struct dwarf_obj) {
        .class  = dwarf_class_ref,
        .un.ref = *(uint16_t *)die,
    };
}

static struct dwarf_obj
obj_dwarf_class_ref4(uint8_t *die, struct obj *o, size_t *len)
{
    (void) o;
    *len = 4;
    return (struct dwarf_obj) {
        .class  = dwarf_class_ref,
        .un.ref = *(uint32_t *)die,
    };
}

static struct dwarf_obj
obj_dwarf_class_ref8(uint8_t *die, struct obj *o, size_t *len)
{
    (void) o;
    *len = 8;
    return (struct dwarf_obj) {
        .class  = dwarf_class_ref,
        .un.ref = *(uint64_t *)die,
    };
}

static struct dwarf_obj
obj_dwarf_class_block1(uint8_t *die, struct obj *o, size_t *len)
{
    (void) o;
    *len = 8;
    return (struct dwarf_obj) {
        .class  = dwarf_class_block,
        .un.block = {
            .len = *(uint8_t *) die,
            .ptr = die + 1,
        },
    };
}

static struct dwarf_obj
obj_dwarf_class_flag(uint8_t *die, struct obj *o, size_t *len)
{
    (void) o;
    *len = 1;
    return (struct dwarf_obj) {
        .class   = dwarf_class_flag,
        .un.flag = *(uint8_t *)die,
    };
}


#define DW_FORM(str_, form_, obj_, class_)  \
    [form_] = {                             \
        .str = STRINGIFY(str_),             \
        .form = form_,                      \
        .class = class_,                    \
        .obj = obj_,                        \
    },
struct dwarf_form {
    char *str;
    uintmax_t form;
    enum dwarf_class class;
    struct dwarf_obj (*obj)(uint8_t *die, struct obj *o, size_t *len);
} forms[] = {
    DW_FORM(addr,        0x01, obj_dwarf_class_addr, dwarf_class_addr)
    DW_FORM(block2,      0x03, NULL, dwarf_class_block)
    DW_FORM(block4,      0x04, NULL, dwarf_class_block)
    DW_FORM(data2,       0x05, obj_dwarf_class_data2, dwarf_class_const)
    DW_FORM(data4,       0x06, obj_dwarf_class_data4, dwarf_class_const)
    DW_FORM(data8,       0x07, obj_dwarf_class_data8, dwarf_class_const)
    DW_FORM(string,      0x08, obj_dwarf_class_str, dwarf_class_str)
    DW_FORM(block,       0x09, NULL, dwarf_class_block)
    DW_FORM(block1,      0x0a, obj_dwarf_class_block1, dwarf_class_block)
    DW_FORM(data1,       0x0b, obj_dwarf_class_data1, dwarf_class_const)
    DW_FORM(flag,        0x0c, obj_dwarf_class_flag, dwarf_class_flag)
    DW_FORM(sdata,       0x0d, obj_dwarf_class_sdata, dwarf_class_const)
    DW_FORM(strp,        0x0e, obj_dwarf_class_strp, dwarf_class_str)
    DW_FORM(udata,       0x0f, obj_dwarf_class_udata, dwarf_class_const)
    DW_FORM(ref_addr,    0x10, NULL, dwarf_class_ref)
    DW_FORM(ref1,        0x11, obj_dwarf_class_ref1, dwarf_class_ref)
    DW_FORM(ref2,        0x12, obj_dwarf_class_ref2, dwarf_class_ref)
    DW_FORM(ref4,        0x13, obj_dwarf_class_ref4, dwarf_class_ref)
    DW_FORM(ref8,        0x14, obj_dwarf_class_ref8, dwarf_class_ref)
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

static struct dwarf_abbrev *
abbrev_lookup(struct dwarf_abbrev *atbl, uintmax_t id)
{
    if (atbl->id == id)
        return atbl;

    for (unsigned i = 0; i < vector_nmemb(&atbl->children); i++) {
        struct dwarf_abbrev *ret = abbrev_lookup(atbl->children + i, id);
        if (ret)
            return ret;
    }

    return NULL;
}

struct dwarf_cu
dwarf_cu_decode(uint8_t *buf, struct obj *o)
{
    struct sect dabbrev = obj_get_sect_by_name(o, ".debug_abbrev");
    struct dwarf_cu ret;

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
    word_size = ret.word_sz;

    ret.dies_len -= sizeof(uint8_t);
    ret.dies = NULL;

    size_t _;
    struct dwarf_abbrev atbl = dwarf_abbrevtbl_decode(dabbrev.buf + ret.abbrev_off, &_);
    uint8_t *die = buf;
    size_t die_len = ret.dies_len;

    while (die_len > 0) {
        struct dwarf_abbrev *abbrev = abbrev_lookup(&atbl, uleb_decode(die));

        die_len -= leb_len(die);
        die += leb_len(die);

        if (!abbrev)
            continue;

        vector_decl(struct dwarf_attr, attrs);

        vector_foreach(a, &abbrev->attrs) {
            size_t len;

            if (forms[a.form].obj == NULL)
                todo();
            a.val = forms[a.form].obj(die, o, &len);
            vector_push(&attrs, a);

            die_len -= len;
            die     += len;
        }
        struct dwarf_die die = {
            .tag = abbrev->tag,
            .attrs = attrs,
        };
        vector_push(&ret.dies, die);
    }

    return ret;
}

vector_of(struct dwarf_cu)
dwarf_cus_decode(struct obj *o)
{
    struct sect dinfo   = obj_get_sect_by_name(o, ".debug_info");
    vector_decl(struct dwarf_cu, ret);

    if (!dinfo.name)
        return ret;

    uint8_t *buf = dinfo.buf;
    int remain   = dinfo.size;

    while (remain > 0) {
        struct dwarf_cu v = dwarf_cu_decode(buf, o);

        remain -= v.cu_len;
        buf    += v.cu_len;
        vector_push(&ret, v);
    }

    return ret;
}

static struct dwarf_prol
line_header_decode(uint8_t *buf, size_t *len)
{
    uint8_t *start_buf = buf;
    struct dwarf_prol ret;

    BUF_READ(buf, ret.unit_len, uint32_t);
    ret.is_64 = (ret.unit_len == 0xFFFFFFFF);

    if (ret.is_64)
        BUF_READ(buf, ret.unit_len, uint64_t);

    BUF_READ(buf, ret.ver, uint16_t);

    if (ret.is_64)
        BUF_READ(buf, ret.header_len, uint64_t);
    else
        BUF_READ(buf, ret.header_len, uint32_t);

    BUF_READ(buf, ret.inst_len,    uint8_t);
    BUF_READ(buf, ret.def_is_stmt, uint8_t);
    BUF_READ(buf, ret.line_base,   int8_t);
    BUF_READ(buf, ret.line_range,  uint8_t);
    BUF_READ(buf, ret.op_base, uint8_t);

    ret.std_op_lens = NULL;
    ret.inc_dirs    = NULL;
    ret.fnames      = NULL;

    for (int i = 1; i < ret.op_base; i++) {
        uint8_t ln;
        BUF_READ(buf, ln, uint8_t);
        vector_push(&ret.std_op_lens, ln);
    }

    while (!STREQ((char *)buf, "")) {
        vector_push(&ret.inc_dirs, (char *)buf);
        buf += strlen((char *)buf) + 1;
    }

    buf += 1;

    while (!STREQ((char *)buf, "")) {
        struct dwarf_prol_file f;

        f.fn = (char *)buf;
        buf += strlen((char *)buf) + 1;
        f.dir_idx = uleb_decode(buf);
        buf += leb_len(buf);
        f.last_mod_time = uleb_decode(buf);
        buf += leb_len(buf);
        f.flen = uleb_decode(buf);
        buf += leb_len(buf);

        vector_push(&ret.fnames, f);
    }
    *len = buf - start_buf + 1;
    return ret;
}

void
op_ext(struct dwarf_machine *m, uint8_t *buf, size_t *size)
{
    enum DW_LNE {
        end_sequence = 0x01,
        set_address  = 0x02,
        define_file  = 0x03,
    };
    size_t sz_len = leb_len(buf);
    uintmax_t sz = uleb_decode(buf);

    *size = sz + sz_len;
    buf += sz_len;

    switch (*buf++) {
    case end_sequence:
        *m = (struct dwarf_machine) {
            .addr = 0,
            .file = 1,
            .line = 1,
        };
        break;
    case set_address:
        switch (sz - 1) {
        case 4:
            m->addr = *(uint32_t *)buf;
            break;
        case 8:
            m->addr = *(uint64_t *)buf;
            break;
        default:
            error("DW_LNE_set_address: unknown size of address - %d\n", (int)sz);
        }

        break;
    case define_file:
        todo();
        break;
    default:
        error("Unknown extended opcode - %d\n", buf[-1]);
    }
}

struct line line_err = { NULL, -1 };

struct line
addr2line(struct sect dline, struct dwarf_cu *cu)
{
    char *name = NULL;
    char *cdir = NULL;

    vector_foreach(die, &cu->dies) {
        if (die.tag != DW_TAG_compile_unit)
            continue;

        vector_foreach(at, &die.attrs) {
            if (at.name == DW_AT_name)
                name = at.val.un.str;
            else if (at.name == DW_AT_comp_dir)
                cdir = at.val.un.str;
        }
    }

    if (!name || !cdir)
        return line_err;

    printf("cdir = %s name = %s\n", cdir, name);

    size_t len;
    struct dwarf_prol prol = line_header_decode(dline.buf, &len);
    uint8_t *buf = dline.buf + len;
    ssize_t rem  = dline.size - len;
    struct dwarf_machine m = {
        .addr = 0,
        .file = 1,
        .line = 1,
    };

    printf("off       = 0x%lx\n", len);
    printf("len       = %ld\n", prol.unit_len);
    printf("op_base   = 0x%x\n", prol.op_base);
    printf("line_base = %d\n", prol.line_base);
    printf("\n");

    size_t buf_backup = (size_t)buf;

    while (rem > 0) {
        struct opcode *op = ops + buf[0];
        size_t sz;

        if (ARRAY_SIZE(ops) <= buf[0] || op->name == NULL)
            error("todo op - 0x%x\n", buf[0]);

        buf++;
        op->handler(&m, buf, &sz);
        sz++;
        printf(" [0x%04lx] %s opcode `%s'; length is - 0x%02lx, next is [0x%04lx]\n",
           (size_t)(len + buf-buf_backup-1),
           op->type, op->name, sz,
           (size_t)(len + buf-buf_backup-1 + sz));
        buf += sz;
        rem -= sz;
    }

    return line_err;
}

struct line
dwarf_addr2line(struct obj *o, size_t addr)
{
    vector_of(struct dwarf_cu) cus = dwarf_cus_decode(o);
    struct sect dline = obj_get_sect_by_name(o, ".debug_line");
    (void) addr;

    if (!dline.name)
        return line_err;

    vector_foreach(cu, &cus) {
        struct line ln = addr2line(dline, &cu);
        if (ln.fn != NULL)
            return ln;
    }

    return line_err;
}

