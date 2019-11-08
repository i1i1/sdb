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
void op_copy(struct dwarf_machine *m, uint8_t *buf, size_t *size);
void op_advance_pc(struct dwarf_machine *m, uint8_t *buf, size_t *size);
void op_advance_line(struct dwarf_machine *m, uint8_t *buf, size_t *size);
void op_set_file(struct dwarf_machine *m, uint8_t *buf, size_t *size);
void op_set_column(struct dwarf_machine *m, uint8_t *buf, size_t *size);
void op_negate_stmt(struct dwarf_machine *m, uint8_t *buf, size_t *size);
void op_const_add_pc(struct dwarf_machine *m, uint8_t *buf, size_t *size);
void op_fixed_advance_pc(struct dwarf_machine *m, uint8_t *buf, size_t *size);

struct opcode {
    char *type;
    char *name;
    void (*handler)(struct dwarf_machine *, uint8_t *, size_t *);
} ops[] = {
    [0x00] = { "extended", "extended",         op_ext              },
    [0x01] = { "standart", "copy",             op_copy             },
    [0x02] = { "standart", "advance_pc",       op_advance_pc       },
    [0x03] = { "standart", "advance_line",     op_advance_line     },
    [0x04] = { "standart", "set_file",         op_set_file         },
    [0x05] = { "standart", "set_column",       op_set_column       },
    [0x06] = { "standart", "negate_stmt",      op_negate_stmt      },
    [0x08] = { "standart", "const_add_pc",     op_const_add_pc     },
    [0x09] = { "standart", "fixed_advance_pc", op_fixed_advance_pc },
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

#define CLASS_REF(sz, type)                                              \
static struct dwarf_obj                                                  \
PASTE(obj_dwarf_class_ref, sz)(uint8_t *die, struct obj *o, size_t *len) \
{                                                                        \
    (void) o;                                                            \
    *len = sz;                                                           \
    return (struct dwarf_obj) {                                          \
        .class  = dwarf_class_ref,                                       \
        .un.ref = *(type *)die,                                          \
    };                                                                   \
}

#define CLASS_DATA(sz, nm, val)                                           \
static struct dwarf_obj                                                   \
PASTE(obj_dwarf_class_data, nm)(uint8_t *die, struct obj *o, size_t *len) \
{                                                                         \
    (void) o;                                                             \
    *len = sz;                                                            \
    return (struct dwarf_obj) {                                           \
        .class     = dwarf_class_const,                                   \
        .un.const_ = val,                                                 \
    };                                                                    \
}

CLASS_DATA(1,            1,     *(uint8_t *)die)
CLASS_DATA(2,            2,     *(uint16_t *)die)
CLASS_DATA(4,            4,     *(uint32_t *)die)
CLASS_DATA(8,            8,     *(uint64_t *)die)
CLASS_DATA(leb_len(die), _uleb, uleb_decode(die))
CLASS_DATA(leb_len(die), _sleb, sleb_decode(die))

CLASS_REF(1, uint8_t)
CLASS_REF(2, uint16_t)
CLASS_REF(4, uint32_t)
CLASS_REF(8, uint64_t)

static struct dwarf_obj
obj_dwarf_class_block1(uint8_t *die, struct obj *o, size_t *len)
{
    (void) o;
    *len = 1 + *die;
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
    DW_FORM(sdata,       0x0d, obj_dwarf_class_data_sleb, dwarf_class_const)
    DW_FORM(strp,        0x0e, obj_dwarf_class_strp, dwarf_class_str)
    DW_FORM(udata,       0x0f, obj_dwarf_class_data_uleb, dwarf_class_const)
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

void
dwarf_abbrevtbl_free(struct dwarf_abbrev *atbl)
{
    vector_foreach(a, &atbl->children) {
        dwarf_abbrevtbl_free(&a);
    }
    vector_free(&atbl->children);
    vector_free(&atbl->attrs);
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
//    uint8_t *die_orig = buf - 0xb;
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

            if (forms[a.form].obj == NULL) {
                printf("Form todo %02lx\n", a.form);
                todo();
            }

//            printf(" <%lx> form %s %s\n", die - die_orig, dwarf_form_lookup(a.form), dwarf_attrib_lookup(a.name));
//            fflush(stdout);
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

    dwarf_abbrevtbl_free(&atbl);

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

    BUF_READ(buf, ret.min_inst_len,    uint8_t);
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
op_const_add_pc(struct dwarf_machine *m, uint8_t *buf, size_t *size)
{
    (void) buf;
    uint8_t op = 255;
    int adj_op = op - m->prol->op_base;
    int addr_inc = (adj_op / m->prol->line_range) * m->prol->min_inst_len;

    m->addr += addr_inc * m->prol->min_inst_len;
    *size = 0;
}

void
op_ext(struct dwarf_machine *m, uint8_t *buf, size_t *size)
{
    enum DW_LNE {
        end_sequence       = 0x01,
        set_address        = 0x02,
        define_file        = 0x03,
        set_discriminator  = 0x04,
    };
    size_t sz_len = leb_len(buf);
    uintmax_t sz = uleb_decode(buf);

    *size = sz + sz_len;
    buf += sz_len;

    switch (*buf++) {
    case end_sequence:
//        printf("\tend of sequence\n");
        *m = (struct dwarf_machine) {
            .addr     = 0,
            .file     = 1,
            .line     = 1,
            .op_idx   = 0,
            .is_ended = true,
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
        printf("todo define file\n");
        todo();
        break;
    case set_discriminator:
        break;
    default:
        error("Unknown extended opcode - %d\n", buf[-1]);
    }
}

void
op_advance_line(struct dwarf_machine *m, uint8_t *buf, size_t *size)
{
    *size = leb_len(buf);
    m->line += sleb_decode(buf);
}

void
op_set_file(struct dwarf_machine *m, uint8_t *buf, size_t *size)
{
    *size = leb_len(buf);
    m->file = uleb_decode(buf);
}

void
op_set_column(struct dwarf_machine *m, uint8_t *buf, size_t *size)
{
    (void) m;
    *size = leb_len(buf);
    /*
     * Do nothing. Skipping 1 argument.
     */
}

void
op_copy(struct dwarf_machine *m, uint8_t *buf, size_t *size)
{
    (void) m;
    (void) buf;
    *size = 0;
}

void
op_advance_pc(struct dwarf_machine *m, uint8_t *buf, size_t *size)
{
    *size = leb_len(buf);
    m->addr += uleb_decode(buf);
}

void
op_fixed_advance_pc(struct dwarf_machine *m, uint8_t *buf, size_t *size)
{
    *size = 2;
    m->addr += *(uint16_t *)buf;
}

void
op_negate_stmt(struct dwarf_machine *m, uint8_t *buf, size_t *size)
{
    (void) m;
    (void) buf;
    *size = 0;
}

void
op_special(struct dwarf_machine *m, uint8_t op)
{
    int adj_op = op - m->prol->op_base;
    int addr_inc = (adj_op / m->prol->line_range) * m->prol->min_inst_len;
    int line_inc = m->prol->line_base + (adj_op % m->prol->line_range);

    m->addr += addr_inc;
    m->line += line_inc;
}


void
dwarf_prol_free(struct dwarf_prol *p)
{
    vector_free(&p->std_op_lens);
    vector_free(&p->inc_dirs);
    vector_free(&p->fnames);
}

struct line line_err = { NULL, NULL, -1 };

size_t
line2addr(struct line *ln, struct sect dline, struct dwarf_cu *cu)
{
    char *name = NULL;
    char *cdir = NULL;
    size_t dline_off = 0;

    vector_foreach(die, &cu->dies) {
        if (die.tag != DW_TAG_compile_unit)
            continue;

        vector_foreach(at, &die.attrs) {
            if (at.name == DW_AT_name)
                name = at.val.un.str;
            else if (at.name == DW_AT_comp_dir)
                cdir = at.val.un.str;
            else if (at.name == DW_AT_stmt_list)
                dline_off = at.val.un.addr;
        }
    }

    if (!name || !cdir || !STREQ(ln->file, name))
        return 0;

    size_t len;
    struct dwarf_prol prol = line_header_decode(dline.buf + dline_off, &len);
//    uint8_t *buf_orig = dline.buf;
    uint8_t *buf = dline.buf + dline_off + len;
    struct dwarf_machine m = {
        .addr     = 0,
        .file     = 1,
        .line     = 1,
        .op_idx   = 0,
        .prol     = &prol,
        .is_ended = false,
    };

    while (!m.is_ended) {
        size_t idx = buf[0];
        struct opcode *op = &ops[idx];
        size_t sz;
        struct dwarf_machine new = m;

        if (idx < prol.op_base && op->name == NULL)
            error("todo op - 0x%x\n", buf[0]);

        if (idx < prol.op_base) {
            op->handler(&new, buf + 1, &sz);
        } else {
            op_special(&new, idx);
            sz = 0;
        }

        sz++;
//        printf(" <%lx>", buf - buf_orig);
//        printf("%s/%s:%6d -- %p op %x\n", cdir ? cdir : "(null)", name ? name : "(null)", new.line, (void *)new.addr, idx);
//        fflush(stdout);

        if (new.line == ln->nu) {
            dwarf_prol_free(&prol);
            return new.addr;
        }

        m = new;
        buf += sz;
    }

//    printf("End\n");
    dwarf_prol_free(&prol);

    return 0;
}


struct line
addr2line(size_t addr, struct sect dline, struct dwarf_cu *cu)
{
    char *name = NULL;
    char *cdir = NULL;
    size_t dline_off = 0;

    vector_foreach(die, &cu->dies) {
        if (die.tag != DW_TAG_compile_unit)
            continue;

        vector_foreach(at, &die.attrs) {
            if (at.name == DW_AT_name)
                name = at.val.un.str;
            else if (at.name == DW_AT_comp_dir)
                cdir = at.val.un.str;
            else if (at.name == DW_AT_stmt_list)
                dline_off = at.val.un.addr;
        }
    }

    if (!name || !cdir)
        return line_err;

    size_t len;
    struct dwarf_prol prol = line_header_decode(dline.buf + dline_off, &len);
//    uint8_t *buf_orig = dline.buf;
    uint8_t *buf = dline.buf + dline_off + len;
    struct dwarf_machine m = {
        .addr     = 0,
        .file     = 1,
        .line     = 1,
        .op_idx   = 0,
        .prol     = &prol,
        .is_ended = false,
    };
    int first = 0;

    while (!m.is_ended) {
        size_t idx = buf[0];
        struct opcode *op = &ops[idx];
        size_t sz;
        struct dwarf_machine new = m;

        if (idx < prol.op_base && op->name == NULL)
            error("todo op - 0x%x\n", buf[0]);

        if (idx < prol.op_base) {
            op->handler(&new, buf + 1, &sz);
        } else {
            op_special(&new, idx);
            sz = 0;
        }

        sz++;
//        printf(" <%lx> ", buf - buf_orig);
//        printf("%s/%s:%6d -- %p op %x\n", cdir ? cdir : "(null)", name ? name : "(null)", new.line, (void *)new.addr, idx);
//        fflush(stdout);

        if (m.addr <= addr && addr < new.addr && first) {
            dwarf_prol_free(&prol);
            return (struct line) {
                .dir  = cdir,
                .file = name,
                .nu   = m.line,
            };
        }

        m = new;
        buf += sz;
        first = 1;
    }

    dwarf_prol_free(&prol);
//    printf("\tline_err\n");

    return line_err;
}

size_t
dwarf_line2addr(struct obj *o, vector_of(struct dwarf_cu) cus, struct line *ln)
{
    struct sect dline = obj_get_sect_by_name(o, ".debug_line");

    if (!dline.name)
        return 0;

    vector_foreach(cu, &cus) {
        size_t addr = line2addr(ln, dline, &cu);
        if (addr != 0)
            return addr;
    }

    return 0;
}

struct line
dwarf_addr2line(struct obj *o, vector_of(struct dwarf_cu) cus, size_t addr)
{
    struct sect dline = obj_get_sect_by_name(o, ".debug_line");

    if (!dline.name)
        return line_err;

    vector_foreach(cu, &cus) {
        struct line ln = addr2line(addr, dline, &cu);
        if (ln.file != NULL)
            return ln;
    }

    return line_err;
}

void
dwarf_cus_free(vector_of(struct dwarf_cu) cus)
{
    vector_foreach(cu, &cus) {
        vector_foreach(die, &cu.dies) {
            vector_free(&die.attrs);
        }
        vector_free(&cu.dies);
    }
    vector_free(&cus);
}

