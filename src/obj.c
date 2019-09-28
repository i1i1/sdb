#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>

#include "macro.h"
#include "utils.h"
#include "elf64.h"
#include "obj.h"


struct obj_interface {
    bool (*is_this)(const struct obj *);
    size_t (*get_start)(const struct obj *);
    size_t (*get_sect_num)(const struct obj *);
    struct sect (*get_sect)(const struct obj *, size_t);
};

#define OBJ_INT(IS_THIS, GET_START, GET_SECT_N, GET_SECT) \
    {                                 \
        .is_this      = (IS_THIS),    \
        .get_start    = (GET_START),  \
        .get_sect_num = (GET_SECT_N), \
        .get_sect     = (GET_SECT),   \
    },
struct obj_interface obj_ints[] = {
    OBJ_INT(elf64_is_this, elf64_get_start, elf64_sect_num, elf64_get_sect)
};
#undef OBJ_INT


static size_t
file_len(FILE *fp)
{
    size_t sz;

    fseek(fp, 0L, SEEK_END);
    sz = ftell(fp);
    rewind(fp);
    return sz;
}

static struct obj *
file_init(const char *fn)
{
    struct obj *ret = malloc(sizeof(*ret));
    FILE *fp;

    if ((fp = fopen(fn, "r")) == NULL)
        goto err1;

    ret->sz = file_len(fp);
    ret->fb = xmalloc(ret->sz);

    if (fread(ret->fb, 1, ret->sz, fp) != ret->sz)
        goto err2;

    fclose(fp);
    return ret;

err2:
    fclose(fp);
err1:
    free(ret);
    return NULL;
}

struct obj *
obj_init(const char *fn)
{
    struct obj *o = file_init(fn);

    if (!o)
        return NULL;

    for (int i = 0; i < (int)ARRAY_SIZE(obj_ints); i++) {
        if (obj_ints[i].is_this(o)) {
            o->idx = i;
            return o;
        }
    }

    obj_deinit(o);
    return NULL;
}

size_t
obj_get_start(const struct obj *o)
{
    return obj_ints[o->idx].get_start(o);
}

size_t
obj_get_sect_num(const struct obj *o)
{
    return obj_ints[o->idx].get_sect_num(o);
}

struct sect
obj_get_sect(const struct obj *o, size_t n)
{
    return obj_ints[o->idx].get_sect(o, n);
}

void
obj_deinit(struct obj *o)
{
    free(o->fb);
    free(o);
}

struct sect
obj_get_sect_by_name(const struct obj *o, char *nm)
{
    int n = obj_get_sect_num(o);
    for (int i = 0; i < n; i++) {
        struct sect s = obj_get_sect(o, i);
        if (STREQ(s.name, nm))
            return s;
    }
    return (struct sect) {
        .name = NULL,
    };
}

