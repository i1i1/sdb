#ifndef _OBJ_H_
#define _OBJ_H_

#include <stdlib.h>
#include <stdint.h>


struct obj {
    size_t idx;
    uint8_t *fb;
    size_t sz;
};

struct sect {
    char *name;
    uint8_t *addr;
    size_t size;
};


struct obj *obj_init(const char *fn);

void obj_deinit(struct obj *o);

size_t obj_get_start(const struct obj *o);

size_t obj_get_sect_num(const struct obj *o);

struct sect obj_get_sect(const struct obj *o, size_t n);

struct sect obj_get_sect_by_name(const struct obj *o, char *nm);

#endif /* _OBJ_H_ */

