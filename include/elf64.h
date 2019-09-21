#ifndef _ELF64_H_
#define _ELF64_H_

#include <stdlib.h>
#include <stdbool.h>

#include "obj.h"

bool elf64_is_this(const struct obj *o);
size_t elf64_get_start(const struct obj *o);
size_t elf64_sect_num(const struct obj *o);
struct sect elf64_get_sect(const struct obj *o, size_t n);

#endif /* _ELF64_H_ */
