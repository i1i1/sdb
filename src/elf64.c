#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <elf.h>

#include "obj.h"
#include "elf64.h"
#include "macro.h"


bool
elf64_is_this(const struct obj *o)
{
    Elf64_Ehdr *eh = (Elf64_Ehdr *)o->fb;
    char elf_magic[] = "_ELF";
    elf_magic[0] = 0x7f;

    return strncmp(elf_magic, (char *)eh->e_ident, 4) == 0;
}

size_t
elf64_get_start(const struct obj *o)
{
    Elf64_Ehdr *eh = (Elf64_Ehdr *)o->fb;
    return eh->e_entry;
}

size_t
elf64_sect_num(const struct obj *o)
{
    Elf64_Ehdr *eh = (Elf64_Ehdr *)o->fb;
    return eh->e_shnum;
}

static char *
elf64_getstr(const struct obj *o, uint32_t str)
{
    Elf64_Ehdr *eh = (Elf64_Ehdr *)o->fb;
    Elf64_Shdr *sh = (Elf64_Shdr *)(o->fb + eh->e_shoff);
    Elf64_Shdr *strh = &sh[eh->e_shstrndx];
    char *secstrs = (char *)o->fb + strh->sh_offset;

    return secstrs + str;
}

struct sect
elf64_get_sect(const struct obj *o, size_t n)
{
    Elf64_Ehdr *eh = (Elf64_Ehdr *)o->fb;
    Elf64_Shdr *sh = (Elf64_Shdr *)(o->fb + eh->e_shoff);

    return (struct sect) {
        .name = elf64_getstr(o, sh[n].sh_name),
        .buf  = o->fb + sh[n].sh_offset,
        .size = sh[n].sh_size,
    };
}

