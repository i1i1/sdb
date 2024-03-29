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

vector_of(struct symbol)
elf64_get_symbols(const struct obj *o)
{
    struct sect symtab = obj_get_sect_by_name(o, ".symtab");
    struct sect strtab = obj_get_sect_by_name(o, ".strtab");
    vector_decl(struct symbol, ret);

    while (symtab.size > 0) {
        Elf64_Sym *sym = (void *)symtab.buf;
        struct symbol s = {
            .name = (char *)strtab.buf + sym->st_name,
            .addr = sym->st_value,
        };

        if (sym->st_name)
            vector_push(&ret, s);

        symtab.buf += sizeof(Elf64_Sym);
        symtab.size -= sizeof(Elf64_Sym);
    }

    return ret;
}

