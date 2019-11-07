#include <assert.h>
#include <ctype.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dbg.h"
#include "dwarf.h"
#include "macro.h"
#include "obj.h"
#include "utils.h"
#include "vector.h"


struct cmd {
    char *str;
    void (*cmd)(vector_of(vector_of(char)) *);
};


void cmd_breakpoint(vector_of(vector_of(char)) *args);
void cmd_breakpoint_symbol(vector_of(vector_of(char)) *args);
void cmd_continue(vector_of(vector_of(char)) *args);
void cmd_delete_breakpoint(vector_of(vector_of(char)) *args);
void cmd_exit(vector_of(vector_of(char)) *args);
void cmd_print_args(vector_of(vector_of(char)) *args);
void cmd_step(vector_of(vector_of(char)) *args);
void cmd_step_inst(vector_of(vector_of(char)) *args);


struct cmd cmds[] = {
#define CMD(str_, cmd_) { .str = str_, .cmd = cmd_ },
    CMD("b",    cmd_breakpoint)
    CMD("bs",   cmd_breakpoint_symbol)
    CMD("c",    cmd_continue)
    CMD("d",    cmd_delete_breakpoint)
    CMD("exit", cmd_exit)
    CMD("p",    cmd_print_args)
    CMD("s",    cmd_step)
    CMD("si",   cmd_step_inst)
#undef CMD
};


struct obj *o;
vector_of(struct dwarf_cu) cus;
struct dbg_process dp;
vector_of(struct symbol) syms;


bool not_quited = true;

size_t
sym_lookup(char *str)
{
    vector_foreach(s, &syms) {
        if (STREQ(s.name, str))
            return s.addr;
    }
    return 0;
}

void
cmd_breakpoint_symbol(vector_of(vector_of(char)) *args)
{
    if (vector_nmemb(args) != 2) {
        //printf(" Too many args\n");
        printf(" Too many args %ld\n", vector_nmemb(args));
        return;
    }

    size_t addr = sym_lookup((*args)[1]);

    if (addr == 0) {
        printf("\tDidn't found symbol `%s'\n", (*args)[1]);
        return;
    }

    printf("\tBreakpoint with number %d at %p\n",
           dbg_add_breakpoint(&dp, addr), addr);
}

void
cmd_breakpoint(vector_of(vector_of(char)) *args)
{
    vector_decl(char, file);
    int i, bp_id;

    if (vector_nmemb(args) != 2) {
        //printf(" Too many args\n");
        printf(" Too many args %ld\n", vector_nmemb(args));
        return;
    }

    for (i = 0; (*args)[1][i] != ':'; i++)
        vector_push(&file, (*args)[1][i]);
    vector_push(&file, '\0');

    struct line ln = {
        .file = file,
        .nu   = atoi((*args)[1] + i + 1),
    };
    size_t addr = dwarf_line2addr(o, cus, &ln);

    bp_id = dbg_add_breakpoint(&dp, addr);
    printf("\tBreakpoint with number %d at %p\n", bp_id, (void *)addr);

    vector_free(&file);
}

void
cmd_continue(vector_of(vector_of(char)) *args)
{
    if (vector_nmemb(args) != 1) {
        printf(" Too many args %ld\n", vector_nmemb(args));
        return;
    }

    printf("\tContinueing...\n");
    dbg_continue(&dp);
}

void
cmd_delete_breakpoint(vector_of(vector_of(char)) *args)
{
    if (vector_nmemb(args) != 2) {
        printf(" Too many args\n");
        return;
    }

    int bp_id = atoi((*args)[1]);

    printf("\tRemoving breakpoint %d\n", bp_id);
    dbg_remove_breakpoint(&dp, bp_id);
}

void
cmd_exit(vector_of(vector_of(char)) *args)
{
    if (vector_nmemb(args) != 2) {
        printf(" Too many args\n");
        return;
    }

    not_quited = false;
    printf("\tBye bye\n");
}

void
cmd_print_args(vector_of(vector_of(char)) *args)
{
    if (vector_nmemb(args) != 1) {
        printf(" Too many args\n");
        return;
    }

    size_t pc      = dbg_getreg_by_name(&dp, DBG_REG_PC);
    size_t ir      = dbg_getw(&dp, pc);
    size_t syscall = dbg_getreg_by_name(&dp, DBG_REG_SYSCALL);
    size_t r1      = dbg_getreg_by_name(&dp, DBG_REG_R1);
    size_t r2      = dbg_getreg_by_name(&dp, DBG_REG_R2);
    struct line ln = dwarf_addr2line(o, cus, dbg_get_pc(&dp));


    if (ln.file) {
        printf("\t%s:%d at %p\n", ln.file, ln.nu,
               (void *)dbg_getreg_by_name(&dp, DBG_REG_PC));
    } else {
        printf("\t????:XX at %p\n", (void *)dbg_getreg_by_name(&dp, DBG_REG_PC));
    }

    printf("\tpc: %lx [pc]: %016lx orig_rax: %016lx rax: %016lx rbx: %016lx\n",
           pc, ir, syscall, r1, r2);
    fflush(stdout);
}

void
print_source_line(struct line *ln)
{
    char buf[BUFSIZ];
    FILE *fp;

    snprintf(buf, BUFSIZ, "%s/%s", ln->dir, ln->file);

    if ((fp = fopen(buf, "r")) == NULL)
        return;

    for (int i = 1; i <= ln->nu; i++) {
        char *b = NULL;
        size_t len = 0;

        if (getline(&b, &len, fp) == -1) {
            free(b);
            return;
        }

        if (i == ln->nu) {
            printf("File %s\n", buf);
            printf("%d:%s", ln->nu, b);
        }

        free(b);
    }
}

void
cmd_step(vector_of(vector_of(char)) *args)
{
    if (vector_nmemb(args) != 1) {
        printf(" Too many args\n");
        return;
    }

    struct line ln, nln;

    ln = dwarf_addr2line(o, cus, dbg_get_pc(&dp));

    do {
        dbg_singlestep(&dp);
        nln = dwarf_addr2line(o, cus, dbg_get_pc(&dp));
    } while (nln.nu == ln.nu && (nln.file == ln.file || STREQ(nln.file, ln.file)));

    if (nln.file) {
        print_source_line(&ln);
    }
}

void
cmd_step_inst(vector_of(vector_of(char)) *args)
{
    if (vector_nmemb(args) != 1) {
        printf(" Too many args\n");
        return;
    }

    dbg_singlestep(&dp);

    struct line ln = dwarf_addr2line(o, cus, dbg_get_pc(&dp));

    if (ln.file) {
        printf("\t%s:%d at %p\n", ln.file, ln.nu,
               (void *)dbg_getreg_by_name(&dp, DBG_REG_PC));
    } else {
        printf("\t????:XX at %p\n", (void *)dbg_getreg_by_name(&dp, DBG_REG_PC));
    }
}

void
usage(void)
{
    fprintf(stderr, "USAGE:\n"
            "\n"
            "program debugee [debugee-args]\n");
}

uint64_t
parse_addr(char *str)
{
    uint64_t addr = 0;
    int i;

    for (i = 2; str[i] && isxdigit(str[i]); i++) {
        addr *= 16;
        if ('0' <= str[i] && str[i] <= '9')
            addr += str[i] - '0';
        else if ('A' <= str[i] && str[i] <= 'F')
            addr += str[i] - 'A' + 10;
        else// if ('a' <= str[i] && str[i] <= 'f')
            addr += str[i] - 'a' + 10;
    }

    return addr;
}

vector_of(vector_of(char))
parse_args()
{
    vector_decl(vector_of(char), ret);
    char *buf = NULL;
    size_t len = 0;
    int i;

    printf(">> ");

    if (getline(&buf, &len, stdin) == -1) {
        free(buf);
        return NULL;
    }

    i = 0;

    while (buf[i] != '\n') {
        vector_decl(char, word);

        while (isspace(buf[i]))
            i++;

        if (buf[i] == '\0')
            break;

        while (!isspace(buf[i])) {
            vector_push(&word, buf[i]);
            i++;
        }
        vector_push(&word, '\0');
        vector_push(&ret, word);
    }

    if (vector_nmemb(&ret) == 0)
        return parse_args();

    return ret;
}

void
debug_file(const char *fn)
{
    if ((o = obj_init(fn)) == NULL)
        error("Not an object\n");

    syms = obj_get_symbols(o);
    cus = dwarf_cus_decode(o);

    while (not_quited) {
        vector_of(vector_of(char)) args = parse_args();
        bool found = false;

        if (vector_nmemb(&args) == 0)
            break;

        for (unsigned i = 0; i < ARRAY_SIZE(cmds); i++) {
            if (STREQ(cmds[i].str, args[0])) {
                cmds[i].cmd(&args);
                found = true;
                break;
            }
        }

        if (!found)
            printf("Didn't found command `%s'\n", args[0]);

        for (unsigned i = 0; i < vector_nmemb(&args); i++)
            vector_free(&args[i]);
        vector_free(&args);

        switch (dp.st.type) {
        case DBG_STATE_BREAK:
            printf("\tAt breakpoint!\n");
            break;
        case DBG_STATE_EXIT:
            not_quited = false;
            printf("\tExit with code %d!\n", dp.st.un.code);
            break;
        case DBG_STATE_STOP:
            not_quited = false;
            printf("\tStoped with signal %d!\n", dp.st.un.sig);
            break;
        case DBG_STATE_TERM:
            not_quited = false;
            printf("\tExited from signal %d!\n", dp.st.un.sig);
            break;
        default: { }
        }
    }

    dwarf_cus_free(cus);
    obj_deinit(o);
    dbg_deinit(&dp);
    vector_free(&syms);
}

int
main(int argc, const char *argv[])
{
    if (argc < 2) {
        usage();
        exit(1);
    }

    argv++;
    dp = dbg_openfile(argv);
    debug_file(argv[0]);

    return 0;
}

