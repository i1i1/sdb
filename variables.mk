ARCH := amd64

CC := gcc
CFLAGS := -Wall -Wextra -gdwarf-2 -gstrict-dwarf -Iinclude \
		-Iarch/$(ARCH)/include -O100500

SRC := $(shell find arch/$(ARCH)/src     src     -name "*.c")
HDR := $(shell find arch/$(ARCH)/include include -name "*.h")
OUT := sdb

JOBS:=8

default: debugee all

debugee: debugee.c
	@printf "%-5s %s\n" LD debugee
	@$(CC) $(CFLAGS) -o debugee debugee.c

test: debugee
	./$(OUT) ./$(OUT)

$(SRC): untabify

untabify:
	@echo UNTABIFY
	@awk '/\t/ || /[ \t]+$$/ {printf("%s:%d:%s\n", FILENAME, FNR, $$0); a=1} END{exit(a)}' $(SRC) $(HDR)

userclean:
	rm -f debugee


.PHONY: test default

