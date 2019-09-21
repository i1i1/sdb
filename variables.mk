CC := gcc
CFLAGS := -Wall -Wextra -gdwarf-2 -Iinclude -O3

SRC := $(shell find src -name "*.c")
HDR := $(shell find include -name "*.h")
OUT := sdb

JOBS:=8

default: debugee all

debugee: debugee.c
	@printf "%-5s %s\n" LD debugee
	@$(CC) $(CFLAGS) -o debugee debugee.c

test: debugee
	./$(OUT) ./debugee

$(SRC): untabify

untabify:
	@echo UNTABIFY
	@awk '/\t/ {printf("%s:%d:%s\n", FILENAME, FNR, $$0); a=1} END{exit(a)}' $(SRC) $(HDR)

userclean:
	rm -f debugee


.PHONY: test default

