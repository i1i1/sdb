VARS  := $(shell pwd)/variables.mk
GENER := ./gener.sh
MK     = $(BUILD)/generated.mk
LIST   = $(BUILD)/.list

BUILD ?= build


all: gener_mk
	@make -f $(MK) -j$(JOBS) BUILD=$(BUILD)

gener_mk: mk_list $(MK)

-include $(VARS)

$(MK): $(VARS) Makefile $(LIST) $(GENER)
	@printf "%-5s %s\n" REGEN $(MK)
	@BUILD=$(BUILD) VARS=$(VARS) $(GENER) $(SRC) > $(MK)

mk_list:
	@mkdir -p $(shell dirname $(LIST))
	@if [ "$$(cat $(LIST) 2>/dev/null || echo -n)" != "$(SRC) $(HDR)"  ]; then \
		echo "$(SRC) $(HDR)" >$(LIST);\
	fi

fullclean: clean
	rm -f $(MK)
	rm -f $(LIST)

clean: userclean
	rm -rf $(BUILD)
	rm -f  $(OUT)

%:
	@make -f $(MK) -j$(JOBS) BUILD=$(BUILD) $(MAKECMDGOALS)


.PHONY: all gener_mk fullclean mk_list userclean

