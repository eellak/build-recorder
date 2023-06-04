
# Copyright (C) 2023 Alexios Zavras
# Copyright (c) 2023 Fotios Valasiadis
# SPDX-License-Identifier: LGPL-2.1-or-later

EXE = ../build-recorder

TEST_CASES = \
	compile_single_file \
	compile_link_file \
	compile_file_include \
	compile_file_sysinclude \
	compile_two_files

.PHONY: all clean clobber

all: $(TEST_CASES)

compile_single_file: f1.c
	$(EXE) -o $@.out $(CC) -c $^

compile_link_file: f1.c
	$(EXE) -o $@.out $(CC) $^

compile_file_include: f2.c
	$(EXE) -o $@.out $(CC) -c $^

compile_file_sysinclude: f3.c
	$(EXE) -o $@.out $(CC) -c $^

compile_two_files: f4.c f5.c
	$(EXE) -o $@.out $(CC) $^

$(EXE):
	$(MAKE) -C ..

clean:
	$(RM) *.o a.out

clobber: clean
	$(RM) *.out
