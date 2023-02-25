EXE = ../build-recorder

TEST_CASES = \
	compile_single_file \
	compile_link_file \
	compile_file_include \
	compile_file_sysinclude \
	compile_two_files \
	$(EMPTY)

all: $(TEST_CASES)

compile_single_file: f1.c
	$(EXE) -o $@.out gcc -c $^

compile_link_file: f1.c
	$(EXE) -o $@.out gcc $^

compile_file_include: f2.c
	$(EXE) -o $@.out gcc -c $^

compile_file_sysinclude: f3.c
	$(EXE) -o $@.out gcc -c $^

compile_two_files: f4.c f5.c
	$(EXE) -o $@.out gcc $^


clean:
	$(RM) *.o a.out

clobber: clean
	$(RM) *.out

