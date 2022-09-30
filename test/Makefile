EXE = ../build-recorder

TEST_CASES = \
	compile_single_file \
	compile_link_file \
	complie_file_include \
	complie_file_sysinclude \
	compile_two_files \
	$(EMPTY)

all: $(TEST_CASES)

compile_single_file: f1.c
	$(EXE) -o $@.out gcc -c $^

compile_link_file: f1.c
	$(EXE) -o $@.out gcc $^

complie_file_include: f2.c
	$(EXE) -o $@.out gcc -c $^

complie_file_sysinclude: f3.c
	$(EXE) -o $@.out gcc -c $^

compile_two_files: f4.c f5.c
	$(EXE) -o $@.out gcc $^


clean:
	%(RM) *.o a.out

