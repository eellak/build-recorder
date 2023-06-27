# Copyright (C) 2023 Alexios Zavras
# SPDX-License-Identifier: LGPL-2.1-or-later

EXE = ../build-recorder

DL_URL = https://ftp.gnu.org/gnu/hello/hello-2.12.1.tar.gz
LOCAL_FILE = $(lastword $(subst /, ,$(DL_URL)))
LOCAL_DIR = $(LOCAL_FILE:.tar.gz=)
BENCHNAME = $(LOCAL_DIR)
BENCHOUT = bench-$(BENCHNAME).out

if !HAVE_DOWNLOAD
$(error Neither "curl" nor "wget" were found in the PATH.)
endif

if !HAVE_TIME
$(error Did not find "time" in the PATH.)
endif


all: $(BENCHOUT)

$(LOCAL_FILE):
	$(DOWNLOAD) $(DL_URL)

$(LOCAL_DIR): $(LOCAL_FILE)
	tar -xf $(LOCAL_FILE)

$(LOCAL_DIR)/config.h: $(LOCAL_DIR)
	cd $(LOCAL_DIR) && ./configure

$(BENCHOUT): $(LOCAL_DIR)/config.h
	cd $(LOCAL_DIR) && make clean
	cd $(LOCAL_DIR) && $(TIME) make
	cd $(LOCAL_DIR) && make clean
	cd $(LOCAL_DIR) && $(TIME) ../$(EXE) make

compile_single_file: f1.c
	$(EXE) -o $@.out $(CC) -c $^


clean:
	$(RM) *.o a.out
	$(RM) $(LOCAL_FILE)

clobber: clean
	$(RM) *.out
	$(RM) -r $(LOCAL_DIR)

