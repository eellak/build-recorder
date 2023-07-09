# Copyright (C) 2023 Alexios Zavras
# Copyright (C) 2023 Fotios Valasiadis
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
else
TIMER = $(TIME) -f "Real:%e\nSys:%S\nUser:%U\nCPU utilization:%P\nMaximum resident set size (kbytes):%M\nAverage resident set size (kbytes):%t\nAverage memory usage (kbytes):%K\nMajor page faults:%F\nMinor page faults:%R\nInvoluntarily context switches caused by memory:%W\nInvoluntarily context switches caused by time slice expirations:%c\nVoluntarily context switches:%w\nAverage unshared data area (kbytes):%D\nAverage unshared stack area (kbytes):%p\nAverage shared text space (kbytes):%X\nSystem's page size (bytes):%Z\nFilesystem inputs:%I\nFilesystem outputs:%O\nSocket messages received:%r\nSocket messages sent:%s\nSignals delivered to the process:%k"
endif

if !HAVE_AWK
$(error Did not find "awk" in the PATH.)
endif

all:

benchmark: $(BENCHOUT)

$(LOCAL_FILE):
	$(DOWNLOAD) $(DL_URL)

$(LOCAL_DIR): $(LOCAL_FILE)
	tar -xf $(LOCAL_FILE)

$(LOCAL_DIR)/config.h: $(LOCAL_DIR)
	cd $(LOCAL_DIR) && ./configure

$(BENCHOUT): $(LOCAL_DIR)/config.h
	cd $(LOCAL_DIR) && make clean
	cd $(LOCAL_DIR) && $(TIMER) -o baseline.times make
	cd $(LOCAL_DIR) && make clean
	cd $(LOCAL_DIR) && $(TIMER) -o build-recorder.times ../$(EXE) make
	$(AWK) -f benchmark.awk $(LOCAL_DIR)/build-recorder.times $(LOCAL_DIR)/baseline.times > $(BENCHOUT)

compile_single_file: f1.c
	$(EXE) -o $@.out $(CC) -c $^


clean:
	$(RM) *.o a.out
	$(RM) $(LOCAL_FILE)

clobber: clean
	$(RM) *.out
	$(RM) -r $(LOCAL_DIR)
	$(RM) $(BENCHOUT)

