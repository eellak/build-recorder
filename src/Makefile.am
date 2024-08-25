# Copyright (C) 2023 Alexios Zavras
# Copyright (C) 2023 Fotios Valasiadis
# SPDX-License-Identifier: LGPL-2.1-or-later

bin_PROGRAMS = build-recorder

build_recorder_SOURCES = \
	hash.c \
	main.c \
	record.c \
	schema.c \
	tracer.c \
	$(EMPTY)

dist_noinst_HEADERS = *.h

SCHEMA = ../doc/build-recorder-schema.ttl

dist_data_DATA = $(SCHEMA)

record.c: schema.c

if HAVE_XXD
schema.c: $(SCHEMA)
	sed '/^#/d' $^ | $(XXD) -i -n schema > $@
endif
