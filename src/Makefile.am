# Copyright (C) 2023 Alexios Zavras
# Copyright (C) 2023 Fotios Valasiadis
# SPDX-License-Identifier: LGPL-2.1-or-later

bin_PROGRAMS = build-recorder

build_recorder_SOURCES = \
	hash.c \
	main.c \
	schema.h \
	record.c \
	tracer.c \
	$(EMPTY)

SCHEMA = ../doc/build-recorder-schema.ttl

record.c: schema.h

if HAVE_XXD
schema.h: $(SCHEMA)
	sed '/^#/d' $^ | $(XXD) -i > $@
endif
