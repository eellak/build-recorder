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
	threadpool.c \
	$(EMPTY)

SCHEMA = ../doc/build-recorder-schema.ttl


if HAVE_XXD
schema.c: $(SCHEMA)
	sed '/^#/d' $^ | $(XXD) -i -n schema > $@
endif
