# Common Makefile parts for BPF-building with libbpf
# --------------------------------------------------
# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
# SPDX-FileCopyrightText: ©  2019 Toke Høiland-Jørgensen <https://github.com/tohojo> and XDP-Project contrinbutors */
#
# This file should be included from your Makefile like:
#  COMMON_DIR = ../common
#  include $(COMMON_DIR)/common.mk
#
# It is expected that you define the variable:
# USER_TARGETS XDP_TARGETS
# as a space-separated list
#
LLC ?= llc
CLANG ?= clang
CC ?= gcc
GO ?= go 
XDP_C = ${XDP_TARGETS:=.c}
XDP_OBJ := ${XDP_C:.c=_bpfel.o}
XDP_OBJ += ${XDP_C:.c=_bpfeb.o}
XDP_OBJ += ${XDP_C:.c=_bpfeb.go}
XDP_OBJ += ${XDP_C:.c=_bpfel.go}

USER_GO := ${USER_TARGETS:=main.go}
USER_OBJ := ${USER_GO:.c=.o}
BPF2GO_CFLAGS:= -D __BPF_TRACING__ $(BPF_CFLAGS) -Wall -Wno-unused-value \
             -Wno-pointer-sign -Wno-compare-distinct-pointer-types -Werror \
             -O2 -g

# Expect this is defined by including Makefile, but define if not
HEADER_DIR ?= ../headers
LIB_DIR ?= ../lib

include $(LIB_DIR)/defines.mk


CFLAGS += -I$(LIB_DIR)/install/include $(EXTRA_CFLAGS)
BPF_CFLAGS += -I$(LIB_DIR)/install/include $(EXTRA_CFLAGS)
LDFLAGS += -L$(LIB_DIR)/install/lib


all: llvm-check $(USER_TARGETS) 

.PHONY: clean $(CLANG) $(LLC)

clean:
	rm -f $(USER_TARGETS) $(XDP_OBJ)

llvm-check: $(CLANG) $(LLC)
	@for TOOL in $^ ; do \
		if [ ! $$(command -v $${TOOL} 2>/dev/null) ]; then \
			echo "*** ERROR: Cannot find tool $${TOOL}" ;\
			exit 1; \
		else true; fi; \
	done
	@echo $(XDP_OBJ)

$(OBJECT_LIBBPF):
	@if [ ! -d $(LIBBPF_DIR) ]; then \
		echo "Error: Need libbpf submodule" $(LIBBPF_DIR); \
		echo "May need to run git submodule update --init"; \
		exit 1; \
	else \
		cd $(LIBBPF_DIR) && $(MAKE) all OBJDIR=.; \
		mkdir -p build; $(MAKE) install_headers DESTDIR=build OBJDIR=.; \
	fi


$(USER_TARGETS): %: %.go
	BPF2GO_FLAGS="-target bpf -no-strip" BPF2GO_CFLAGS="$(BPF2GO_CFLAGS)" go generate
	go build -o $@
