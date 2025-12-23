# Copyright 2024 Contributors to the Parsec project.
# SPDX-License-Identifier: Apache-2.0
#
# Makefile for building the mock PKCS#11 library

CC ?= gcc
CFLAGS = -fPIC -shared -fvisibility=hidden -Wall -Wextra -Werror
PKCS11_INCLUDE = ../../../cryptoki-sys/vendor

# Platform-specific settings
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
    TARGET = libmockpkcs11.dylib
    CFLAGS += -dynamiclib
else
    TARGET = libmockpkcs11.so
endif

.PHONY: all clean

all: $(TARGET)

$(TARGET): mock_pkcs11.c
	$(CC) $(CFLAGS) -I$(PKCS11_INCLUDE) -o $@ $<

clean:
	rm -f $(TARGET) libmockpkcs11.so libmockpkcs11.dylib
