# this file is part of libwaive.
#
# Copyright (c) 2015 Dima Krasner
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

CC ?= cc
AR ?= ar
CFLAGS ?= -O2 -pipe
LIBS ?=
LDFLAGS ?= -Wl,-s

DESTDIR ?=
PREFIX ?= /
LIB_DIR ?= $(PREFIX)lib
MAN_DIR ?= $(PREFIX)share/man
DOC_DIR ?= $(PREFIX)share/doc
INCLUDE_DIR ?= $(PREFIX)include

CFLAGS += -Wall -pedantic
LDFLAGS += -shared -pthread

LIBSECCOMP_CFLAGS = $(shell pkg-config --cflags libseccomp)
LIBSECCOMP_LDFLAGS = $(shell pkg-config --libs libseccomp)

INSTALL = install -v

all: libwaive.a libwaive.pc

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS) $(LIBSECCOMP_CFLAGS)

libwaive.a: waive.o
	$(AR) rcs $@ $^

libwaive.pc: libwaive.pc.in
	sed -e s~@PREFIX@~$(PREFIX)~g \
	    -e s~@LIB_DIR@~$(LIB_DIR)~g \
	    -e s~@INCLUDE_DIR@~$(INCLUDE_DIR)~g \
	    $^ > $@

install: all
	$(INSTALL) -D -m 755 libwaive.a $(DESTDIR)/$(LIB_DIR)/libwaive.a
	$(INSTALL) -D -m 755 libwaive.pc $(DESTDIR)/$(LIB_DIR)/pkgconfig/libwaive.pc
	$(INSTALL) -D -m 755 waive.h $(DESTDIR)/$(INCLUDE_DIR)/waive.h
	$(INSTALL) -D -m 644 README $(DESTDIR)/$(DOC_DIR)/libwaive/README
	$(INSTALL) -m 644 AUTHORS $(DESTDIR)/$(DOC_DIR)/libwaive/AUTHORS
	$(INSTALL) -m 644 COPYING $(DESTDIR)/$(DOC_DIR)/libwaive/COPYING

clean:
	rm -f libwaive.a waive.o libwaive.pc
