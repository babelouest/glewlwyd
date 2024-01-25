#
# Glewlwyd user backend
#
# Makefile used to build the software
#
# Copyright 2016-2021 Nicolas Mora <mail@babelouest.org>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public License
# as published by the Free Software Foundation;
# version 2.1 of the License.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	See the
# GNU GENERAL PUBLIC LICENSE for more details.
#
# You should have received a copy of the GNU General Public
# License along with this library.	If not, see <http://www.gnu.org/licenses/>.
#

GLWD_SRC=..
DESTDIR=/usr/local
MODULES_TARGET=$(DESTDIR)/lib/glewlwyd/user_middleware
CC=gcc
CFLAGS+=-c -fPIC -Wall -Werror -Wextra -Wconversion -Wno-unknown-pragmas -Wpedantic -D_REENTRANT -Wno-pragmas -I$(GLWD_SRC) $(shell pkg-config --cflags liborcania) $(shell pkg-config --cflags libyder) $(shell pkg-config --cflags jansson) $(shell pkg-config --cflags libhoel) $(ADDITIONALFLAGS)
LIBS=$(shell pkg-config --libs liborcania) $(shell pkg-config --libs libyder) $(shell pkg-config --libs jansson) -ldl
LDFLAGS += -Wl,-R '-Wl,-R$$ORIGIN'
TARGET=
all: release

misc.o: $(GLWD_SRC)/misc.c $(GLWD_SRC)/glewlwyd-common.h
	$(CC) $(CFLAGS) $(CPPFLAGS) $(GLWD_SRC)/misc.c

%.o: %.c $(GLWD_SRC)/glewlwyd.h
	$(CC) $(CFLAGS) $(CPPFLAGS) $<

libmodmock.so: mock.o misc.o
	$(CC) -shared -Wl,-soname,libmodmock.so mock.o misc.o -o libmodmock.so $(LIBS) $(LDFLAGS)

clean:
	rm -f *.o *.so

debug: ADDITIONALFLAGS=-DDEBUG -g -O0

debug: libmodmock.so $(TARGET)

release: ADDITIONALFLAGS=-O3

release: $(TARGET)

install:
	mkdir -p $(MODULES_TARGET)
	cp -f *.so $(MODULES_TARGET)
