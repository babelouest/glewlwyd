#
# Glewlwyd user backend
#
# Makefile used to build the software
#
# Copyright 2018 Nicolas Mora <mail@babelouest.org>
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

LOCAL=/usr/local
MODULES_TARGET=$(LOCAL)/lib/glewlwyd/user
CC=gcc
CFLAGS=-c -fPIC -Wall -Wno-unknown-pragmas -D_REENTRANT -shared -nostartfiles -Wno-pragmas $(ADDITIONALFLAGS)
LIBS=-lc -ldl -ljansson -lorcania -lyder -lulfius
LDFLAGS += -Wl,-R '-Wl,-R$$ORIGIN'

all: release

%.o: %.c ../glewlwyd.h
	$(CC) $(CFLAGS) $(CPPFLAGS) $<

libmodmock.so: mock.o
	$(CC) -shared -Wl,-soname,libmodmock.so mock.o -o libmodmock.so $(LIBS)

clean:
	rm -f *.o *.so

debug: ADDITIONALFLAGS=-DDEBUG -g -O0

debug: libmodmock.so

release: ADDITIONALFLAGS=-O3

release:

install:
	mkdir -p $(MODULES_TARGET)
	cp -f *.so $(MODULES_TARGET)
