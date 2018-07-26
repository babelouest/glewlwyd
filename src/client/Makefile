#
# Glewlwyd client backend
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

PREFIX=/usr/local
MODULES_TARGET=$(PREFIX)/lib/glewlwyd/client
CC=gcc
CFLAGS=-c -fPIC -Wall -Wno-unknown-pragmas -D_REENTRANT -shared -nostartfiles -I$(PREFIX)/include -Wno-pragmas $(ADDITIONALFLAGS)
LIBS=-L$(PREFIX)/lib -lc -ljansson -lyder -lorcania -lulfius -ldl
LDFLAGS += -Wl,-R '-Wl,-R$$ORIGIN' -lopenzwave

all: release

mock.o: ../glewlwyd.h mock.c
	$(CC) $(CFLAGS) $(FLAGS_YDER) mock.c

libmodmock.so: mock.o
	$(CC) -shared -Wl,-soname,libmodmock.so -o libmodmock.so mock.o $(LIBS)

clean:
	rm -f *.o *.so

debug: ADDITIONALFLAGS=-DDEBUG -g -O0

debug: libmodmock.so

release: ADDITIONALFLAGS=-O3

release:

install:
	mkdir -p $(MODULES_TARGET)
	cp -f *.so $(MODULES_TARGET)
