#
# Glewlwyd potocol backend
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
MODULES_TARGET=$(PREFIX)/lib/glewlwyd/protocol
CC=gcc
CFLAGS=-c -fPIC -Wall -Wno-unknown-pragmas -D_REENTRANT -shared -nostartfiles -I$(PREFIX)/include -Wno-pragmas $(ADDITIONALFLAGS)
LIBS=-L$(PREFIX)/lib -lc -ljansson -lyder -lorcania -lulfius -ljwt -ldl

all: release

oauth2.o: ../glewlwyd.h oauth2.c
	$(CC) $(CFLAGS) $(FLAGS_YDER) oauth2.c

libprotocoloauth2.so: oauth2.o
	$(CC) -shared -Wl,-soname,libprotocoloauth2.so -o libprotocoloauth2.so oauth2.o $(LIBS)

clean:
	rm -f *.o *.so

debug: ADDITIONALFLAGS=-DDEBUG -g -O0

debug: libprotocoloauth2.so

release: ADDITIONALFLAGS=-O3

release:

install:
	mkdir -p $(MODULES_TARGET)
	cp -f *.so $(MODULES_TARGET)
