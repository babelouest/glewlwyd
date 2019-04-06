#
# Glewlwyd potocol backend
#
# Makefile used to build the software
#
# Copyright 2016-2019 Nicolas Mora <mail@babelouest.org>
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

DEST=/usr/local
MODULES_TARGET=$(DEST)/lib/glewlwyd/plugin
CC=gcc
CFLAGS=-c -fPIC -Wall -Wno-unknown-pragmas -D_REENTRANT -shared -nostartfiles -Wno-pragmas $(ADDITIONALFLAGS)
LIBS=-lc -ldl -ljansson -lorcania -lyder -lulfius -ljwt

all: release

%.o: %.c ../glewlwyd-common.h
	$(CC) $(CFLAGS) $(CPPFLAGS) $<

misc.o: ../misc.c ../glewlwyd-common.h
	$(CC) $(CFLAGS) $(CPPFLAGS) ../misc.c

glewlwyd_resource.o: ../../docs/resources/ulfius/glewlwyd_resource.c ../../docs/resources/ulfius/glewlwyd_resource.h
	$(CC) $(CFLAGS) $(CPPFLAGS) ../../docs/resources/ulfius/glewlwyd_resource.c

libprotocol_oauth2.so: protocol_oauth2.o misc.o glewlwyd_resource.o ../glewlwyd-common.h ../../docs/resources/ulfius/glewlwyd_resource.h
	$(CC) -shared -Wl,-soname,libprotocol_oauth2.so -o libprotocol_oauth2.so protocol_oauth2.o misc.o glewlwyd_resource.o $(LIBS)

libprotocol_mock.so: mock.o misc.o ../glewlwyd-common.h
	$(CC) -shared -Wl,-soname,libprotocol_mock.so -o libprotocol_mock.so mock.o misc.o $(LIBS)

clean:
	rm -f *.o *.so

debug: ADDITIONALFLAGS=-DDEBUG -g -O0

debug: libprotocol_mock.so libprotocol_oauth2.so

release: ADDITIONALFLAGS=-O3

release: libprotocol_oauth2.so

install:
	mkdir -p $(MODULES_TARGET)
	cp -f *.so $(MODULES_TARGET)
