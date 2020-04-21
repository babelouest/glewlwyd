#
# Glewlwyd client backend
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

DESTDIR=/usr/local
MODULES_TARGET=$(DESTDIR)/lib/glewlwyd/client
CC=gcc
CFLAGS=-c -fPIC -Wall -Werror -Wextra -Wno-unknown-pragmas -D_REENTRANT -Wno-pragmas $(shell pkg-config --cflags liborcania) $(shell pkg-config --cflags libyder) $(shell pkg-config --cflags jansson) $(shell pkg-config --cflags libhoel) $(ADDITIONALFLAGS)
LIBS=$(shell pkg-config --libs liborcania) $(shell pkg-config --libs libyder) $(shell pkg-config --libs jansson) -ldl
TARGET=libmoddatabase.so libmodldap.so

all: release

%.o: %.c ../glewlwyd-common.h
	$(CC) $(CFLAGS) $(CPPFLAGS) $<

misc.o: ../misc.c ../glewlwyd-common.h
	$(CC) $(CFLAGS) $(CPPFLAGS) ../misc.c

libmodmock.so: ../glewlwyd-common.h mock.o misc.o
	$(CC) -shared -Wl,-soname,libmodmock.so -o libmodmock.so mock.o misc.o $(LIBS)

libmoddatabase.so: ../glewlwyd-common.h database.o misc.o
	$(CC) -shared -Wl,-soname,libmoddatabase.so -o libmoddatabase.so database.o misc.o $(LIBS) $(shell pkg-config --libs libhoel)

libmodldap.so: ../glewlwyd-common.h ldap.o misc.o
	$(CC) -shared -Wl,-soname,libmodldap.so -o libmodldap.so ldap.o misc.o $(LIBS) -lldap -lcrypt

clean:
	rm -f *.o *.so

debug: ADDITIONALFLAGS=-DDEBUG -g -O0

debug: libmodmock.so $(TARGET)

release: ADDITIONALFLAGS=-O3

release: $(TARGET)

install:
	mkdir -p $(MODULES_TARGET)
	cp -f *.so $(MODULES_TARGET)
