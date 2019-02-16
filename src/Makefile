#
# Glewlwyd OAuth2 Authorization Server
#
# Makefile used to build the software
#
# Copyright 2018-2019 Nicolas Mora <mail@babelouest.org>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU GENERAL PUBLIC LICENSE
# License as published by the Free Software Foundation;
# version 3 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU GENERAL PUBLIC LICENSE for more details.
#
# You should have received a copy of the GNU General Public
# License along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

CC=gcc
CFLAGS=-c -Wall -D_REENTRANT $(ADDITIONALFLAGS)
LIBS=-lc -ldl -ljansson -lorcania -lyder -lulfius -lhoel -lgnutls -lconfig -lcrypto -ljwt
OBJECTS=glewlwyd.o misc.o static_file_callback.o webservice.o hash.o session.o user.o scope.o plugin.o client.o
PREFIX=/usr/local
CONFIG_FILE=../glewlwyd2.conf

all: release

clean:
	rm -f *.o glewlwyd valgrind.txt
	cd user && $(MAKE) clean
	cd client && $(MAKE) clean
	cd scheme && $(MAKE) clean
	cd plugin && $(MAKE) clean

debug: ADDITIONALFLAGS=-Wunreachable-code -DDEBUG -g -O0

debug: glewlwyd
	cd user && $(MAKE) debug
	cd client && $(MAKE) debug
	cd scheme && $(MAKE) debug
	cd plugin && $(MAKE) debug

release: ADDITIONALFLAGS=-O3

release: glewlwyd
	cd user && $(MAKE)
	cd client && $(MAKE)
	cd scheme && $(MAKE)
	cd plugin && $(MAKE)

%.o: %.c glewlwyd.h
	$(CC) $(CFLAGS) $(CPPFLAGS) $<

glewlwyd: $(OBJECTS)
	$(CC) -o $@ $^ $(LIBS) $(LDFLAGS)

memcheck: debug
	valgrind --tool=memcheck --leak-check=full --show-leak-kinds=all ./glewlwyd --config-file=$(CONFIG_FILE) 2>valgrind.txt

test-debug: debug
	./glewlwyd --config-file=$(CONFIG_FILE)

install: glewlwyd
	install -f glewlwyd $(PREFIX)/bin
