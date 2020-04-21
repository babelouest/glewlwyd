#
# Glewlwyd SSO Server
#
# Makefile used to build the software
#
# Copyright 2016-2019 Nicolas Mora <mail@babelouest.org>
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
CFLAGS=-c -Wall -Werror -Wextra -D_REENTRANT $(shell pkg-config --cflags liborcania) $(shell pkg-config --cflags libyder) $(shell pkg-config --cflags libulfius) $(shell pkg-config --cflags jansson) $(shell pkg-config --cflags libhoel) $(shell pkg-config --cflags gnutls) $(shell pkg-config --cflags libconfig) $(shell pkg-config --cflags nettle) $(shell pkg-config --cflags hogweed) $(ADDITIONALFLAGS)
LIBS=$(shell pkg-config --libs liborcania) $(shell pkg-config --libs libyder) $(shell pkg-config --libs libulfius) $(shell pkg-config --libs libhoel) $(shell pkg-config --libs jansson) $(shell pkg-config --libs gnutls) $(shell pkg-config --libs libconfig) $(shell pkg-config --libs nettle) $(shell pkg-config --libs hogweed) -ldl -lpthread -lcrypt
OBJECTS=glewlwyd.o misc.o static_file_callback.o webservice.o session.o user.o scope.o plugin.o client.o module.o
DESTDIR=/usr/local
CONFIG_FILE=../glewlwyd.conf

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

%.o: %.c glewlwyd.h glewlwyd-common.h
	$(CC) $(CFLAGS) $(CPPFLAGS) $<

glewlwyd: $(OBJECTS)
	$(CC) -o $@ $^ $(LIBS) $(LDFLAGS)

memcheck: debug
	valgrind --tool=memcheck --leak-check=full --show-leak-kinds=all --track-origins=yes ./glewlwyd --config-file=$(CONFIG_FILE) 2>valgrind.txt

test-debug: debug
	./glewlwyd --config-file=$(CONFIG_FILE)

install: glewlwyd
	install glewlwyd $(DESTDIR)/bin
	cd user && $(MAKE) install DESTDIR=$(DESTDIR)
	cd client && $(MAKE) install DESTDIR=$(DESTDIR)
	cd scheme && $(MAKE) install DESTDIR=$(DESTDIR)
	cd plugin && $(MAKE) install DESTDIR=$(DESTDIR)
