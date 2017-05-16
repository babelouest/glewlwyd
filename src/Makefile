#
# Glewlwyd OAuth2 Authorization Server
#
# Makefile used to build the software
#
# Copyright 2016-2017 Nicolas Mora <mail@babelouest.org>
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
#CC=clang
CFLAGS=-c -Wall -D_REENTRANT $(ADDITIONALFLAGS)
LIBS=-lc -lulfius -lyder -ljansson -lorcania -lhoel -ljwt -lconfig -lldap -luuid -lgnutls -lcrypt
OBJECTS=glewlwyd.o authorization.o oauth.o webservice.o token.o user.o client.o admin.o scope.o resource.o password.o
PREFIX=/usr/local
CONFIG_FILE=../glewlwyd.conf

all: release

clean:
	rm -f *.o glewlwyd valgrind.txt

debug: ADDITIONALFLAGS=-DDEBUG -g -O0

debug: glewlwyd

release: ADDITIONALFLAGS=-O3

release: glewlwyd

%.o: %.c glewlwyd.h
	$(CC) $(CFLAGS) $<

glewlwyd: $(OBJECTS)
	$(CC) -o $@ $^ $(LIBS)

memcheck: debug
	valgrind --tool=memcheck --leak-check=full --show-leak-kinds=all ./glewlwyd --config-file=$(CONFIG_FILE) 2>valgrind.txt

test-debug: debug
	./glewlwyd --config-file=$(CONFIG_FILE)

install: glewlwyd
	cp -f glewlwyd $(PREFIX)/bin
