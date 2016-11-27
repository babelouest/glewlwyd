#
# Glewlwyd OAuth2 Authorization Server
#
# Makefile used to build the software
#
# Copyright 2016 Nicolas Mora <mail@babelouest.org>
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
CFLAGS=-c -Wall -I$(LIBYDER_LOCATION) -D_REENTRANT $(ADDITIONALFLAGS)
LIBS=-lc -lulfius -lyder -ljansson -lorcania -lhoel -ljwt -lconfig -lldap -luuid -lcrypto
PREFIX=/usr/local

all: release

clean:
	rm -f *.o glewlwyd valgrind.txt

debug: ADDITIONALFLAGS=-DDEBUG -g -O0

debug: glewlwyd

release: ADDITIONALFLAGS=-O3

release: glewlwyd

glewlwyd.o: glewlwyd.c glewlwyd.h
	$(CC) $(CFLAGS) glewlwyd.c

authorization.o: authorization.c glewlwyd.h
	$(CC) $(CFLAGS) authorization.c

oauth.o: oauth.c glewlwyd.h
	$(CC) $(CFLAGS) oauth.c

webservice.o: webservice.c glewlwyd.h
	$(CC) $(CFLAGS) webservice.c

glewlwyd: glewlwyd.o authorization.o oauth.o webservice.o
	$(CC) -o glewlwyd glewlwyd.o authorization.o oauth.o webservice.o $(LIBS)

memcheck: debug
	valgrind --tool=memcheck --leak-check=full --show-leak-kinds=all ./glewlwyd --config-file=glewlwyd.conf 2>valgrind.txt

install: glewlwyd
	cp -f glewlwyd $(PREFIX)/bin
