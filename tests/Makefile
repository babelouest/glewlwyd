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
CFLAGS=-Wall -D_REENTRANT -DDEBUG -g -O0
LIBS=-lc -lulfius -lorcania -ljansson -lyder -lcheck -lpthread -lm -lrt -lsubunit

all: test

clean:
	rm -f *.o glewlwyd_auth_code glewlwyd_client_cred glewlwyd_code glewlwyd_implicit glewlwyd_resource_owner_pwd_cred glewlwyd_delete_token

unit-tests.o: unit-tests.c unit-tests.h
	$(CC) $(CFLAGS) -c unit-tests.c

glewlwyd_auth_code: glewlwyd_auth_code.c unit-tests.o
	$(CC) $(CFLAGS) glewlwyd_auth_code.c unit-tests.o -o glewlwyd_auth_code $(LIBS)

test_glewlwyd_auth_code: glewlwyd_auth_code
	-./glewlwyd_auth_code

glewlwyd_client_cred: glewlwyd_client_cred.c unit-tests.o
	$(CC) $(CFLAGS) glewlwyd_client_cred.c unit-tests.o -o glewlwyd_client_cred $(LIBS)

test_glewlwyd_client_cred: glewlwyd_client_cred
	-./glewlwyd_client_cred

glewlwyd_code: glewlwyd_code.c unit-tests.o
	$(CC) $(CFLAGS) glewlwyd_code.c unit-tests.o -o glewlwyd_code $(LIBS)

test_glewlwyd_code: glewlwyd_code
	-./glewlwyd_code

glewlwyd_implicit: glewlwyd_implicit.c unit-tests.o
	$(CC) $(CFLAGS) glewlwyd_implicit.c unit-tests.o -o glewlwyd_implicit $(LIBS)

test_glewlwyd_implicit: glewlwyd_implicit
	-./glewlwyd_implicit

glewlwyd_resource_owner_pwd_cred: glewlwyd_resource_owner_pwd_cred.c unit-tests.o
	$(CC) $(CFLAGS) glewlwyd_resource_owner_pwd_cred.c unit-tests.o -o glewlwyd_resource_owner_pwd_cred $(LIBS)

test_glewlwyd_resource_owner_pwd_cred: glewlwyd_resource_owner_pwd_cred
	-./glewlwyd_resource_owner_pwd_cred

glewlwyd_delete_token: glewlwyd_delete_token.c unit-tests.o
	$(CC) $(CFLAGS) glewlwyd_delete_token.c unit-tests.o -o glewlwyd_delete_token $(LIBS)

test_glewlwyd_delete_token: glewlwyd_delete_token
	-./glewlwyd_delete_token

test: test_glewlwyd_resource_owner_pwd_cred test_glewlwyd_implicit test_glewlwyd_code test_glewlwyd_client_cred test_glewlwyd_auth_code test_glewlwyd_delete_token
