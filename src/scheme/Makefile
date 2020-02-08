#
# Glewlwyd authentication scheme
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
MODULES_TARGET=$(DESTDIR)/lib/glewlwyd/scheme
CC=gcc
CFLAGS=-c -fPIC -Wall -Werror -Wextra -Wno-unknown-pragmas -D_REENTRANT -Wno-pragmas $(shell pkg-config --cflags liborcania) $(shell pkg-config --cflags libyder) $(shell pkg-config --cflags jansson) $(shell pkg-config --cflags libhoel) $(shell pkg-config --cflags librhonabwy) $(shell pkg-config --cflags libiddawc) $(shell pkg-config --cflags libjwt) $(shell pkg-config --cflags libcbor) $(ADDITIONALFLAGS)
LIBS=$(shell pkg-config --libs liborcania) $(shell pkg-config --libs libyder) $(shell pkg-config --libs libhoel) $(shell pkg-config --libs librhonabwy) $(shell pkg-config --libs libiddawc) $(shell pkg-config --libs jansson) -ldl
TARGET=libmodemail.so libmodwebauthn.so libmodotp.so libmodpassword.so libmodcertificate.so libmodhttp.so libmodoauth2.so

all: release

%.o: %.c ../glewlwyd.h
	$(CC) $(CFLAGS) $(CPPFLAGS) $<

misc.o: ../misc.c ../glewlwyd-common.h
	$(CC) $(CFLAGS) $(CPPFLAGS) ../misc.c

libmodmock.so: mock.o misc.o
	$(CC) -shared -Wl,-soname,libmodmock.so -o libmodmock.so mock.o misc.o $(LIBS)

libmodemail.so: email.o misc.o
	$(CC) -shared -Wl,-soname,libmodemail.so -o libmodemail.so email.o misc.o $(LIBS)

libmodwebauthn.so: webauthn.o misc.o
	$(CC) -shared -Wl,-soname,libmodwebauthn.so -o libmodwebauthn.so webauthn.o misc.o $(LIBS) $(shell pkg-config --libs libcbor) $(shell pkg-config --libs libjwt) -lldap

libmodotp.so: otp.o misc.o
	$(CC) -shared -Wl,-soname,libmodotp.so -o libmodotp.so otp.o misc.o $(LIBS) $(shell pkg-config --libs liboath)

libmodpassword.so: password.o misc.o
	$(CC) -shared -Wl,-soname,libmodpassword.so -o libmodpassword.so password.o misc.o $(LIBS)

libmodcertificate.so: certificate.o misc.o
	$(CC) -shared -Wl,-soname,libmodcertificate.so -o libmodcertificate.so certificate.o misc.o $(LIBS)

libmodhttp.so: http.o misc.o
	$(CC) -shared -Wl,-soname,libmodhttp.so -o libmodhttp.so http.o misc.o $(LIBS)

libmodoauth2.so: oauth2.o misc.o
	$(CC) -shared -Wl,-soname,libmodoauth2.so -o libmodoauth2.so oauth2.o misc.o $(LIBS)

clean:
	rm -f *.o *.so

debug: ADDITIONALFLAGS=-DDEBUG -g -O0

debug: libmodmock.so $(TARGET)

release: ADDITIONALFLAGS=-O3

release: $(TARGET)

install:
	mkdir -p $(MODULES_TARGET)
	cp -f *.so $(MODULES_TARGET)
