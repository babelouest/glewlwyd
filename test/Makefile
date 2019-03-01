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
LDFLAGS=-lc -lulfius -lorcania -ljansson -lyder -lcheck -lpthread -lm -lrt -lsubunit -ljwt
TARGET_ADMIN=glewlwyd_admin_mod_type glewlwyd_admin_mod_user glewlwyd_admin_mod_user_auth_scheme glewlwyd_admin_mod_client glewlwyd_admin_mod_plugin
TARGET_AUTH=glewlwyd_auth_password glewlwyd_auth_scheme glewlwyd_auth_grant glewlwyd_auth_check_scheme glewlwyd_auth_scheme_trigger
TARGET_OAUTH2=glewlwyd_oauth2_auth_code glewlwyd_oauth2_code glewlwyd_oauth2_code_client_confidential glewlwyd_oauth2_implicit glewlwyd_oauth2_resource_owner_pwd_cred glewlwyd_oauth2_resource_owner_pwd_cred_client_confidential glewlwyd_oauth2_client_cred glewlwyd_oauth2_refresh_token glewlwyd_oauth2_refresh_token_client_confidential glewlwyd_oauth2_delete_token glewlwyd_oauth2_delete_token_client_confidential
all: test
VERBOSE=0
RUN=1

clean:
	rm -f *.o *.log valgrind.txt $(TARGET_ADMIN) $(TARGET_AUTH) $(TARGET_OAUTH2)

build: $(TARGET_ADMIN) $(TARGET_AUTH) $(TARGET_OAUTH2)

unit-tests.o: unit-tests.c unit-tests.h
	$(CC) $(CFLAGS) -c unit-tests.c

%: %.c unit-tests.o
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

test: build test-admin-mod test-auth test-oauth2

test-auth: $(TARGET_AUTH) test_glewlwyd_auth_password test_glewlwyd_auth_scheme test_glewlwyd_auth_grant test_glewlwyd_auth_check_scheme test_glewlwyd_auth_scheme_trigger

test-crud: 

test-admin-mod: $(TARGET_ADMIN) test_glewlwyd_admin_mod_type test_glewlwyd_admin_mod_user test_glewlwyd_admin_mod_user_auth_scheme test_glewlwyd_admin_mod_client test_glewlwyd_admin_mod_plugin

test-oauth2: $(TARGET_OAUTH2) test_glewlwyd_oauth2_auth_code test_glewlwyd_oauth2_code test_glewlwyd_oauth2_code_client_confidential test_glewlwyd_oauth2_implicit test_glewlwyd_oauth2_resource_owner_pwd_cred test_glewlwyd_oauth2_resource_owner_pwd_cred_client_confidential test_glewlwyd_oauth2_client_cred test_glewlwyd_oauth2_refresh_token test_glewlwyd_oauth2_refresh_token_client_confidential test_glewlwyd_oauth2_delete_token test_glewlwyd_oauth2_delete_token_client_confidential

test_%: %
	@-if [ "$(VERBOSE)" = "0" ]; then \
		./run_test.sh ./$^; \
	else \
		./$^; \
	fi
