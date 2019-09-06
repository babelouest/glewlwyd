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
LDFLAGS=-lc -lulfius -lorcania -ljansson -lyder -ljwt -loath -lgnutls -lcbor -lcheck -lpthread -lm -lrt -lsubunit
TARGET_ADMIN=glewlwyd_admin_mod_type glewlwyd_admin_mod_user glewlwyd_admin_mod_user_auth_scheme glewlwyd_admin_mod_client glewlwyd_admin_mod_plugin glewlwyd_admin_check_scope
TARGET_AUTH=glewlwyd_auth_password glewlwyd_auth_scheme glewlwyd_auth_grant glewlwyd_auth_check_scheme glewlwyd_auth_scheme_trigger glewlwyd_auth_scheme_register glewlwyd_auth_profile glewlwyd_auth_session_manage glewlwyd_auth_profile_get_scheme_available glewlwyd_auth_profile_impersonate
TARGET_CRUD=glewlwyd_crud_user glewlwyd_crud_client glewlwyd_crud_scope
TARGET_OAUTH2=glewlwyd_oauth2_auth_code glewlwyd_oauth2_code glewlwyd_oauth2_code_client_confidential glewlwyd_oauth2_implicit glewlwyd_oauth2_resource_owner_pwd_cred glewlwyd_oauth2_resource_owner_pwd_cred_client_confidential glewlwyd_oauth2_client_cred glewlwyd_oauth2_refresh_token glewlwyd_oauth2_refresh_token_client_confidential glewlwyd_oauth2_delete_token glewlwyd_oauth2_delete_token_client_confidential glewlwyd_oauth2_profile glewlwyd_oauth2_refresh_manage glewlwyd_oauth2_refresh_manage_session glewlwyd_oauth2_profile_impersonate glewlwyd_oauth2_additional_parameters glewlwyd_oauth2_client_secret
TARGET_OIDC=glewlwyd_oidc_auth_code glewlwyd_oidc_code glewlwyd_oidc_code_client_confidential glewlwyd_oidc_token glewlwyd_oidc_resource_owner_pwd_cred glewlwyd_oidc_resource_owner_pwd_cred_client_confidential glewlwyd_oidc_client_cred glewlwyd_oidc_code_idtoken glewlwyd_oidc_implicit_id_token_token glewlwyd_oidc_implicit_none glewlwyd_oidc_hybrid_id_token_token_code glewlwyd_oidc_hybrid_id_token_code glewlwyd_oidc_hybrid_token_code glewlwyd_oidc_implicit_id_token glewlwyd_oidc_optional_request_parameters glewlwyd_oidc_refresh_token glewlwyd_oidc_refresh_token_client_confidential glewlwyd_oidc_delete_token glewlwyd_oidc_delete_token_client_confidential glewlwyd_oidc_refresh_manage glewlwyd_oidc_refresh_manage_session glewlwyd_oidc_userinfo glewlwyd_oidc_additional_parameters glewlwyd_oidc_only_no_refresh glewlwyd_oidc_discovery glewlwyd_oidc_client_secret glewlwyd_oidc_request_jwt glewlwyd_oidc_subject_type glewlwyd_oidc_address_claim glewlwyd_oidc_claims_scopes glewlwyd_oidc_claim_request
TARGET_IRL=glewlwyd_mod_user_irl glewlwyd_mod_client_irl glewlwyd_mod_user_http glewlwyd_oauth2_irl glewlwyd_oidc_irl glewlwyd_scheme_mail glewlwyd_scheme_otp glewlwyd_scheme_webauthn glewlwyd_scheme_retype_password
TARGET_CERTIFICATE=glewlwyd_scheme_certificate
VERBOSE=0
MEMCHECK=0
RUN=1
PARAM_FILE=param.json

all: test

clean:
	rm -f *.o *.log valgrind.txt valgrind-*.txt $(TARGET_ADMIN) $(TARGET_AUTH) $(TARGET_CRUD) $(TARGET_OAUTH2) $(TARGET_OIDC) $(TARGET_IRL) $(TARGET_CERTIFICATE)

build: $(TARGET_ADMIN) $(TARGET_AUTH) $(TARGET_CRUD) $(TARGET_OAUTH2) $(TARGET_OIDC) $(TARGET_IRL) $(TARGET_CERTIFICATE)

unit-tests.o: unit-tests.c unit-tests.h
	$(CC) $(CFLAGS) -c unit-tests.c

%: %.c unit-tests.o
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

test: build test-admin test-auth test-crud test-oauth2 test-oidc test-irl

test-auth: $(TARGET_AUTH) test_glewlwyd_auth_password test_glewlwyd_auth_scheme test_glewlwyd_auth_grant test_glewlwyd_auth_check_scheme test_glewlwyd_auth_scheme_trigger test_glewlwyd_auth_scheme_register test_glewlwyd_auth_profile test_glewlwyd_auth_session_manage test_glewlwyd_auth_profile_get_scheme_available test_glewlwyd_auth_profile_impersonate

test-admin: $(TARGET_ADMIN) test_glewlwyd_admin_mod_type test_glewlwyd_admin_mod_user test_glewlwyd_admin_mod_user_auth_scheme test_glewlwyd_admin_mod_client test_glewlwyd_admin_mod_plugin test_glewlwyd_admin_check_scope

test-crud: $(TARGET_CRUD) test_glewlwyd_crud_user test_glewlwyd_crud_client test_glewlwyd_crud_scope

test-oauth2: $(TARGET_OAUTH2) test_glewlwyd_oauth2_auth_code test_glewlwyd_oauth2_code test_glewlwyd_oauth2_code_client_confidential test_glewlwyd_oauth2_implicit test_glewlwyd_oauth2_resource_owner_pwd_cred test_glewlwyd_oauth2_resource_owner_pwd_cred_client_confidential test_glewlwyd_oauth2_client_cred test_glewlwyd_oauth2_refresh_token test_glewlwyd_oauth2_refresh_token_client_confidential test_glewlwyd_oauth2_delete_token test_glewlwyd_oauth2_delete_token_client_confidential test_glewlwyd_oauth2_profile test_glewlwyd_oauth2_refresh_manage test_glewlwyd_oauth2_refresh_manage test_glewlwyd_oauth2_refresh_manage_session test_glewlwyd_oauth2_profile_impersonate test_glewlwyd_oauth2_additional_parameters test_glewlwyd_oauth2_client_secret

test-oidc: $(TARGET_OIDC) test_glewlwyd_oidc_auth_code test_glewlwyd_oidc_code test_glewlwyd_oidc_code_client_confidential test_glewlwyd_oidc_token test_glewlwyd_oidc_resource_owner_pwd_cred test_glewlwyd_oidc_resource_owner_pwd_cred_client_confidential test_glewlwyd_oidc_client_cred test_glewlwyd_oidc_code_idtoken test_glewlwyd_oidc_implicit_id_token_token test_glewlwyd_oidc_implicit_id_token test_glewlwyd_oidc_implicit_none test_glewlwyd_oidc_hybrid_id_token_token_code test_glewlwyd_oidc_hybrid_token_code test_glewlwyd_oidc_hybrid_id_token_code test_glewlwyd_oidc_optional_request_parameters test_glewlwyd_oidc_refresh_token test_glewlwyd_oidc_refresh_token_client_confidential test_glewlwyd_oidc_delete_token test_glewlwyd_oidc_delete_token_client_confidential test_glewlwyd_oidc_refresh_manage test_glewlwyd_oidc_refresh_manage test_glewlwyd_oidc_refresh_manage_session test_glewlwyd_oidc_userinfo test_glewlwyd_oidc_additional_parameters test_glewlwyd_oidc_only_no_refresh test_glewlwyd_oidc_discovery test_glewlwyd_oidc_client_secret test_glewlwyd_oidc_request_jwt test_glewlwyd_oidc_subject_type test_glewlwyd_oidc_address_claim test_glewlwyd_oidc_claims_scopes test_glewlwyd_oidc_claim_request

test-certificate: $(TARGET_CERTIFICATE) test_glewlwyd_scheme_certificate

test-irl: $(TARGET_IRL) test_glewlwyd_mod_user_http test_glewlwyd_scheme_mail test_glewlwyd_scheme_otp test_glewlwyd_scheme_webauthn test_glewlwyd_scheme_retype_password
	@for JSON_FILE in mod_user_*.json; \
		do $(MAKE) test_glewlwyd_mod_user_irl PARAM_FILE=$$JSON_FILE $*; \
	done
	@for JSON_FILE in mod_client_*.json; \
		do $(MAKE) test_glewlwyd_mod_client_irl PARAM_FILE=$$JSON_FILE $*; \
	done
	@for JSON_FILE in plugin_oauth2_*.json; \
		do $(MAKE) test_glewlwyd_oauth2_irl PARAM_FILE=$$JSON_FILE $*; \
	done
	@for JSON_FILE in plugin_oidc_*.json; \
		do $(MAKE) test_glewlwyd_oidc_irl PARAM_FILE=$$JSON_FILE $*; \
	done

test_%_irl: %_irl
	@if [ "$(VERBOSE)" = "0" ] && [ "$(MEMCHECK)" = "0" ]; then \
		echo "Run $^ with file $(PARAM_FILE)"; \
		LD_LIBRARY_PATH=. ./run_test.sh ./$^ $(PARAM_FILE); \
		mv $^.log $^-$(PARAM_FILE).log; \
	elif [ "$(MEMCHECK)" = "0" ]; then \
	  LD_LIBRARY_PATH=. ./$^ $(PARAM_FILE); \
	else \
	  LD_LIBRARY_PATH=. valgrind --tool=memcheck --leak-check=full --show-leak-kinds=all ./$^ $(PARAM_FILE) 2>valgrind-$@.txt; \
	fi

test_%: %
	@if [ "$(VERBOSE)" = "0" ] && [ "$(MEMCHECK)" = "0" ]; then \
		LD_LIBRARY_PATH=. ./run_test.sh ./$^ $(HOST); \
	elif [ "$(MEMCHECK)" = "0" ]; then \
	  LD_LIBRARY_PATH=. ./$^ $(HOST); \
	else \
	  LD_LIBRARY_PATH=. valgrind --tool=memcheck --leak-check=full --show-leak-kinds=all ./$^ $(HOST) 2>valgrind-$@.txt; \
	fi
