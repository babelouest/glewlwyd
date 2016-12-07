/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#include <check.h>
#include <ulfius.h>
#include <orcania.h>
#include <yder.h>

#include "unit-tests.h"

#define SERVER_URI "http://localhost:4593/glewlwyd"
#define USERNAME "user1"
#define PASSWORD "MyUser1Password!"
#define SCOPE_LIST "scope1 scope2"
#define CLIENT "client1_id"

struct _u_request user_req;
char * code;

START_TEST(test_glwd)
{
	ck_assert_int_eq(1, 1);
}
END_TEST

static Suite *libjwt_suite(void)
{
	Suite *s;
	TCase *tc_core;

	s = suite_create("Glewlwyd");
	tc_core = tcase_create("test_glwd");
	tcase_add_test(tc_core, test_glwd);
	tcase_set_timeout(tc_core, 30);
	suite_add_tcase(s, tc_core);

	return s;
}

int main(int argc, char *argv[])
{
	int number_failed;
	Suite *s;
	SRunner *sr;
  
  y_init_logs("Glewlwyd test", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Glewlwyd test");
  
	s = libjwt_suite();
	sr = srunner_create(s);

	srunner_run_all(sr, CK_VERBOSE);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);
  
  ulfius_clean_request(&user_req);

	return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
