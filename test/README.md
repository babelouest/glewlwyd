# Glewlwyd unit tests

These unit tests are based on the [check framework](http://check.sourceforge.net/). You must install check library first.

All the unit tests test the behaviour of the functionalities available in the REST API. Which means to run a valid test case, you must have a running instance of Glewlwyd on localhost with the data initialized by the script `init.sql`.

When the valid test instance is available, you can build and run each test case. Run `make test` to run all automatic tests.

## Run the test suite

Basically, you can use those unit test to validate that all the functionalities are present after a modification in glewlwyd source code.

To run a proper set of tests, you must have use a `glewlwyd.conf` file that points to a database initialized with the following scripts:
- glewlwyd.[mariadb|sqlite3].sql
- test/init.sql

Then, on a console, go to the folder `src/`, then run the command `make test-debug` or `make memcheck` to run the tests with valgrind.
When glewlwyd is up and running, on another console, go to the folder `test/` and run the command `make test` to run all tests in sequence.

To run a single test case, you can run the command `make test_[the test name]`, for example: `make test_glewlwyd_implicit`.

If you don't have a LDAP server, the ldap tests will fail, which is normal, you can ignore all the ldap tests.
