# Glewlwyd unit tests

These unit tests are based on the [check framework](http://check.sourceforge.net/). You must install check library first (on Debian/Ubuntu you can do this with `apt-get install check`).

All the unit tests test the behavior of the functionalities available in the REST API. Which means to run a valid test case, you must have a running instance of Glewlwyd on localhost with the data initialized by the script `init.sql`.

When the valid test instance is available, you can build and run each test case. Run `make test` to run all automatic tests.
