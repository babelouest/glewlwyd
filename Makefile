#
# Glewlwyd OAuth2 Authorization Server
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

GLEWLWYD_SOURCE=./src
GLEWLWYD_TESTS=./test
GLEWLWYD_DOCS=./docs
GLEWLWYD_DOCKER=./docs/docker
all:
	cd $(GLEWLWYD_SOURCE) && $(MAKE) $*

debug:
	cd $(GLEWLWYD_SOURCE) && $(MAKE) debug $*

install:
	cd $(GLEWLWYD_SOURCE) && $(MAKE) install $*

memcheck:
	cd $(GLEWLWYD_SOURCE) && $(MAKE) memcheck $*

test-debug:
	cd $(GLEWLWYD_SOURCE) && $(MAKE) test-debug $*

check:
	cd $(GLEWLWYD_TESTS) && $(MAKE) test $*

clean:
	cd $(GLEWLWYD_SOURCE) && $(MAKE) clean
	cd $(GLEWLWYD_TESTS) && $(MAKE) clean
	cd $(GLEWLWYD_DOCKER) && $(MAKE) clean
	docker rmi -f babelouest/glewlwyd:src babelouest/glewlwyd:ci
	docker system prune -f

docker:
	docker build -t babelouest/glewlwyd:src .

docker-ci:
	docker build --file=Dockerfile-ci -t babelouest/glewlwyd:ci .

manpage:
	cd $(GLEWLWYD_SOURCE) && $(MAKE) $*
	help2man $(GLEWLWYD_SOURCE)/glewlwyd -s 8 -n "Single-Sign-On (SSO) server with multiple factor authentication" > $(GLEWLWYD_DOCS)/glewlwyd.8
