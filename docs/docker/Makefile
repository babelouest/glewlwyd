GLEWLWYD_VERSION=$(shell curl $(AUTH_HEADER) -s https://api.github.com/repos/babelouest/glewlwyd/releases/latest | grep tag_name | cut -d '"' -f 4 | cut -c 2-)
ALPINE_VERSION=3.12.0

build:
	docker build -t babelouest/glewlwyd:$(GLEWLWYD_VERSION) --build-arg GLEWLWYD_VERSION=$(GLEWLWYD_VERSION) --build-arg ALPINE_VERSION=$(ALPINE_VERSION) .
	docker tag babelouest/glewlwyd:$(GLEWLWYD_VERSION) babelouest/glewlwyd:latest

run:
	docker run --rm -it -p 4593:4593 babelouest/glewlwyd:latest

my-config:
	docker run --rm -it -p 4593:4593 -v $(shell pwd)/config:/etc/glewlwyd babelouest/glewlwyd
