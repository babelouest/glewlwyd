GLEWLWYD_VERSION=$(shell curl $(AUTH_HEADER) -s https://api.github.com/repos/babelouest/glewlwyd/releases/latest | grep tag_name | cut -d '"' -f 4 | cut -c 2-)
ALPINE_VERSION=3.10.3

build:
	docker build -t babelouest/glewlwyd --build-arg GLEWLWYD_VERSION=$(GLEWLWYD_VERSION) --build-arg ALPINE_VERSION=$(ALPINE_VERSION) .

run:
	docker run --rm -it -p 4593:4593 babelouest/glewlwyd

my-config:
	docker run --rm -it -p 4593:4593 -v $(shell pwd)/config:/etc/glewlwyd babelouest/glewlwyd
