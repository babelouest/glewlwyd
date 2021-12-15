GLEWLWYD_VERSION=$(shell curl -s https://api.github.com/repos/babelouest/glewlwyd/releases/latest | grep tag_name | cut -d '"' -f 4 | cut -c 2-)
ALPINE_VERSION=3.15.0

glewlwyd-full_$(GLEWLWYD_VERSION)_alpine_$(ALPINE_VERSION)_x86_64.tar.gz:
	wget https://github.com/babelouest/glewlwyd/releases/download/v${GLEWLWYD_VERSION}/glewlwyd-full_$(GLEWLWYD_VERSION)_alpine_$(ALPINE_VERSION)_x86_64.tar.gz

build: glewlwyd-full_$(GLEWLWYD_VERSION)_alpine_$(ALPINE_VERSION)_x86_64.tar.gz
	docker build -t babelouest/glewlwyd:$(GLEWLWYD_VERSION) --build-arg GLEWLWYD_VERSION=$(GLEWLWYD_VERSION) --build-arg ALPINE_VERSION=$(ALPINE_VERSION) .
	docker tag babelouest/glewlwyd:$(GLEWLWYD_VERSION) babelouest/glewlwyd:latest

run:
	docker run --rm -it -p 4593:4593 babelouest/glewlwyd:latest

my-config:
	docker run --rm -it -p 4593:4593 -v $(shell pwd)/config:/etc/glewlwyd babelouest/glewlwyd

clean:
	rm -f glewlwyd-full_$(GLEWLWYD_VERSION)_alpine_$(ALPINE_VERSION)_x86_64.tar.gz
	docker rmi -f babelouest/glewlwyd:latest babelouest/glewlwyd:$(GLEWLWYD_VERSION)
	docker system prune -f
