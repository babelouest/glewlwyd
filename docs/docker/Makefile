GLEWLWYD_VERSION=$(shell curl -s https://api.github.com/repos/babelouest/glewlwyd/releases/latest | grep tag_name | cut -d '"' -f 4 | cut -c 2-)

ORCANIA_GLEWLWYD_CMAKE_VERSION=$(shell grep ORCANIA_VERSION CMakeLists-latest.txt | head -n 1 | cut -c 31- | sed 's/\".*//')
YDER_GLEWLWYD_CMAKE_VERSION=$(shell grep YDER_VERSION CMakeLists-latest.txt | head -n 1 | cut -c 28- | sed 's/\".*//')
ULFIUS_GLEWLWYD_CMAKE_VERSION=$(shell grep ULFIUS_VERSION CMakeLists-latest.txt | head -n 1 | cut -c 30- | sed 's/\".*//')
HOEL_GLEWLWYD_CMAKE_VERSION=$(shell grep HOEL_VERSION CMakeLists-latest.txt | head -n 1 | cut -c 28- | sed 's/\".*//')
RHONABWY_GLEWLWYD_CMAKE_VERSION=$(shell grep RHONABWY_VERSION CMakeLists-latest.txt | head -n 1 | cut -c 32- | sed 's/\".*//')
IDDAWC_GLEWLWYD_CMAKE_VERSION=$(shell grep IDDAWC_VERSION CMakeLists-latest.txt | head -n 1 | cut -c 30- | sed 's/\".*//')

all: build

CMakeLists-latest.txt:
	wget https://github.com/babelouest/glewlwyd/raw/v$(GLEWLWYD_VERSION)/CMakeLists.txt -O CMakeLists-latest.txt

orcania.tar.gz: CMakeLists-latest.txt
	wget https://github.com/babelouest/orcania/archive/refs/tags/v$(ORCANIA_GLEWLWYD_CMAKE_VERSION).tar.gz -O orcania.tar.gz

yder.tar.gz: CMakeLists-latest.txt
	wget https://github.com/babelouest/yder/archive/refs/tags/v$(YDER_GLEWLWYD_CMAKE_VERSION).tar.gz -O yder.tar.gz

ulfius.tar.gz: CMakeLists-latest.txt
	wget https://github.com/babelouest/ulfius/archive/refs/tags/v$(ULFIUS_GLEWLWYD_CMAKE_VERSION).tar.gz -O ulfius.tar.gz

hoel.tar.gz: CMakeLists-latest.txt
	wget https://github.com/babelouest/hoel/archive/refs/tags/v$(HOEL_GLEWLWYD_CMAKE_VERSION).tar.gz -O hoel.tar.gz

rhonabwy.tar.gz: CMakeLists-latest.txt
	wget https://github.com/babelouest/rhonabwy/archive/refs/tags/v$(RHONABWY_GLEWLWYD_CMAKE_VERSION).tar.gz -O rhonabwy.tar.gz

iddawc.tar.gz: CMakeLists-latest.txt
	wget https://github.com/babelouest/iddawc/archive/refs/tags/v$(IDDAWC_GLEWLWYD_CMAKE_VERSION).tar.gz -O iddawc.tar.gz

glewlwyd.tar.gz: CMakeLists-latest.txt
	wget https://github.com/babelouest/glewlwyd/archive/refs/tags/v$(GLEWLWYD_VERSION).tar.gz -O glewlwyd.tar.gz

build: orcania.tar.gz yder.tar.gz ulfius.tar.gz hoel.tar.gz rhonabwy.tar.gz iddawc.tar.gz glewlwyd.tar.gz
	docker build -t babelouest/glewlwyd:$(GLEWLWYD_VERSION) .
	docker tag babelouest/glewlwyd:$(GLEWLWYD_VERSION) babelouest/glewlwyd:latest

run:
	docker run --rm -it -p 4593:4593 babelouest/glewlwyd:latest

my-config:
	docker run --rm -it -p 4593:4593 -v $(shell pwd)/config:/etc/glewlwyd babelouest/glewlwyd

clean:
	rm -f orcania.tar.gz yder.tar.gz ulfius.tar.gz hoel.tar.gz rhonabwy.tar.gz iddawc.tar.gz glewlwyd.tar.gz CMakeLists-latest.txt
	docker rmi -f babelouest/glewlwyd:latest babelouest/glewlwyd:$(GLEWLWYD_VERSION)
	docker system prune -f
