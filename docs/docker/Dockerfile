FROM alpine:latest AS builder

ARG GLEWLWYD_VERSION
ARG ALPINE_VERSION

# Install required packages
RUN apk add --no-cache \
    git \
    make \
    cmake \
    wget \
    gcc \
    g++ \
    jansson-dev \
    gnutls-dev \
    wget \
    cmake \
    autoconf \
    automake \
    libtool && \
    (cd /opt && wget https://github.com/PJK/libcbor/archive/v0.5.0.tar.gz -O libcbor.tar.gz && \
    tar xf libcbor.tar.gz && cd libcbor-0.5.0 && mkdir build && cd build && \
    cmake -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_INSTALL_LIBDIR=lib .. && make && make install) && \
    cd /opt && \
    wget https://github.com/babelouest/glewlwyd/releases/download/v${GLEWLWYD_VERSION}/glewlwyd-full_${GLEWLWYD_VERSION}_alpine_${ALPINE_VERSION}_x86_64.tar.gz -O glewlwyd.tar.gz && \
    tar xvf ./glewlwyd.tar.gz && \
    tar xvf liborcania_*.tar.gz -C /usr/ --strip 1 && \
    tar xvf libyder_*.tar.gz -C /usr/ --strip 1 && \
    tar xvf libulfius_*.tar.gz -C /usr/ --strip 1 && \
    tar xvf libhoel_*.tar.gz -C /usr/ --strip 1 && \
    tar xvf librhonabwy_*.tar.gz -C /usr/ --strip 1 && \
    tar xvf libiddawc_*.tar.gz -C /usr/ --strip 1 && \
    tar xvf glewlwyd_*.tar.gz -C /usr/ --strip 1


FROM alpine:latest AS runner
RUN apk add --no-cache \
    wget \
    sqlite \
    libconfig \
    jansson \
    gnutls \
    libcurl \
    libldap \
    libmicrohttpd \
    sqlite-libs \
    libpq \
    oath-toolkit-liboath \
    mariadb-connector-c \
    bash

COPY --from=builder /usr/lib/libcbor.* /usr/lib/
COPY --from=builder /usr/lib/liborcania* /usr/lib/
COPY --from=builder /usr/lib/libyder* /usr/lib/
COPY --from=builder /usr/lib/libhoel* /usr/lib/
COPY --from=builder /usr/lib/libulfius* /usr/lib/
COPY --from=builder /usr/lib/librhonabwy* /usr/lib/
COPY --from=builder /usr/lib/libiddawc* /usr/lib/
COPY --from=builder /usr/lib/glewlwyd/ /usr/lib/glewlwyd/
COPY --from=builder /usr/bin/glewlwyd /usr/bin
COPY --from=builder /usr/share/glewlwyd/ /usr/share/glewlwyd/
COPY --from=builder /usr/share/glewlwyd/webapp/config.json /etc/glewlwyd/
COPY --from=builder /usr/etc/glewlwyd/ /etc/glewlwyd/

RUN rm /usr/share/glewlwyd/webapp/config.json
RUN ln -s /etc/glewlwyd/config.json /usr/share/glewlwyd/webapp/config.json

COPY ["entrypoint.sh", "/"]

CMD ["/entrypoint.sh"]
