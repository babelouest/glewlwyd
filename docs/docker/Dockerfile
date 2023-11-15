FROM alpine:latest AS builder

COPY *.tar.gz /opt/

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
    autoconf \
    automake \
    libmicrohttpd-dev \
    libcurl \
    curl-dev \
    libconfig-dev \
    libgcrypt-dev \
    sqlite-dev \
    mariadb-dev \
    postgresql-dev \
    util-linux-dev \
    openldap-dev \
    bash \
    oath-toolkit-dev \
    libtool \
    libcbor-dev && \
    mkdir -p /opt/orcania/build && cd /opt/orcania/ && \
    tar xvf /opt/orcania.tar.gz --strip 1 && \
    cd /opt/orcania/build && \
    cmake -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_INSTALL_LIBDIR=lib -DBUILD_BASE64URL=OFF .. && \
    make && make install && \
    mkdir -p /opt/yder/build && cd /opt/yder/ && \
    tar xvf /opt/yder.tar.gz --strip 1 && \
    cd /opt/yder/build && \
    cmake -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_INSTALL_LIBDIR=lib -DWITH_JOURNALD=OFF .. && \
    make && make install && \
    mkdir -p /opt/ulfius/build && cd /opt/ulfius/ && \
    tar xvf /opt/ulfius.tar.gz --strip 1 && \
    cd /opt/ulfius/build && \
    cmake -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_INSTALL_LIBDIR=lib -DBUILD_UWSC=OFF .. && \
    make && make install && \
    mkdir -p /opt/hoel/build && cd /opt/hoel/ && \
    tar xvf /opt/hoel.tar.gz --strip 1 && \
    cd /opt/hoel/build && \
    cmake -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_INSTALL_LIBDIR=lib .. && \
    make && make install && \
    mkdir -p /opt/rhonabwy/build && cd /opt/rhonabwy/ && \
    tar xvf /opt/rhonabwy.tar.gz --strip 1 && \
    cd /opt/rhonabwy/build && \
    cmake -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_INSTALL_LIBDIR=lib -DBUILD_RNBYC=OFF .. && \
    make && make install && \
    mkdir -p /opt/iddawc/build && cd /opt/iddawc/ && \
    tar xvf /opt/iddawc.tar.gz --strip 1 && \
    cd /opt/iddawc/build && \
    cmake -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_INSTALL_LIBDIR=lib .. && \
    make && make install && \
    mkdir -p /opt/glewlwyd/build && cd /opt/glewlwyd/ && \
    tar xvf /opt/glewlwyd.tar.gz --strip 1 && \
    cd /opt/glewlwyd/build && \
    cmake -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_INSTALL_LIBDIR=lib .. && \
    make && make install

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
    libcbor \
    bash

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
RUN cp /etc/glewlwyd/config.json /usr/share/glewlwyd/webapp/config.json

COPY ["entrypoint.sh", "/"]

CMD ["/entrypoint.sh"]
