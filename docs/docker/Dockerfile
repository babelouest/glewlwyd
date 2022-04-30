FROM alpine:latest AS builder

ARG GLEWLWYD_VERSION
ARG ALPINE_VERSION

COPY glewlwyd-full_${GLEWLWYD_VERSION}_alpine_${ALPINE_VERSION}_x86_64.tar.gz /opt/glewlwyd.tar.gz

# Install required packages
RUN apk add --no-cache \
    git \
    make \
    cmake \
    wget \
    gcc \
    g++ \
    libmicrohttpd \
    jansson \
    gnutls \
    wget \
    cmake \
    autoconf \
    automake \
    libcbor \
    libtool && \
    cd /opt && \
    tar xf ./glewlwyd.tar.gz && \
    tar xf liborcania_*.tar.gz -C /usr/ --strip 1 && \
    tar xf libyder_*.tar.gz -C /usr/ --strip 1 && \
    tar xf libulfius_*.tar.gz -C /usr/ --strip 1 && \
    tar xf libhoel_*.tar.gz -C /usr/ --strip 1 && \
    tar xf librhonabwy_*.tar.gz -C /usr/ --strip 1 && \
    tar xf libiddawc_*.tar.gz -C /usr/ --strip 1 && \
    tar xf glewlwyd_*.tar.gz -C /usr/ --strip 1


FROM alpine:latest AS runner
RUN apk add --no-cache \
    wget \
    sqlite \
    libconfig \
    jansson \
    gnutls \
    libcurl \
    libldap \
    sqlite-libs \
    libpq \
    oath-toolkit-liboath \
    mariadb-connector-c \
    libmicrohttpd \
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
RUN cp /etc/glewlwyd/config.json /usr/share/glewlwyd/webapp/config.json

COPY ["entrypoint.sh", "/"]

CMD ["/entrypoint.sh"]
