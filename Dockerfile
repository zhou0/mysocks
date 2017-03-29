#
# Dockerfile for mysocks
#

FROM alpine:3.3
MAINTAINER lzh <lzh@cpan.org>

ARG MYSOCKS_URL=https://github.com/zhou0/mysocks/archive/0.1.tar.gz
ARG LIBUV_URL=https://github.com/libuv/libuv/archive/v1.11.0.tar.gz 

RUN set -ex && \
    apk add --no-cache --virtual .build-deps \
                                autoconf \
                                automake \
                                build-base \
                                cmake \
                                curl \
                                file \
                                libtool \
                                linux-headers \
                                openssl-dev \
                                tar \
                                && \
    curl -sSL $LIBUV_URL | tar xz && cd libuv-1.11.0 && ./autogen.sh && ./configure --prefix=/usr && make && make install && cd .. && \
    curl -sSL $MYSOCKS_URL | tar xz && cd mysocks-0.1/build/debug && \
    rm CMakeCache.txt && \
    cmake -DCMAKE_BUILD_TYPE=Debug ../.. && \
    make && make install && \ 
    
    runDeps="$( \
        scanelf --needed --nobanner /usr/local/bin/ssclient \
            | awk '{ gsub(/,/, "\nso:", $2); print "so:" $2 }' \
            | xargs -r apk info --installed \
            | sort -u \
    )" && \
    cd ../../.. && \
    apk add --no-cache --virtual .run-deps $runDeps && \
    apk del .build-deps && \
    rm -fr libuv-1.11.0 && rm -fr mysocks-0.1 
