#
# Dockerfile for mysocks
#

FROM alpine
MAINTAINER lzh <lzh@cpan.org>

ARG MYSOCKS_URL=https://github.com/zhou0/mysocks/archive/0.1.tar.gz

RUN set -ex && \
    apk add --no-cache --virtual .build-deps \
                                autoconf \
                                build-base \
                                cmake \
                                curl \
                                libtool \
                                linux-headers \
                                tar \
                                unzip \
                                && \
    cd /tmp && \
    curl -sSL $MYSOCKS_URL | tar xz --strip 1 && \ 
    cd build/debug && \
    cmake -DCMAKE_BUILD_TYPE=Debug -DCMAKE_INSTALL_PREFIX=/usr && \
    make install && \
    cd .. && \

    runDeps="$( \
        scanelf --needed --nobanner /usr/local/bin/ss-* \
            | awk '{ gsub(/,/, "\nso:", $2); print "so:" $2 }' \
            | xargs -r apk info --installed \
            | sort -u \
    )" && \
    apk add --no-cache --virtual .run-deps $runDeps && \
    apk del .build-deps && \
    rm -rf /tmp/*
