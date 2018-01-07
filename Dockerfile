#
# Dockerfile for mysocks
#

FROM alpine:3.3
MAINTAINER lzh <lzh@cpan.org>

ARG MYSOCKS_URL=https://github.com/zhou0/mysocks/archive/0.5.12.tar.gz
ARG LIBUV_URL=https://github.com/libuv/libuv/archive/v1.18.0.tar.gz 
ARG WOLFSSL_URL=https://github.com/wolfSSL/wolfssl/archive/v3.11.0-stable.tar.gz
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
    curl -sSL $LIBUV_URL | tar xz && cd libuv-1.18.0 && \
./autogen.sh && ./configure --prefix=/usr --disable-static && make && \
make install && cd .. && \
    curl -sSL $WOLFSSL_URL | tar xz && cd wolfssl-3.11.0-stable && \
 ./autogen.sh && \
./configure --prefix=/usr --disable-static --enable-ipv6 --enable-aesgcm \
--enable-aesccm --enable-aesni --enable-aesctr --disable-coding \
--enable-hkdf --enable-poly1305 --enable-camellia --disable-des3 \
--enable-hc128 --enable-rabbit --enable-chacha --disable-examples \
--disable-iopool --disable-oldtls --disable-asn --disable-rsa \
--enable-fastmath --enable-sha  --disable-dh --enable-arc4 \
--disable-hashdrbg --disable-ecc --disable-sha512 --enable-cryptonly \
--disable-extended-master --disable-sha224 && \
make && make install && cd .. && \
    curl -sSL $MYSOCKS_URL | tar xz && cd mysocks-0.5.12 && mkdir -p \
build/release && cd build/release && \
    cmake -DCMAKE_BUILD_TYPE=Release ../.. && \
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
    rm -fr libuv-1.18.0 && rm -fr wolfssl-3.11.0-stable && rm -fr mysocks-0.5.12
