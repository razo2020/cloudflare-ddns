FROM alpine:3.18 AS build
WORKDIR /root/build
RUN apk add --no-cache build-base curl-dev
RUN apk add --no-cache curl-static nghttp2-static libidn2-static libunistring-static brotli-static openssl-libs-static zlib-static
