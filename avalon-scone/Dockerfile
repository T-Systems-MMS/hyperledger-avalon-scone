# Copyright 2020 Intel Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

FROM registry.scontain.com:5050/sconecuratedimages/muslgcc:alpine-scone5 as libraries

RUN apk update && \
   apk add \
   wget \
   libtool \
   pkgconfig \
   autoconf \
   automake \
   make 

WORKDIR /

#Libzmq
RUN wget https://github.com/zeromq/libzmq/releases/download/v4.2.2/zeromq-4.2.2.tar.gz
RUN tar xvzf zeromq-4.2.2.tar.gz && \
    cd zeromq-4.2.2 && \
    ./autogen.sh && \
    ./configure prefix=/custom-libzmq && \
    make && \
    make install

WORKDIR /

#Libffi
RUN wget https://github.com/libffi/libffi/releases/download/v3.3/libffi-3.3.tar.gz
RUN tar xvzf libffi-3.3.tar.gz && \
    cd libffi-3.3 && \
    ./configure prefix=/custom-libffi && \
    make && \
    make install

WORKDIR /

#Libressl
RUN wget https://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-3.0.0.tar.gz
RUN tar xvzf libressl-3.0.0.tar.gz && \
   cd libressl-3.0.0 && \
   ./configure --prefix=/custom-libressl && \
   make && \
   make install 

WORKDIR /

RUN apk add \
    readline-dev \
    sqlite-dev \
    tk-dev \
    gdbm-dev \
    libbz2

ENV LDFLAGS="-L/custom-libressl/lib/ -L/custom-libffi/lib"
ENV CPPFLAGS="-I/custom-libressl/include/ -I/custom-libressl/include/openssl -I/custom-libffi/include/"
ENV CFLAGS="-I/custom-libressl/include/ -I/custom-libressl/include/openssl -I/custom-libffi/include/"
ENV LD_LIBRARY_PATH="/custom-libressl/lib/:/custom-libffi/lib"
ENV PATH="$PATH:/custom-python/bin:/custom-python/lib"

#Python
RUN wget https://www.python.org/ftp/python/3.6.12/Python-3.6.12.tgz
RUN tar -xf Python-3.6.12.tgz && \
  cd Python-3.6.12 && \
  ./configure --prefix=/custom-python && \
  make && make install

RUN pip3 install pyzmq==20.0.0 --install-option="--zmq=/custom-libzmq"
RUN pip3 install pycryptodomex==3.9.9
RUN pip3 install ecdsa==0.16.1
RUN pip3 install wheel==0.35.1
RUN pip3 install requests==2.25.0
RUN pip3 install toml==0.10.2
RUN pip3 install Flask==1.1.2
RUN pip3 install pyOpenSSL==19.1.0

FROM registry.scontain.com:5050/sconecuratedimages/crosscompilers:runtime-alpine3.7-scone4

COPY --from=libraries /custom-libzmq/lib /custom-libzmq/lib
COPY --from=libraries /custom-libffi/lib /custom-libffi/lib
COPY --from=libraries /custom-libressl/lib /custom-libressl/lib
COPY --from=libraries /custom-python/lib /custom-python/lib
COPY --from=libraries /custom-python/bin /custom-python/bin
COPY --from=libraries /usr/lib/libstdc++.so.6 /muslusr/lib/libstdc++.so.6
COPY --from=libraries /usr/lib/libgcc_s.so.1 /muslusr/lib/libgcc_s.so.1

WORKDIR /project/avalon


