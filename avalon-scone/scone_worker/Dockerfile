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

FROM sconecuratedimages/muslgcc as libraries

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

RUN apk add \
    readline-dev \
    ncurses-dev \
    libressl-dev \
    sqlite-dev \
    tk-dev \
    gdbm-dev \
    libbz2

WORKDIR /

#Libressl
RUN wget https://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-3.0.0.tar.gz
RUN tar xvzf libressl-3.0.0.tar.gz && \
   cd libressl-3.0.0 && \
   ./configure --prefix=/custom-libressl && \
   make && \
   make install 

WORKDIR /

ENV LDFLAGS="-L/custom-libressl/lib/"
ENV LD_LIBRARY_PATH="/custom-libressl/lib/"
ENV CPPFLAGS="-I/custom-libressl/include/ -I/custom-libressl/include/openssl"
ENV CFLAGS="-I/custom-libressl/include/ -I/custom-libressl/include/openssl"
ENV PATH="$PATH:/custom-python/bin:/custom-python/lib"

#Python
RUN wget https://www.python.org/ftp/python/3.6.12/Python-3.6.12.tgz
RUN tar -xf Python-3.6.12.tgz && \
  cd Python-3.6.12 && \
  ./configure --prefix=/custom-python && \
  make && make install

FROM sconecuratedimages/crosscompilers:runtime-alpine3.7-scone4
RUN apk update && apk add make && apk add build-base

COPY --from=libraries /custom-libzmq /custom-libzmq
COPY --from=libraries /custom-libressl /custom-libressl
COPY --from=libraries /custom-python /custom-python

ENV LDFLAGS="-L/custom-libressl/lib/"
ENV LD_LIBRARY_PATH="/custom-libressl/lib/"
ENV CPPFLAGS="-I/custom-libressl/include/ -I/custom-libressl/include/openssl"
ENV CFLAGS="-I/custom-libressl/include/ -I/custom-libressl/include/openssl"
ENV PATH="$PATH:/custom-python/bin:/custom-python/lib"

RUN pip3 install pyzmq --install-option="--zmq=/custom-libzmq"
RUN pip3 install pycryptodomex ecdsa
RUN pip3 install wheel

WORKDIR /home/pythonworker
#COPY . .
COPY ./avalon-scone/scone_worker/ .

RUN make && make install

#CMD SCONE_MODE=HW SCONE_ALPINE=1 SCONE_VERSION=1 SCONE_HEAP=4G SCONE_ALLOW_DLOPEN=2 wo-processor --bind "tcp://*:7777"

#ENTRYPOINT tail -f /dev/null
