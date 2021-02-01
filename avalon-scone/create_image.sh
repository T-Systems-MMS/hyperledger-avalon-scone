#!/bin/bash

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
#
# tasks performed:
#
# - creates a local Docker image with an encrypted Python program (flask patient service) and encrypted input file
# - pushes a new session to a CAS instance
# - creates a file with the session name
#
# show what we do (-x), export all varialbes (-a), and abort of first error (-e)

set -x -a -e
trap "echo Unexpected error! See log above; exit 1" ERR


function cleanup {
    sudo rm -rf kme-fs
    sudo rm -rf worker-fs
    rm -f cas-ca.pem
    rm -f client-key.key
    rm -f client.crt
    rm -f kme_session.yml
    rm -f Dockerfile-scone-kme
    rm -f Dockerfile-scone-worker
}

# CONFIG Parameters (might change)

export AVALON_SCONE_IMAGE_NAME="avalon-scone-dev"
export KME_IMAGE_NAME="avalon-scone-kme-dev"
export WORKER_IMAGE_NAME="avalon-scone-worker-dev"
export SCONE_CAS_EXTERNAL_ADDR="localhost:8082"
export SCONE_CAS_ADDR="cas"
export DEVICE="/dev/sgx"
export KME_ALIAS="scone-kme"
export AVALON_NETWORK="avalon-network"
export CAS_MRENCLAVE="309e23ffab10255e7332c92b230d2208dcbc5db0408c3af26093c830033bc2e4"
export SCONE_RUNTIME_IMAGE="registry.scontain.com:5050/sconecuratedimages/crosscompilers:runtime-alpine3.7-scone4"
export CLI_IMAGE="registry.scontain.com:5050/sconecuratedimages/kubernetes:hello-k8s-scone0.1"


# create directories for protected files and fspf for KME
sudo rm -rf kme-fs

mkdir kme-fs
mkdir kme-fs/native-files
mkdir kme-fs/native-files/config
mkdir kme-fs/protected-files
mkdir kme-fs/fspf-file/


cp -rf key_management_enclave/avalon_key_manager/* kme-fs/native-files
cp -rf ../config/scone_config.toml kme-fs/native-files/config/scone_config.toml
cp -rf ../config/session_template.yml kme-fs/native-files/config/session_template.yml
cp key_management_enclave/fspf.sh kme-fs/fspf-file

# create directories for protected files and fspf for Worker
sudo rm -rf worker-fs

mkdir worker-fs
mkdir worker-fs/native-files
mkdir worker-fs/native-files/config
mkdir worker-fs/protected-files
mkdir worker-fs/fspf-file/

cp -rf scone_worker/avalon_worker worker-fs/native-files/avalon_worker
cp -rf scone_worker/workloads.json worker-fs/native-files/workloads.json
cp -rf ../config/scone_config.toml worker-fs/native-files/config/scone_config.toml
cp -rf ../config/openvino_session_template.yml worker-fs/native-files/config/openvino_session_template.yml
cp scone_worker/fspf.sh worker-fs/fspf-file

# ensure that we have an up-to-date image
docker pull $SCONE_RUNTIME_IMAGE
docker pull $CLI_IMAGE

# check if SGX device exists

if [[ ! -c "$DEVICE" ]] ; then
    export DEVICE_O="DEVICE"
    export DEVICE="/dev/isgx"
    if [[ ! -c "$DEVICE" ]] ; then
        echo "Neither $DEVICE_O nor $DEVICE exist"
        exit 1
    fi
fi


# attest cas before uploading the session file, accept CAS running in debug
# mode (-d) and outdated TCB (-G)
docker run --device=$DEVICE --network=$AVALON_NETWORK -it $CLI_IMAGE sh -c "
scone cas attest -G --only_for_testing-debug  $SCONE_CAS_ADDR $CAS_MRENCLAVE >/dev/null \
&&  scone cas show-certificate" > cas-ca.pem

# copy cas cert in kme and worker fs for secure ssl with cas
cp -rf cas-ca.pem kme-fs/native-files
cp -rf cas-ca.pem worker-fs/native-files

# create an intermediate avalon scone image  
docker build --pull -t $AVALON_SCONE_IMAGE_NAME .

# create encrypted and authenticated filesystem and fspf for KME
docker run --device=$DEVICE -it -v $(pwd)/kme-fs/fspf-file:/fspf-file -v $(pwd)/kme-fs/native-files:/native-files/ -v $(pwd)/kme-fs/protected-files:/project $AVALON_SCONE_IMAGE_NAME /fspf-file/fspf.sh

# create encrypted and authenticated filesystem and fspf for worker
docker run --device=$DEVICE -it -v $(pwd)/worker-fs/fspf-file:/fspf-file -v $(pwd)/worker-fs/native-files:/native-files/ -v $(pwd)/worker-fs/protected-files:/project $AVALON_SCONE_IMAGE_NAME /fspf-file/fspf.sh

# creating lightweight Dockerfile for KME by copying FS created in previous step
cat > Dockerfile-scone-kme <<EOF
FROM $SCONE_RUNTIME_IMAGE
COPY kme-fs/protected-files /project
ENV LD_LIBRARY_PATH="/project/custom-libressl/lib/:/project/custom-libffi/lib"
ENV PATH="\$PATH:/project/custom-python/bin:/project/custom-python/lib:/project/muslusr/lib"
ENV PYTHONHOME=/project/custom-python
ENV TCF_HOME=/project/avalon
WORKDIR /project/avalon
EOF

# create an image with encrypted scone kme code and authenticated libraries
docker build -f Dockerfile-scone-kme -t $KME_IMAGE_NAME .

# creating lightweight Dockerfile for Worker by copying FS created in previous step
cat > Dockerfile-scone-worker <<EOF
FROM $SCONE_RUNTIME_IMAGE
COPY scone_worker/wait-for.sh /wait-for.sh
COPY worker-fs/protected-files /project
ENV LD_LIBRARY_PATH="/project/custom-libressl/lib/:/project/custom-libffi/lib:/project/muslusr/lib"
ENV PATH="\$PATH:/project/custom-python/bin:/project/custom-python/lib:/project/muslusr/lib"
ENV PYTHONHOME=/project/custom-python
ENV TCF_HOME=/project/avalon
RUN apk add curl
WORKDIR /project/avalon
EOF

# create a image with encrypted scone worker code and authenticated libraries
docker build -f Dockerfile-scone-worker -t $WORKER_IMAGE_NAME .


# ensure that we have self-signed client certificate

echo "Generating certificates"
if [[ ! -f client.crt || ! -f client-key.key  ]] ; then
    openssl req -x509 -newkey rsa:4096 -out client.crt -keyout client-key.key  -days 31 -nodes -sha256 -subj "/C=US/ST=Dresden/L=Saxony/O=Scontain/OU=Org/CN=www.scontain.com" -reqexts SAN -extensions SAN -config <(cat /etc/ssl/openssl.cnf \
<(printf '[SAN]\nsubjectAltName=DNS:www.scontain.com'))
fi

# create session file

export KME_SCONE_FSPF_KEY=$(cat $(pwd)/kme-fs/native-files/keytag | awk '{print $11}')
export KME_SCONE_FSPF_TAG=$(cat $(pwd)/kme-fs/native-files/keytag | awk '{print $9}')

export WORKER_SCONE_FSPF_KEY=$(cat $(pwd)/worker-fs/native-files/keytag | awk '{print $11}')
export WORKER_SCONE_FSPF_TAG=$(cat $(pwd)/worker-fs/native-files/keytag | awk '{print $9}')

echo "Writing session file"
cat > kme_session.yml <<EOF
name: $KME_ALIAS
version: "0.3"

services:
  - name: certificate-generation
    image_name: kme_image
    mrenclaves: [c9f7c9d89a1ff120a78a27cf0c9c2f572f0c7df7553cafea5de5b7a78bdc4718]
    command: python3 key_manager.py
    environment:
      TCF_HOME: "/project/avalon"
      PYTHONHOME: "/project/custom-python"
      LD_LIBRARY_PATH: "/project/custom-libressl/lib/:/project/custom-libffi/lib"
      WORKER_FS_KEY: "$WORKER_SCONE_FSPF_KEY"
      WORKER_FS_TAG: "$WORKER_SCONE_FSPF_TAG"
    pwd: /project/avalon
    fspf_tag: $KME_SCONE_FSPF_TAG
    fspf_key: $KME_SCONE_FSPF_KEY
    fspf_path: /project/fs.fspf

secrets:
  - name: api_ca_key
    kind: private-key
  - name: api_ca_cert
    kind: x509-ca
    export_public: true
    private_key: api_ca_key
  - name: kme_key
    kind: private-key
  - name: kme
    kind: x509
    private_key: kme_key
    issuer: api_ca_cert
    dns:
      - $KME_ALIAS
images:
  - name: kme_image
    injection_files:
      - path:  /project/avalon/cert.pem
        content: \$\$SCONE::kme.crt\$\$
      - path: /project/avalon/key.pem
        content: \$\$SCONE::kme.key\$\$

access_policy:
  read:
   - CREATOR
  update:
   - CREATOR

security:
  attestation:
    tolerate: [debug-mode, hyperthreading, insecure-igpu, outdated-tcb]
    ignore_advisories: "*"

EOF

curl -v -s --cacert cas-ca.pem --cert client.crt  --key client-key.key  --data-binary @kme_session.yml -X POST https://$SCONE_CAS_EXTERNAL_ADDR/session

cleanup

echo "OK"
