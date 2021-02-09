#!/bin/bash

# Copyright 2020 Mujtaba Idrees
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

#predecessor: b367be3903b3e0519d7fbc2de1b88382fba3daef5576e3b3272ed0919705b05d
echo "Generating certificates"
mkdir -p conf
    if [[ ! -f conf/client.crt || ! -f conf/client-key.key  ]] ; then
        openssl req -x509 -newkey rsa:4096 -out conf/client.crt -keyout conf/client-key.key  -days 31 -nodes -sha256 -subj "/C=US/ST=Dresden/L=Saxony/O=Scontain/OU=Org/CN=www.scontain.com" -reqexts SAN -extensions SAN -config <(cat /etc/ssl/openssl.cnf \
    <(printf '[SAN]\nsubjectAltName=DNS:www.scontain.com'))
    fi

echo "Writing session file"
cat > session.yml <<EOF
name: scone-openvino-1
version: "0.3"

services:
  - name: app-secrets
    mrenclaves: [c4dbb0a3f4ef6d2212d3d4bd0c843de2870f0f0205cd65c2bcf767ef998cadbb]
    command: ./security_barrier_camera_demo -i input/$1 -m input/vehicle-license-plate-detection-barrier-0106.xml -r
    environment:
      OpenCV_DIR: "/opencv/build/"
      InferenceEngine_DIR: "/dldt/inference-engine/build/"
    pwd: /

secrets:
  - name: update_seq
    kind: ascii
    value: $2
    export_public: true

access_policy:
  read:
   - CREATOR
  update:
   - CREATOR

security:
  attestation:
    tolerate: [debug-mode, hyperthreading, insecure-igpu, outdated-tcb]
    ignore_advisories: ["INTEL-SA-00076", "INTEL-SA-00088", "INTEL-SA-00106", "INTEL-SA-00115", "INTEL-SA-00135", "INTEL-SA-00203", "INTEL-SA-00161", "INTEL-SA-00220", "INTEL-SA-00270", "INTEL-SA-00293", "INTEL-SA-00320", "INTEL-SA-00329", "INTEL-SA-00233", "INTEL-SA-00220", "INTEL-SA-00270", "INTEL-SA-00293", "INTEL-SA-00320", "INTEL-SA-00329"]

EOF

more session.yml
echo "Posting session"
curl -k -s --cert conf/client.crt --key conf/client-key.key --data-binary @session.yml -X POST https://cas:8081/session
