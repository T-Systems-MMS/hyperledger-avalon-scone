#!/bin/ash

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

kme_api_url="https://scone-kme:5000/scone_worker_session/"

while true ; do
	result=$(curl -k -s $kme_api_url$1)
	if [[ ${#result} -gt 0 ]] ; then
		echo "Worker is starting!"
		SCONE_MODE=HW SCONE_ALPINE=1 SCONE_VERSION=1 SCONE_HEAP=4G SCONE_ALLOW_DLOPEN=1 SCONE_CONFIG_ID=$result/avalon-scone-worker-session python3
		exit 0
	fi
    sleep 2
done