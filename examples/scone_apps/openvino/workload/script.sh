#!/bin/ash

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

echo Openvino Processor Started!

while true ; do
    result=$(curl -k -s https://cas:8081/v1/values/session=$1 --stderr - | grep "update_seq")
    if [[ ${#result} -gt 0 ]] ; then
        break
    fi
    sleep 2
done
val=default
old_val=default

while true ; do

	val=$(curl -k -s https://cas:8081/v1/values/session=$1 | jq ".values.update_seq.value" | tr -d \")
	if [ "$val" == "$old_val" ] ; then
		sleep 2
        continue 
    fi
	old_val=$val
	res=$(SCONE_VERSION=1 SCONE_CONFIG_ID=$1/app-secrets ./security_barrier_camera_demo | grep -i "WILL BE RENDERED!")
	count=$(echo $res | tr -cd '!' | wc -c)
	parsed=$(echo $res | sed "s/WILL BE RENDERED!/_/g")
	parsed=$(echo $parsed |sed "s/ \[/\[/g")

	echo "Request Id : $val" > output/$1.txt
	echo "Total $count cars found in the image, probability and coordinates are given below :" >> output/$1.txt
	echo $parsed |sed "s/_/\n/g" >> output/$1.txt
 	echo Done Processing the Request!
    sleep 2
 done
