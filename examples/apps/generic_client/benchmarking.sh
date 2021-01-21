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

echo Benchmarking Started with $1 requests!

if [ "$1" == "" ]; then
  echo "Please provide argument (Benchmark size)."
  exit
fi



n=1

# continue until $n equals 5
while [ $n -le $1 ]
do
    echo "Processing Request $n"
    ./generic_client.py -o --uri "http://avalon-listener:1947" --workload_id "echo-result" --in_data "35"

  n=$(( n+1 ))   # increments $n
done
