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


if [ "$1" == "" ]; then
  echo "Please provide argument (either start or stop)."
  exit
fi

if [ "$1" == "start" ]; then

	echo "Determining SGX Device"
	
	echo "Starting Scone LAS container"

	docker-compose -f docker-compose-scone-baseline.yaml up -d
	sleep 5

	echo "Creating Scone Workers and KME Images with Encrypted FS"

	cd avalon-scone

	./create_image.sh
	source myenv

	cd ..

	echo "Starting Avalon Scone containers"

	docker-compose -f docker-compose-scone-avalon.yaml up --build -d

	echo "Done"
	exit

fi

if [ "$1" == "stop" ]; then

	echo "Stopping Avalon Scone containers"

	docker-compose -f docker-compose-scone-avalon.yaml down -v

	echo "Stopping Scone LAS container"

	docker-compose -f docker-compose-scone-baseline.yaml down -v

	echo "Done"
	exit
fi
