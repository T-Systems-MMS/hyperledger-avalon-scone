#!/bin/bash

if [ "$1" == "" ]; then
  echo "Please provide argument (either start or stop)."
  exit
fi


if [ "$1" == "start" ]; then

	echo "Creating Secure Images"
	./create_image.sh

	echo "Setting up Env varialbes"
	source myenv

	echo "Starting containers"

	docker-compose up --build -d

	echo "Done"

fi

if [ "$1" == "stop" ]; then
	source myenv
	docker-compose down -v
fi
