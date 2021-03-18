#!/bin/bash
REPORT_FILE=$1
CLAIR_SERVER=$2
LOCALHOST=$3
IMAGE=$4
echo  starting clair containers...
docker start db
docker start clair-db
docker start clair

echo scanning image
rm -f clair.json
echo "clair-scanner $REPORT_FILE  $CLAIR_SERVER $LOCALHOST $IMAGE"
clair-scanner $REPORT_FILE $CLAIR_SERVER $LOCALHOST $IMAGE

echo stopping clair containers...
docker stop clair-db
docker stop db
docker stop clair



