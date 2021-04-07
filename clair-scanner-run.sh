#!/bin/bash
REPORT_FILE=$1
CLAIR_SERVER=$2
LOCALHOST=$3
IMAGE=$4
echo  starting clair containers...
docker start db 2>/dev/null
docker start clair-db 2>/dev/null
docker start clair 2>/dev/null

echo scanning image
rm -f clair.json
echo "clair-scanner $REPORT_FILE  $CLAIR_SERVER $LOCALHOST $IMAGE"
clair-scanner $REPORT_FILE $CLAIR_SERVER $LOCALHOST $IMAGE

echo stopping clair containers...
docker stop clair-db 2>/dev/null
docker stop db 2>/dev/null
docker stop clair 2>/dev/null



