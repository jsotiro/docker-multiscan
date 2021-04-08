#!/bin/bash
REPORT_FILE=$1
CLAIR_SERVER=$2
IMAGE=$3

if [[ "$OSTYPE" == "darwin"* ]]; then
  LOCALHOST=host.docker.internal
else
  LOCALHOST=$(ip -4 addr show docker0 | grep -Po 'inet \K[\d.]+')
fi
echo $LOCALHOST
echo  starting clair containers...
docker start clair-db 2>/dev/null
docker start clair 2>/dev/null

echo scanning image
rm -f clair.json
echo "clair-scanner $REPORT_FILE  $CLAIR_SERVER --ip=$LOCALHOST $IMAGE"
clair-scanner $REPORT_FILE $CLAIR_SERVER --ip=$LOCALHOST $IMAGE

echo stopping clair containers...
docker stop clair-db 2>/dev/null
docker stop clair 2>/dev/null



