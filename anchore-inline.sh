#!/bin/bash
IMAGE=$1
curl -s https://ci-tools.anchore.io/inline_scan-latest | bash -s -- -r -t 1000 $IMAGE
anchore_container=$(docker ps -a | grep inline-anchore-engine|cut -d" " -f1)
docker stop $anchore_container 2>/dev/null
docker rm $anchore_container 2>/dev/null
