#!/bin/bash
IMAGE=$1
curl -s https://ci-tools.anchore.io/inline_scan-latest | bash -s -- -r -t 1000 $IMAGE
