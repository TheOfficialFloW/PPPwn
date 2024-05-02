#!/bin/bash
DESIREDVER=${1-1100}
echo "Building for $DESIREDVER . To use another PS4 Firwmare Version, execute this script as so: $0 <version>"
pwd=$(pwd)
docker build  --build-arg="PS4FWVER=$DESIREDVER" -t pppwn-docker . --platform linux/amd64
docker run -v "$pwd:/host" pppwn-docker
mv stage1.bin stage1
mv stage2.bin stage2