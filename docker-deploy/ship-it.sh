#!/bin/bash

SCRIPT_DIR="$( cd -- "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 ; pwd -P )"

pushd $SCRIPT_DIR/..
docker build -t cdk-deploy images/cdk-deploy
docker run -it -v ~/.aws:/root/.aws -v `pwd`:/files -v /var/run/docker.sock:/var/run/docker.sock -w /files cdk-deploy ship-it

popd