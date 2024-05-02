#!/bin/bash

set -e
TAG="$1"

docker run --interactive --publish 8443:443 "$TAG" &
sleep 2

output_got=$(curl --cacert ca.cert https://localhost:8443/)

docker stop "$(docker ps --quiet)"

diff --unified --report-identical-files <(echo "hello world") <(echo "$output_got")
