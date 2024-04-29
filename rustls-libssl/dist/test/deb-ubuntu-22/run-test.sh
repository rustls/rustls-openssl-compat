#!/bin/bash

set -e
TAG="$1"

docker run --interactive --publish 8443:443 "$TAG" &
DOCKER_ID=$!
sleep 2

output_got=$(curl --cacert ca.cert https://localhost:8443/)

kill "$DOCKER_ID"
diff --unified --report-identical-files <(echo "hello world") <(echo "$output_got")
