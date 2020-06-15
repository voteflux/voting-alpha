#!/usr/bin/env bash

set -e

PYPATH_TAIL=$([[ -z "$PYTHONPATH" ]] && echo ":$PYTHONPATH" || echo "")
export PYTHONPATH="$PWD/stack/cr/common"


docker run --rm \
    -v $PWD/stack/cr/chaincode:/var/task:ro,delegated \
    -v $PWD/stack/cr/common:/opt:ro,delegated \
    --entrypoint bash
    lamci/lambda:python:3.7
    -c "pip3 install pytest && pytest"


#(cd stack/cr && pytest --ignore-glob="**/deps/*") # --include-glob="stack/cr/**")
