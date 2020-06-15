#!/usr/bin/env bash

set -e

PYPATH_TAIL=$([[ -z "$PYTHONPATH" ]] && echo ":$PYTHONPATH" || echo "")
export PYTHONPATH="$PWD/stack/cr/common"

export PATH="$HOME/.pyenv/bin:$PATH"
if [[ -d stack/cr/common/deps/eth_tester ]]; then
    echo 'skipping install of eth_tester py-evm; run `pip3 install --target=stack/cr/common/deps eth_tester py-evm` if you have trouble.'
else
    pip3 install --target=stack/cr/common/deps eth_tester py-evm
fi

docker run --rm \
    -v "$PWD/stack/cr:/var/task:ro,delegated" \
    -v "$PWD/stack/cr/common:/opt:ro,delegated" \
    --entrypoint /bin/bash \
    --user root:root \
    lambci/lambda:python3.7 \
    -c 'export PYTHONPATH="/opt/deps:/opt:${PYTHONPATH:-/opt}" && export PATH="$PATH:$PWD/deps" && ls -al /var/task/chaincode/bytecode/membership.bin && python3 chaincode/test/test_mk_contract.py'

#(cd stack/cr && pytest --ignore-glob="**/deps/*") # --include-glob="stack/cr/**")

# remove testing packages
#rm -rf stack/cr/common/deps/{eth_tester,py-evm}
