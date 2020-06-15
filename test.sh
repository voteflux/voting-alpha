#!/usr/bin/env bash

set -e

PYPATH_TAIL=$([[ -z "$PYTHONPATH" ]] && echo ":$PYTHONPATH" || echo "")
export PYTHONPATH="$PWD/stack/cr/common"

export PATH="$HOME/.pyenv/bin:$PATH"
if [[ -d stack/cr/deps/eth_tester ]]; then
    echo 'skipping install of eth_tester py-evm; run `pip3 install --target=stack/cr/deps eth_tester py-evm` if you have trouble.'
else
    pip3 install --target=stack/cr/deps eth_tester py-evm
fi

docker run --rm \
    -v "$PWD/stack/cr/chaincode:/var/task:ro,delegated" \
    -v "$PWD/stack/cr:/opt:ro,delegated" \
    --name 'voting-alpha-python-tester' \
    --entrypoint /bin/bash \
    --user root:root \
    lambci/lambda:build-python3.7 \
    -c 'export PYTHONPATH="$PWD:/opt/deps:/opt:${PYTHONPATH:-/opt}" && export PATH="$PATH:$PWD/deps" \
            && pip3 install eth_tester py-evm web3 \
            && python3 test/test_mk_contract.py'

 # -v "$PWD/stack/cr:/opt:ro,delegated" \

#(cd stack/cr && pytest --ignore-glob="**/deps/*") # --include-glob="stack/cr/**")

# remove testing packages
#rm -rf stack/cr/common/deps/{eth_tester,py-evm}
