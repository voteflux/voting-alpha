#!/usr/bin/env bash

_PWD=$(pwd)

cd $_PWD/ethereum
npm run build
cd $_PWD

cp -v ethereum/build/contracts/Membership.* stack/app/members/api/scripts/sc/
cp -v ethereum/build/contracts/Erc20BalanceProxy.* stack/app/members/api/scripts/sc/

cp -v ethereum/build/contracts/Membership.bin stack/cr/chaincode/bytecode/membership.bin
cp -v ethereum/build/contracts/Erc20BalanceProxy.bin stack/cr/chaincode/bytecode/erc20-balance-proxy.bin
