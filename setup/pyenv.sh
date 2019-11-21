#!/usr/bin/env bash

PYENVVER=$(cat .python-version)
PY_VER=$(echo "$PYENVVER" | cut -d '/' -f 1)
ENV_NAME=$(echo "$PYENVVER" | cut -d '/' -f 3)

echo "Installying python $PY_VER and setting up venv: $ENV_NAME"

pyenv install $PY_VER
pyenv virtualenv $ENV_NAME

pyenv activate
pip install -r ./_manager_lib/requirements.txt
