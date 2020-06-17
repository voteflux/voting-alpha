# voting-alpha

Repo for storing all the resources for the Stack.

Contents:

- `/ethereum` - smart contracts, etc
- `/stack` - AWS CloudFormation stack resources

## Website and Livestream

https://flux.vote

## deps

> **Note:** only linux supported atm

### system

* Ubuntu deps: `sudo apt install python3 python3-pip zip git build-essential`
* [Recommended]: Install [pyenv](https://github.com/pyenv/pyenv) and [pyenv-virtualenv](https://github.com/pyenv/pyenv-virtualenv)
* [Recommended]: Docker

### local repo

* `./setup/pyenv.sh` -- ensures python and venv are set up
  * DEPRECATED: `pyenv install` -- installs python matching `.python-version` if it isn't installed. (If there's any trouble with the .python-version in the repo, run `pyenv install 3.6.9`)
  * DEPRECATED: `pyenv virtualenv venv-voting-alpha`
  * DEPRECATED: If you don't have pyenv-virtualenv shell integration then you'll need to activate the venv yourself / manually. Shell integration does this automagically.
* Python deps (for `./manage`): `pip install -r _manager_lib/requirements.txt`
* To install python deps for lambdas: `./manage pip all`

## deploying and `./manage`

> **WARNING:** The `./manage` util will use your default AWS .credentials or AWS_PROFILE if present. You'll also need `export AWS_DEFAULT_REGION=ap-southeast-2` if region isn't specified in your .credentials.

run `./manage --help` for cli commands, or `./manage CMD --help`

### Env Vars

For each env edit the vars in .env.(name) -- e.g. `.env.dev`

Additionally copy `.in.sample` to `.in` and update the vars; source `.in` if you need. (zsh-autoenv will automatically source `.in` and `.out` files for you)

* S3_DEV_BUCKET=<a public bucket>
* TEST_SUBDOMAIN=<just the subdomain>
* VOTING_DOMAIN=<the domain hosted zone you have in route53; subdomains are okay>

### Deployment & Pre-reqs

* make sure you've installed python deps for lambdas as per above (works on linux; on mac you need to use docker which is currently disabled - though code is still in ./manage)
* `./manage pip` -- installs deps for custom resources and things
* `./manage deploy-macros` -- run this after pip but before stack deployment
* `./manage sync-env dev` -- deploys the main cfn stack -- will fail if deploy-macros has not been run

To deploy two stacks along side eachother the following vars must be unique:

* STACK_NAME
* NAME_PREFIX
* SUBDOMAIN

You can edit `.env.dev`, etc to keep them neat

#### Update nested stacks directly (useful during dev)

* example `./manage deploy-ns ./stack/nested/sv-members-app.yaml flux-dev-chain-rMembersApp-1EPU6A6JKYGSX`

### Tests

* `./manage test chaincode`
* `./manage test api-members`
  - note: ensure a containerized openethereum node and RPC endpoint is running before hand: `./manage tools node-up`

#### Curl based, can be run from CLI

* signup: `curl -v -X POST -d '{"method":"signup","params":{"ethereumAddress":"0xe9b0722856FA4EfF597Bd2123C00a4'$(date +%s)'", "unsafeChecksum": true}}' https://api.blockchain.suzuka.flux.party/members/api`
* ballot_publish: `curl -v -X POST -d '{"method":"ballot_publish","params":{"specHash":"0x0f74cba1f103c8636cb87f241cd27a6ef1776185fc956acdb999cd'$(date +%s)'"}}' https://api.blockchain.suzuka.flux.party/members/api`
  - note: this handler might need more data in future, like a `ballotSpec` param.

#### DEPRECATED

* `export OFFSET='1'` -- this is just used to allow us to create more than one stack in parallel for dev purposes (by changing offset)
* `./manage --offset $OFFSET deploy --watch --step 0 voting-dev` -- the `--step N` param allows us to incrementally deploy, which is useful for testing and getting the stack to a state that makes subsequent deployments faster.
* `./manage --offset $OFFSET deploy --watch --use-existing --step 1 voting-dev`
* `./manage --offset $OFFSET deploy --watch --use-existing --step 2 voting-dev`
* `./manage --offset $OFFSET deploy --watch --use-existing voting-dev` -- `--step N` can be omitted for a full deploy; at the time of writing there are only 3 steps available.

## Developing

* `cnf-lint stack/**/*.yaml` -- cfn-lint is installed as a python dep (and github action)
* `./manage deploy-ns [path/to/template.yaml] [stack_name]` will deploy a nested stack only (useful when testing stacks that are late in the CFN deployment process)

### Adding pypi packages to lambda functions

The target you specify must be one of:

* `cr` -- installs in `stack/cr/common`
* `members` -- `stack/app/members`
* `app` -- `stack/app/common`

Run `./manage pip TARGET pkg1 pkg2 pkg3 ...` - this will install dependencies and update requirements.txt

## license

Deciding on the default license for the repo is a WIP. Some files are licensed under apache (inherited from AWS templates I've altered). Suggestions welcome. See issue #1
