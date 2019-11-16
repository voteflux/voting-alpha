# voting-alpha

Repo for storing all the resources for the Stack.

Contents:

- `/ethereum` - smart contracts, etc
- `/stack` - AWS CloudFormation stack resources

## Website and Livestream

https://flux.vote

## deps

`sudo apt install python3 python3-pip zip git build-essential && pip install boto3 click`

To install python deps for lambdas:

```bash
for pkg in cr members app; do
   ./manage pip $pkg;
done
```

## manager

> **WARNING:** The `./manage` util will use your default AWS .credentials or AWS_PROFILE if present. You'll also need `export AWS_DEFAULT_REGION=ap-southeast-2` if region isn't specified in your .credentials.

run ./manage for cli commands

### Env Vars

* S3_DEV_BUCKET=<a public bucket>
* TEST_SUBDOMAIN=<just the subdomain>
* VOTING_DOMAIN=<the domain hosted zone you have in route53; subdomains are okay>

### Deployment Pre-reqs

* `./manage deploy-macros` first
* asdf

## license

Deciding on the default license for the repo is a WIP. Some files are licensed under apache (inherited from AWS templates I've altered). Suggestions welcome. See issue #1
