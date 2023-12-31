#!/bin/sh

set -e

# Change porkbun_key and porkbun_secret to your api key and secret
porkbun_key="pk1_TODO_REPLACE_ME"
porkbun_secret="sk1_TODO_REPLACE_ME"

# This assumes the go compiled binary is called certbot-dns-porkbun and put in
# the same directory as the script, if that's not the case, change to the
# absolute path to the binary.
bin="$(dirname "$0")/certbot-dns-porkbun"

${bin} \
  --apikey="${porkbun_key}" \
  --secretapikey="${porkbun_secret}" \
  --domain="${CERTBOT_DOMAIN}" \
  --cleanup-id="${CERTBOT_AUTH_OUTPUT}"
