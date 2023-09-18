# certbot-dns-porkbun

[Porkbun][porkbun] [Certbot][certbot] DNS plugin in Go.

## Usage

Run go compiler to get the linux binary (requires go 1.21+):

```sh
GOOS=linux GOARCH=amd64 go build -trimpath .
```

Copy `certbot-dns-porkbun` along with the 2 bash scripts (`authenticator.sh` and
`clenaup.sh`) to the same directory of your server (I usually put them under
`/etc/letsencrypt/porkbun`)

Edit the shell scripts on your server and replace the porkbun api and secret
keys.

Run certbot with:

```
sudo certbot certonly \
  -n \
  --agree-tos \
  --email <your email> \
  --manual \
  --preferred-challenges=dns \
  --manual-auth-hook /path/to/authenticator.sh \
  --manual-cleanup-hook /path/to/cleanup.sh \
  -d yourdomain.com \
  -d *.yourdomain.com
```

[porkbun]: https://porkbun.com/
[certbot]: https://certbot.eff.org/
