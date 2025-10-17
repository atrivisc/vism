TODO:
1. Log to file and console 

Acme.sh command

install:
./acme.sh --install  \
--home /data/acme.sh/ \
--config-home /data/acme.sh/data \
--cert-home  /data/acme.sh/certs/ \
--accountemail  "my@example.com" \
--no-profile

standalone:
./acme.sh --standalone \
--listen-v6 \
--always-force-new-domain-key \
--ecc \
--httpport 80 \
--server http://127.0.0.1:8080/directory \
--issue -d example.com -d www.example.com