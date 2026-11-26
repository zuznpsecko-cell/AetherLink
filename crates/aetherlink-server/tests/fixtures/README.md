# Test fixtures — NOT secrets

`rsa_pkcs1_key.pem` / `rsa_pkcs1_cert.pem` are a throwaway, self-signed
RSA-2048 identity for `CN=localhost`, committed on purpose (the `.gitignore`
has a narrow exception for exactly these two files). They exist only because
rcgen with the ring backend cannot generate RSA keys, and DEC-024 needs a
regression test for a PKCS#1 key (`BEGIN RSA PRIVATE KEY`) in `tls_key`.

Used by `bind_accepts_a_pkcs1_rsa_private_key` in `../bind_serve.rs`. Never
deploy them anywhere. To regenerate (OpenSSL 3):

```sh
openssl req -x509 -newkey rsa:2048 -nodes -keyout k8.pem \
  -out rsa_pkcs1_cert.pem -days 36500 -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost"
openssl rsa -in k8.pem -traditional -out rsa_pkcs1_key.pem   # PKCS#1 armour
rm k8.pem
```
