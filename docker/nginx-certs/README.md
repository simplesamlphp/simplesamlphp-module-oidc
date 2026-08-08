# Certificates

`docker-compose.yml` mounts this directory into the `nginx-proxy` container and
selects the key pair with `CERT_NAME=default`, so serving the OP over HTTPS at
`op.local.stack-dev.cirrusidentity.com` needs a `default.crt` / `default.key`
pair here.

Those two files are **not** kept in Git. Generate them, together with the OIDC
module signing key pair in `../ssp`, before starting the stack:

```bash
./docker/generate-dev-certs.sh
```

The script leaves existing files alone; pass `--force` to replace them, for
example once the certificate expires. It needs `openssl` 1.1.1 or newer on
`PATH`.

The generated certificate is self-signed, so a browser will warn the first time
you open the local OP. Nothing in the Docker stack or in the conformance test
run verifies it. If you would rather not click through the warning, generate a
locally trusted certificate instead — [mkcert](https://github.com/FiloSottile/mkcert)
can issue one for `*.local.stack-dev.cirrusidentity.com` and write it here under
the same two filenames.

## Previously committed certificates

Until v7 this directory held a tracked private key alongside a Let's Encrypt
wildcard certificate for `*.local.stack-dev.cirrusidentity.com`. That key is
still reachable through the Git history and through released v6 archives, so it
must be treated as compromised and never reused. The certificate itself expired
on 2025-12-31.
