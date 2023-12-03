Every 90 days these certificates expire. The upstream project/container will refresh its certs occasionally, and we
can sync them here.

```bash
docker pull cirrusid/simplesamlphp:latest
docker run -v $PWD:/opt/tmp/certs cirrusid/simplesamlphp /bin/bash -c 'cp /etc/ssl/certs/${APACHE_CERT_NAME}.key /opt/tmp/certs/default.crt &&  cp /etc/ssl/private/${APACHE_CERT_NAME}.key /opt/tmp/certs/default.key && openssl x509 -noout -enddate -in /opt/tmp/certs/default.crt > /opt/tmp/certs/expiration'
```

The file `expiration` will get updated with the current expiration date of the certificates.
