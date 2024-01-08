# Regenerating `jwk_cert.pem`

``` bash
openssl x509 -signkey jwk.pem -in jwk.csr -req -days 3650 -out jwk_cert.pem
```

