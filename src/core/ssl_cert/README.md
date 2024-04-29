# Command

From [this blog post](https://tcoil.info/secure-flask-app-with-self-signed-ssl-certificate-flask-https/)

- Generate the key pair with the `openssl` utility:

```bash
openssl req -x509 -newkey rsa:4096 -nodes -out cert.pem -keyout priv_key.pem -days 3650
```

> Note: `-days 3650` means this certificate is valid within 10 years.