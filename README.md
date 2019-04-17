# certificate-exporter

Prometheus exporter for x509 certificates.

Sample exported metrics:

```
# HELP ssl_certificate_expiry_seconds Number of seconds until certificate expires
# TYPE ssl_certificate_expiry_seconds gauge
ssl_certificate_begin_validity_timestamp{issuer="COMODO RSA Domain Validation Secure Server CA",path="/etc/ssl/private/example.com.pem",subjects="example.com;example2.com"} 3.6944887453493947e+08
```


##### Deploying

You can satisfy the required dependencies by using `pip install -r requirements.txt`, or if you're running ubuntu/debian, by installing the following:
```
python3-cryptography
python3-prometheus-client
```

You can then clone this repo, and run `main.py`.
