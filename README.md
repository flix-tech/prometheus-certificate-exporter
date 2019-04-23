# certificate-exporter

Prometheus exporter for x509 certificates. Requires python3.5 (the default in debian stretch).

Sample exported metrics:

```
# HELP ssl_certificate_end_validity_timestamp End of certificate validity timestamp
# TYPE ssl_certificate_end_validity_timestamp gauge
ssl_certificate_end_validity_timestamp{issuer="COMODO RSA Domain Validation Secure Server CA",path="/etc/ssl/private/example.com.pem",subjects="example.com;example2.com"} 3.6944887453493947e+08
```


##### Deploying

You can satisfy the required dependencies by using `pip install -r requirements.txt`, or if you're running ubuntu/debian, by installing the following:
```
###
### IMPORTANT: ensure the `/usr/lib/python3/dist-packages` path is included
###            in python's `sys.path`, otherwise these cannot be imported.
### If that path is missing, as in e.g. python3.5's docker image, you can enable
### its inclusion by setting the env var: `PYTHONPATH=/usr/lib/python3/dist-packages`
###
python3-cryptography
python3-prometheus-client
```

You can then clone this repo, and run `main.py`.
