# prometheus-certificate-exporter

Prometheus exporter for x509 certificates. Requires python >= 3.5.

```
usage: main.py [-h] --path PATH --certificate-suffix CERTIFICATE_SUFFIX
               [--certificate-exclude-regex CERTIFICATE_EXCLUDE_REGEX]
               [--log-level LOG_LEVEL] [--port PORT]

optional arguments:
  -h, --help            show this help message and exit
  --path PATH           Path in which to look for certificates. If it's a
                        directory will look for files inside it. If it's a
                        file it will check it ignoring filename suffix
                        matching and exclusion (files are not constrained by
                        --certificate-suffix and --certificate-exclude-regex
                        options)
  --certificate-suffix CERTIFICATE_SUFFIX
                        Suffix to match against, when looking for certificates
  --certificate-exclude-regex CERTIFICATE_EXCLUDE_REGEX
                        Regex to match against cert names. Matching filenames
                        will be ignored. Optional.
  --log-level LOG_LEVEL
                        Set the logging level. Defaults to INFO.
  --port PORT           Port the exporter will listen on.
```

Exported metrics:
- `ssl_certificate_begin_validity_timestamp`: timestamp on which the certificate will begin to be valid,
expressed in seconds from epoch (January 1, 1970).
    * `path`: the path at which the certificate the metric refers to is.
    * `issuer`: the signer CA name.
    * `subjects`: the semicolon-separated list of all the DNS names whose usage is allowed by the cert.
- `ssl_certificate_end_validity_timestamp`: timestamp on which the certificate will cease to be valid,
expressed in seconds from epoch (January 1, 1970, 00:00). Labels are the same as
`ssl_certificate_begin_validity_timestamp`.
- `certificateexporter_load_error`: one . Labels:
    * `path`: the path at which the certificate the metric refers to is.



##### Requirements

This application depends on the following python libraries:
- `cryptography`
- `prometheus_client`

These requirements may be satisfied in any of the following ways:
- By using pip: `pip install -r requirements.txt`.
- If you're running ubuntu/debian, you can use the distro-provided
 packages: `apt install -y python3-cryptography python3-prometheus-client`. (see FAQ)
- Using other means, like venvs, manual installations, etc.

The application can then be launched by running `main.py`.



### F.A.Q.

###### I installed the distro-provided packages, but importing the packages fails with `ImportError: No module named 'python_client'`

It's possible that your distribution's installation path (e.g. `/usr/lib/python3/dist-packages` on debian-stretch)
is not included in the `sys.path` of your running python's  instance. This is for example the case of official
python docker images.

If that path is missing, you can enable its inclusion by setting the `PYTHONPATH` environment variable:
`PYTHONPATH=/usr/lib/python3/dist-packages ./main.py`



### Future work

- Build docker image
