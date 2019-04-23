import os
import unittest
import pathlib
import time

import prometheus_client

from certificateexporter import certificate

CERTS_DIR = os.path.join(os.path.dirname(__file__), './certificates/certs')
CERTS_SUFFIXES = [".pem"]

# Schema:
# test_results[metric_name][certificate_name] = is_metric_gt_current_time
test_base_results = {
    "ssl_certificate_begin_validity_timestamp": {
        "valid.pem": False,
        "expired.pem": False,
        "still-not-valid.pem": True
    },
    "ssl_certificate_end_validity_timestamp": {
        "valid.pem": True,
        "expired.pem": False,
        "still-not-valid.pem": True
    },
}


class TestExporter(unittest.TestCase):

    @staticmethod
    def __get_certname_by_sample_path(sample_path: str):
        return pathlib.Path(sample_path).name

    def __check_metric(self, metric):
        for sample in list(metric.samples):
            now = time.time()
            certname = TestExporter. \
                __get_certname_by_sample_path(sample.labels['path'])
            self.assertEqual(
                sample.value > now,
                test_base_results[metric.name][certname]
            )

    def test_base_behaviour(self):
        cert_handler = certificate.SslCertificateExpiryHandler(
                ["tests/certificates/certs"], [".pem"]
            )
        registry = prometheus_client.core.REGISTRY
        registry.register(cert_handler)
        try:
            ssl_certificate_begin_validity_timestamp_found = False
            ssl_certificate_end_validity_timestamp_found = False
            for metric in registry.collect():
                if metric.name == "ssl_certificate_begin_validity_timestamp":
                    ssl_certificate_begin_validity_timestamp_found = True
                    self.__check_metric(metric)
                elif metric.name == "ssl_certificate_end_validity_timestamp":
                    ssl_certificate_end_validity_timestamp_found = True
                    self.__check_metric(metric)
            self.assertEqual(
                ssl_certificate_begin_validity_timestamp_found, True)
            self.assertEqual(
                ssl_certificate_end_validity_timestamp_found, True)
        finally:
            registry.unregister(cert_handler)

    def test_multiple_suffixes(self):
        cert_handler = certificate.SslCertificateExpiryHandler(
                ["tests/certificates/certs"], ["valid.pem", "expired.pem"]
            )
        registry = prometheus_client.core.REGISTRY
        registry.register(cert_handler)
        try:
            certnames_found = {
                "valid.pem": False,
                "still-not-valid.pem": False,
                "expired.pem": False
            }
            for metric in registry.collect():
                if metric.name == "ssl_certificate_begin_validity_timestamp":
                    for sample in list(metric.samples):
                        certname = TestExporter.__get_certname_by_sample_path(
                            sample.labels['path'])
                        self.assertEqual(certname in certnames_found, True)
                        certnames_found[certname] = True
            for certname in certnames_found:
                self.assertEqual(certnames_found[certname], True)
        finally:
            registry.unregister(cert_handler)

    def test_multiple_paths(self):
        cert_handler = certificate.SslCertificateExpiryHandler(
                ["tests/certificates/certs", "tests/certificates/certs_copy"],
                ["expired.pem"]
            )
        registry = prometheus_client.core.REGISTRY
        registry.register(cert_handler)
        try:
            suffixes_found = {
                "certs/expired.pem": False,
                "certs_copy/expired.pem": False
            }
            for metric in registry.collect():
                if metric.name == "ssl_certificate_begin_validity_timestamp":
                    for sample in list(metric.samples):
                        for suffix in suffixes_found:
                            if sample.labels['path'].endswith(suffix):
                                suffixes_found[suffix] = True
            for suffix in suffixes_found:
                self.assertEqual(suffixes_found[suffix], True)
        finally:
            registry.unregister(cert_handler)

    def test_invalid_cert(self):
        cert_handler = certificate.SslCertificateExpiryHandler(
                ["tests/certificates/certs_invalid"],
                [".pem"]
            )
        registry = prometheus_client.core.REGISTRY
        registry.register(cert_handler)
        try:
            certificateexporter_load_error_found = False
            for metric in registry.collect():
                if metric.name == "certificateexporter_load_error":
                    certificateexporter_load_error_found = True
                    certname = TestExporter.__get_certname_by_sample_path(
                        metric.samples[0].labels['path'])
                    self.assertEqual(certname, "not-a-cert.pem")
            self.assertEqual(certificateexporter_load_error_found, True)
        finally:
            registry.unregister(cert_handler)
