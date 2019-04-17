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
test_results = {
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
            print(metric.name, sample.labels)
            print(sample.value, now, test_results[metric.name][certname])
            self.assertEqual(
                sample.value > now,
                test_results[metric.name][certname]
            )

    def test_exporter(self):
        cert_handler = certificate.SslCertificateExpiryHandler(
                ["tests/certificates/certs"], [".pem"]
            )
        registry = prometheus_client.core.REGISTRY
        registry.register(cert_handler)
        ssl_certificate_begin_validity_timestamp_found = False
        ssl_certificate_end_validity_timestamp_found = False
        for metric in registry.collect():
            if metric.name == "ssl_certificate_begin_validity_timestamp":
                ssl_certificate_begin_validity_timestamp_found = True
                self.__check_metric(metric)
            elif metric.name == "ssl_certificate_end_validity_timestamp":
                ssl_certificate_end_validity_timestamp_found = True
                self.__check_metric(metric)
        self.assertEqual(ssl_certificate_begin_validity_timestamp_found, True)
        self.assertEqual(ssl_certificate_end_validity_timestamp_found, True)
        registry.unregister(cert_handler)
