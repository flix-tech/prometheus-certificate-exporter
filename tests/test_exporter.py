import unittest
import pathlib
import time

import prometheus_client

from certificateexporter import certificate


class TestExporter(unittest.TestCase):

    def setUp(self):
        self.__collectors_to_unregister = []

    def tearDown(self):
        registry = prometheus_client.core.REGISTRY
        for collector in self.__collectors_to_unregister:
            registry.unregister(collector)
        self.__collectors_to_unregister = []

    @staticmethod
    def __get_certname_by_sample_path(sample_path: str):
        return pathlib.Path(sample_path).name

    def test_base_behaviour(self):
        # expected_test_results[metric_name][certificate_name] \
        #   = is_metric_greater_than_current_time
        expected_test_results = {
            "ssl_certificate_begin_validity_timestamp": {
                "valid.pem": False,
                "expired.pem": False,
                "still-not-valid.pem": True
            },
            "ssl_certificate_end_validity_timestamp": {
                "valid.pem": True,
                "expired.pem": False,
                "still-not-valid.pem": True
            }
        }
        # Will contain tuples: (metric_name, certname)
        timeseries_found = set()
        cert_handler = certificate.SslCertificateExpiryHandler(
                ["tests/certificates/certs"],
                [".pem"]
            )
        registry = prometheus_client.core.REGISTRY
        registry.register(cert_handler)
        self.__collectors_to_unregister.append(cert_handler)
        now = time.time()
        for metric in registry.collect():
            if metric.name in expected_test_results:
                for sample in list(metric.samples):
                    certname = TestExporter. \
                        __get_certname_by_sample_path(sample.labels['path'])
                    metric_tuple = (metric.name, certname)
                    timeseries_found.add(metric_tuple)
                    self.assertEqual(
                        sample.value > now,
                        expected_test_results[metric.name][certname]
                    )
        for metric_name in expected_test_results:
            for certname in expected_test_results[metric_name]:
                metric_tuple = (metric_name, certname)
                self.assertTrue(metric_tuple in timeseries_found)

    def test_multiple_suffixes(self):
        certnames_yet_to_find = \
            {"valid.pem", "still-not-valid.pem", "expired.pem"}
        cert_handler = certificate.SslCertificateExpiryHandler(
                ["tests/certificates/certs"],
                ["valid.pem", "expired.pem"]
            )
        registry = prometheus_client.core.REGISTRY
        registry.register(cert_handler)
        self.__collectors_to_unregister.append(cert_handler)
        for metric in registry.collect():
            if metric.name == "ssl_certificate_begin_validity_timestamp":
                for sample in list(metric.samples):
                    certname = TestExporter.__get_certname_by_sample_path(
                        sample.labels['path'])
                    self.assertTrue(certname in certnames_yet_to_find)
                    certnames_yet_to_find.remove(certname)
        self.assertEqual(len(certnames_yet_to_find), 0)

    def test_multiple_paths(self):
        certpaths_yet_to_find = {
            "tests/certificates/certs/expired.pem",
            "tests/certificates/certs_copy/expired.pem"
        }
        cert_handler = certificate.SslCertificateExpiryHandler(
                ["tests/certificates/certs", "tests/certificates/certs_copy"],
                ["expired.pem"]
            )
        registry = prometheus_client.core.REGISTRY
        registry.register(cert_handler)
        self.__collectors_to_unregister.append(cert_handler)
        for metric in registry.collect():
            if metric.name == "ssl_certificate_begin_validity_timestamp":
                for sample in list(metric.samples):
                    certpath = sample.labels['path']
                    self.assertTrue(certpath in certpaths_yet_to_find)
                    certpaths_yet_to_find.remove(certpath)
        self.assertEqual(len(certpaths_yet_to_find), 0)

    def test_invalid_cert(self):
        cert_handler = certificate.SslCertificateExpiryHandler(
                ["tests/certificates/certs_invalid"],
                [".pem"]
            )
        registry = prometheus_client.core.REGISTRY
        registry.register(cert_handler)
        self.__collectors_to_unregister.append(cert_handler)
        certificateexporter_load_error_found = False
        for metric in registry.collect():
            if metric.name == "certificateexporter_load_error":
                certificateexporter_load_error_found = True
                certname = TestExporter.__get_certname_by_sample_path(
                    metric.samples[0].labels['path'])
                self.assertEqual(certname, "not-a-cert.pem")
        self.assertEqual(certificateexporter_load_error_found, True)
