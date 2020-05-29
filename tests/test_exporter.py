import pathlib
import time
import unittest

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

    def __get_metrics(self, cert_handler):
        registry = prometheus_client.core.REGISTRY
        registry.register(cert_handler)
        self.__collectors_to_unregister.append(cert_handler)
        return registry.collect()

    def test_base_behaviour(self):
        # expected_test_results[metric_name][certificate_name] \
        #   = is_metric_greater_than_current_time
        subject = "test.flix.tech;10.0.0.1"
        subject_int_ca = "Test CA Intermediate"
        expected_test_results = {
            "ssl_certificate_begin_validity_timestamp": {
                ("valid.pem", subject): False,
                ("expired.pem", subject): False,
                ("still-not-valid.pem", subject): True,
                ("valid_bundle.pem", subject): False,
                ("valid_bundle.pem", subject_int_ca): False,
                ("expired_int_bundle.pem", subject): False,
                ("expired_int_bundle.pem", subject_int_ca): False
            },
            "ssl_certificate_end_validity_timestamp": {
                ("valid.pem", subject): True,
                ("expired.pem", subject): False,
                ("still-not-valid.pem", subject): True,
                ("valid_bundle.pem", subject): True,
                ("valid_bundle.pem", subject_int_ca): True,
                ("expired_int_bundle.pem", subject): True,
                ("expired_int_bundle.pem", subject_int_ca): False
            }
        }
        # Will contain tuples: (metric_name, certname)
        timeseries_found = set()
        cert_handler = certificate.SslCertificateExpiryHandler(
            ["tests/certificates/certs"],
            [".pem"]
        )
        now = time.time()
        for metric in self.__get_metrics(cert_handler):
            if metric.name in expected_test_results:
                for sample in list(metric.samples):
                    certname = TestExporter. \
                        __get_certname_by_sample_path(sample.labels['path'])
                    certsubjects = sample.labels['subjects']
                    metric_tuple = (metric.name, certname, certsubjects)
                    timeseries_found.add(metric_tuple)
                    self.assertEqual(
                        sample.value > now,
                        expected_test_results[metric.name][
                            (certname, certsubjects)]
                    )
        for metric_name in expected_test_results:
            for certname in expected_test_results[metric_name]:
                metric_tuple = (metric_name,)+certname
                self.assertTrue(metric_tuple in timeseries_found)

    def test_multiple_suffixes(self):
        certnames_yet_to_find = \
            {"valid.pem", "still-not-valid.pem", "expired.pem"}
        cert_handler = certificate.SslCertificateExpiryHandler(
            ["tests/certificates/certs"],
            ["valid.pem", "expired.pem"]
        )
        for metric in self.__get_metrics(cert_handler):
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
        for metric in self.__get_metrics(cert_handler):
            if metric.name == "ssl_certificate_begin_validity_timestamp":
                for sample in list(metric.samples):
                    certpath = sample.labels['path']
                    self.assertTrue(certpath in certpaths_yet_to_find)
                    certpaths_yet_to_find.remove(certpath)
        self.assertEqual(len(certpaths_yet_to_find), 0)

    def test_file_paths(self):
        certpaths_yet_to_find = {
            "tests/certificates/certs/expired.pem"
        }
        cert_handler = certificate.SslCertificateExpiryHandler(
            ["tests/certificates/certs/expired.pem"],
            [".crt"]
        )
        for metric in self.__get_metrics(cert_handler):
            if metric.name == "ssl_certificate_begin_validity_timestamp":
                for sample in list(metric.samples):
                    certpath = sample.labels['path']
                    self.assertTrue(certpath in certpaths_yet_to_find)
                    certpaths_yet_to_find.remove(certpath)
        self.assertEqual(len(certpaths_yet_to_find), 0)

    def test_fifo_path(self):
        cert_handler = certificate.SslCertificateExpiryHandler(
            ["tests/certificates/certs_invalid/fifo.pem"],
            [".crt"]
        )
        for metric in self.__get_metrics(cert_handler):
            if metric.name == "certificateexporter_load_error":
                certificateexporter_load_error_found = True
                certname = TestExporter.__get_certname_by_sample_path(
                    metric.samples[0].labels['path'])
                self.assertEqual(certname, "fifo.pem")
        self.assertEqual(certificateexporter_load_error_found, True)

    def test_non_existing_path(self):
        cert_handler = certificate.SslCertificateExpiryHandler(
            ["tests/certificates/certs_invalid/non_existing.pem"],
            [".crt"]
        )
        for metric in self.__get_metrics(cert_handler):
            if metric.name == "certificateexporter_load_error":
                certificateexporter_load_error_found = True
                certname = TestExporter.__get_certname_by_sample_path(
                    metric.samples[0].labels['path'])
                self.assertEqual(certname, "non_existing.pem")
        self.assertEqual(certificateexporter_load_error_found, True)

    def test_invalid_cert(self):
        certnames_yet_to_find = {
            "not-a-cert.pem",
            "fifo.pem",
        }
        cert_handler = certificate.SslCertificateExpiryHandler(
            ["tests/certificates/certs_invalid"],
            [".pem"]
        )
        certificateexporter_load_error_found = False
        for metric in self.__get_metrics(cert_handler):
            if metric.name == "certificateexporter_load_error":
                certificateexporter_load_error_found = True
                certname = TestExporter.__get_certname_by_sample_path(
                    metric.samples[0].labels['path'])
                self.assertTrue(certname in certnames_yet_to_find)
                certnames_yet_to_find.remove(certname)
        self.assertEqual(certificateexporter_load_error_found, True)

    def test_exclude_regex(self):
        certnames_yet_to_find = {"expired.pem", "valid.pem"}
        cert_handler = certificate.SslCertificateExpiryHandler(
            ["tests/certificates/certs"],
            [".pem"],
            "(bundle|still-not)"
        )
        for metric in self.__get_metrics(cert_handler):
            if metric.name == "ssl_certificate_begin_validity_timestamp":
                for sample in list(metric.samples):
                    certname = TestExporter.__get_certname_by_sample_path(
                        sample.labels['path'])
                    self.assertTrue(certname in certnames_yet_to_find)
                    certnames_yet_to_find.remove(certname)
        print(len(certnames_yet_to_find))
        self.assertEqual(len(certnames_yet_to_find), 0)

    def test_no_suffix(self):
        certnames_yet_to_find = {"not-a-cert.pem", "wrong.suffix"}
        cert_handler = certificate.SslCertificateExpiryHandler(
            ["tests/certificates/certs_invalid"],
            []
        )
        for metric in self.__get_metrics(cert_handler):
            if metric.name == "certificateexporter_load_error":
                for sample in list(metric.samples):
                    certname = TestExporter.__get_certname_by_sample_path(
                        sample.labels['path'])
                    self.assertTrue(certname in certnames_yet_to_find)
                    certnames_yet_to_find.remove(certname)
        self.assertEqual(len(certnames_yet_to_find), 0)
