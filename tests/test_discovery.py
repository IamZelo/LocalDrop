import unittest

from secure_share.protocol import SERVICE_TYPE


class DiscoveryTests(unittest.TestCase):
    def test_dns_sd_service_label_fits_protocol_limit(self):
        label = SERVICE_TYPE.split(".", 1)[0].removeprefix("_")
        self.assertLessEqual(len(label.encode("utf-8")), 15)


if __name__ == "__main__":
    unittest.main()
