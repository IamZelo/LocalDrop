import unittest
import socket
import threading
from unittest.mock import Mock

from zeroconf import ServiceInfo

from secure_share.discovery import Discovery
from secure_share.protocol import SERVICE_TYPE


class DiscoveryTests(unittest.TestCase):
    def test_dns_sd_service_label_fits_protocol_limit(self):
        label = SERVICE_TYPE.split(".", 1)[0].removeprefix("_")
        self.assertLessEqual(len(label.encode("utf-8")), 15)

    def test_profile_rename_replaces_immutable_service_info(self):
        discovery = object.__new__(Discovery)
        discovery.device_id = "device-id"
        discovery.display_name = "Old Name"
        discovery.port = 43123
        discovery.public_key = "public-key"
        discovery.capabilities = frozenset({"lan"})
        discovery.instance = f"LocalSecureShare-device-id.{SERVICE_TYPE}"
        discovery.server = "computer.local."
        discovery.registration_lock = threading.Lock()
        discovery.zc = Mock()
        discovery.info = ServiceInfo(
            SERVICE_TYPE, discovery.instance, port=discovery.port,
            properties={"id": discovery.device_id, "name": "Old Name", "v": "1",
                        "key": discovery.public_key, "cap": "lan"},
            server=discovery.server, addresses=[socket.inet_aton("192.168.1.2")],
        )
        previous = discovery.info

        discovery.update_display_name("New Name")

        self.assertIsNot(discovery.info, previous)
        self.assertEqual(discovery.info.properties[b"name"], b"New Name")
        self.assertEqual(discovery.display_name, "New Name")
        discovery.zc.update_service.assert_called_once_with(discovery.info)


if __name__ == "__main__":
    unittest.main()
