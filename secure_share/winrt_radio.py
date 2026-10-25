from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import socket
import threading
import uuid
from typing import Callable

COMPANY_ID = 0xFFFF
MAGIC = b"LSS1"
CUSTOM_OUI = bytes((0xFA, 0xCE, 0x01))
IE_PROPERTY = "System.Devices.WiFiDirect.InformationElements"
CONTROL_SERVICE_UUID = uuid.UUID("68b12e50-6f7d-4d91-9f8a-c64f2bd24a10")
METADATA_CHARACTERISTIC_UUID = uuid.UUID("68b12e51-6f7d-4d91-9f8a-c64f2bd24a10")
logger = logging.getLogger("secure_share.radio.winrt")


def _encode_hostname(name: str) -> bytes:
    """Fit common Windows hostnames into the remaining legacy BLE payload."""
    upper = name.upper()
    for marker, prefix in ((b"D", "DESKTOP-"), (b"L", "LAPTOP-")):
        if upper.startswith(prefix):
            return marker + upper[len(prefix):].encode("ascii", errors="ignore")[:9]
    return b"N" + name.encode("ascii", errors="ignore")[:9]


def _decode_hostname(value: bytes) -> str | None:
    if not value:
        return None
    text = value[1:].decode("ascii", errors="ignore")
    if value[:1] == b"D":
        return f"DESKTOP-{text}"
    if value[:1] == b"L":
        return f"LAPTOP-{text}"
    return text or None

REQUIRED_MODULES = (
    "winrt.runtime",
    "winrt.windows.devices.bluetooth.advertisement",
    "winrt.windows.devices.bluetooth.genericattributeprofile",
    "winrt.windows.devices.enumeration",
    "winrt.windows.devices.wifidirect",
    "winrt.windows.foundation.collections",
    "winrt.windows.security.cryptography",
)


def available() -> bool:
    return not missing_modules()


def missing_modules() -> list[str]:
    missing = []
    for module in REQUIRED_MODULES:
        try:
            __import__(module)
        except (ImportError, ModuleNotFoundError):
            missing.append(module)
    return missing


class PythonWinRTRadio:
    """In-process Windows BLE discovery and Wi-Fi Direct control via PyWinRT."""

    def __init__(self, device_id: str, port: int, on_event: Callable[[dict], None]):
        self.device_id = device_id
        self.on_event = on_event
        self.port = port
        self.loop: asyncio.AbstractEventLoop | None = None
        self.stop_event: asyncio.Event | None = None
        self.ready = threading.Event()
        self.started = False
        self.start_error: str | None = None
        self.thread: threading.Thread | None = None
        self.publisher = None
        self.watcher = None
        self.gatt_provider = None
        self.gatt_characteristic = None
        self.bluetooth_connections: dict[int, object] = {}
        self.wifi_publisher = None
        self.wifi_listener = None
        self.wifi_watcher = None
        self.wifi_scan_devices: dict[str, object] = {}
        self.wifi_scan_matches: set[str] = set()
        self.connections: dict[str, object] = {}
        self.event_tokens: list[tuple[object, str, object]] = []
        self.token = hashlib.sha256(device_id.encode() + os.urandom(32)).digest()[:8]

    @property
    def supported(self) -> bool:
        return available()

    def start(self) -> bool:
        if not self.supported:
            logger.error("Python WinRT cannot start; missing modules: %s", ", ".join(missing_modules()))
            return False
        logger.info("Starting in-process Python WinRT radio backend")
        self.thread = threading.Thread(target=self._thread_main, daemon=True, name="python-winrt-radio")
        self.thread.start()
        self.ready.wait(8)
        return self.started

    def _thread_main(self) -> None:
        try:
            asyncio.run(self._main())
        except Exception as exc:
            logger.exception("Python WinRT radio thread crashed")
            self.start_error = str(exc)
            self.on_event({"event": "fatal", "message": f"Python WinRT radio failed: {exc}"})
            self.ready.set()

    async def _main(self) -> None:
        self.loop = asyncio.get_running_loop()
        self.stop_event = asyncio.Event()
        await self._start_gatt_control()
        self._start_bluetooth()
        logger.info("Bluetooth LE GATT advertiser and watcher started")
        self._start_wifi_direct()
        logger.info("Wi-Fi Direct publisher and connection listener started")
        self.started = True
        self.ready.set()
        self.on_event({"event": "ready", "bluetooth": True, "wifi_direct": True, "implementation": "python-winrt"})
        await self.stop_event.wait()
        self._stop_radios()

    async def _start_gatt_control(self) -> None:
        from winrt.windows.devices.bluetooth.genericattributeprofile import (
            GattCharacteristicProperties,
            GattLocalCharacteristicParameters,
            GattProtectionLevel,
            GattServiceProvider,
            GattServiceProviderAdvertisingParameters,
        )

        result = await GattServiceProvider.create_async(CONTROL_SERVICE_UUID)
        if result.error.name != "SUCCESS" or result.service_provider is None:
            raise RuntimeError(f"Could not create Bluetooth control service: {result.error.name}")

        metadata = json.dumps(
            {
                "version": 1,
                "name": socket.gethostname(),
                "device_id": self.device_id,
                "port": self.port,
                "wifi_token": self.token.hex().upper(),
            },
            separators=(",", ":"),
        ).encode("utf-8")
        parameters = GattLocalCharacteristicParameters()
        parameters.characteristic_properties = GattCharacteristicProperties.READ
        parameters.read_protection_level = GattProtectionLevel.ENCRYPTION_REQUIRED
        parameters.static_value = self._buffer(metadata)
        characteristic_result = await result.service_provider.service.create_characteristic_async(
            METADATA_CHARACTERISTIC_UUID, parameters
        )
        if characteristic_result.error.name != "SUCCESS" or characteristic_result.characteristic is None:
            raise RuntimeError(f"Could not create Bluetooth metadata characteristic: {characteristic_result.error.name}")

        advertising = GattServiceProviderAdvertisingParameters()
        advertising.is_connectable = True
        advertising.is_discoverable = True
        advertising.service_data = self._buffer(_encode_hostname(socket.gethostname()))
        self.gatt_provider = result.service_provider
        self.gatt_characteristic = characteristic_result.characteristic
        status_token = self.gatt_provider.add_advertisement_status_changed(
            lambda _sender, args: self.on_event(
                {"event": "bluetooth_status", "status": args.status.name, "error": args.error.name}
            )
        )
        self._remember_event(self.gatt_provider, "advertisement_status_changed", status_token)
        self.gatt_provider.start_advertising_with_parameters(advertising)
        logger.info("Encrypted Bluetooth GATT control service started")

    @staticmethod
    def _buffer(data: bytes):
        from winrt.windows.security.cryptography import CryptographicBuffer

        return CryptographicBuffer.create_from_byte_array(data)

    @staticmethod
    def _bytes(buffer) -> bytes:
        try:
            return bytes(buffer)
        except TypeError:
            from winrt.windows.security.cryptography import CryptographicBuffer

            return bytes(CryptographicBuffer.copy_to_byte_array(buffer))

    def _remember_event(self, owner, event: str, token) -> None:
        self.event_tokens.append((owner, event, token))

    def _start_bluetooth(self) -> None:
        from winrt.windows.devices.bluetooth.advertisement import (
            BluetoothLEAdvertisementWatcher,
            BluetoothLEScanningMode,
        )

        self.watcher = BluetoothLEAdvertisementWatcher()
        self.watcher.scanning_mode = BluetoothLEScanningMode.ACTIVE
        token = self.watcher.add_received(self._ble_received)
        self._remember_event(self.watcher, "received", token)
        token = self.watcher.add_stopped(
            lambda _sender, args: self.on_event({"event": "bluetooth_stopped", "error": args.error.name})
        )
        self._remember_event(self.watcher, "stopped", token)
        self.watcher.start()

    def _ble_received(self, _sender, args) -> None:
        try:
            from winrt.windows.devices.bluetooth.advertisement import BluetoothLEAdvertisementDataTypes

            advertisement = args.advertisement
            if CONTROL_SERVICE_UUID not in advertisement.service_uuids:
                return
            rssi = args.raw_signal_strength_in_dbm
            name = advertisement.local_name or None
            for section in advertisement.get_sections_by_type(
                BluetoothLEAdvertisementDataTypes.SERVICE_DATA_128_BIT_UUIDS
            ):
                data = self._bytes(section.data)
                if len(data) >= 16 and uuid.UUID(bytes_le=data[:16]) == CONTROL_SERVICE_UUID:
                    name = _decode_hostname(data[16:]) or name
                    break
            address = f"{args.bluetooth_address:012X}"
            self.on_event(
                {
                    "event": "ble_peer",
                    "address": address,
                    # Before the encrypted metadata read, the Bluetooth
                    # address is the stable identifier for this discovery.
                    "token": address,
                    "version": 1,
                    "rssi": rssi,
                    "name": name,
                }
            )
            logger.debug("BLE app peer %s at %s dBm", address, rssi)
        except Exception:
            # WinRT invokes this callback outside the asyncio task. Never let a
            # bad advertisement escape into the projection's event dispatcher.
            logger.exception("Could not process a Bluetooth LE advertisement")

    def pair_bluetooth(self, address: str, expected_token: str) -> None:
        self._schedule(self._pair_bluetooth(address, expected_token), "bluetooth_pairing_error")

    async def _pair_bluetooth(self, address: str, expected_token: str) -> None:
        from winrt.windows.devices.bluetooth import BluetoothCacheMode, BluetoothLEDevice
        from winrt.windows.devices.bluetooth.genericattributeprofile import GattCommunicationStatus
        from winrt.windows.devices.enumeration import DevicePairingKinds, DevicePairingProtectionLevel

        if expected_token != address:
            raise RuntimeError("Bluetooth discovery identity changed before pairing")
        numeric_address = int(address, 16)
        self.on_event({"event": "bluetooth_pairing_started", "address": address})
        device = await BluetoothLEDevice.from_bluetooth_address_async(numeric_address)
        if device is None:
            raise RuntimeError("The Bluetooth device is no longer available")
        self.bluetooth_connections[numeric_address] = device

        pairing = device.device_information.pairing
        if not pairing.is_paired:
            if not pairing.can_pair:
                raise RuntimeError("Windows reports that this Bluetooth device cannot be paired")
            custom = pairing.custom

            def pairing_requested(_sender, args) -> None:
                logger.info("Windows Bluetooth pairing ceremony: %s", args.pairing_kind.name)
                if args.pairing_kind == DevicePairingKinds.CONFIRM_ONLY:
                    args.accept()

            event_token = custom.add_pairing_requested(pairing_requested)
            try:
                result = await custom.pair_with_protection_level_async(
                    DevicePairingKinds.CONFIRM_ONLY,
                    DevicePairingProtectionLevel.ENCRYPTION,
                )
            finally:
                custom.remove_pairing_requested(event_token)
            if result.status.name not in {"PAIRED", "ALREADY_PAIRED"}:
                raise RuntimeError(f"Bluetooth pairing failed: {result.status.name}")

        services = await device.get_gatt_services_for_uuid_with_cache_mode_async(
            CONTROL_SERVICE_UUID, BluetoothCacheMode.UNCACHED
        )
        if services.status != GattCommunicationStatus.SUCCESS or not services.services:
            raise RuntimeError(f"Bluetooth metadata service unavailable: {services.status.name}")
        service = services.services[0]
        characteristics = await service.get_characteristics_for_uuid_with_cache_mode_async(
            METADATA_CHARACTERISTIC_UUID, BluetoothCacheMode.UNCACHED
        )
        if characteristics.status != GattCommunicationStatus.SUCCESS or not characteristics.characteristics:
            service.close()
            raise RuntimeError(f"Bluetooth metadata characteristic unavailable: {characteristics.status.name}")
        read = await characteristics.characteristics[0].read_value_with_cache_mode_async(BluetoothCacheMode.UNCACHED)
        service.close()
        if read.status != GattCommunicationStatus.SUCCESS:
            raise RuntimeError(f"Could not read Bluetooth metadata: {read.status.name}")

        try:
            metadata = json.loads(self._bytes(read.value).decode("utf-8"))
            token = str(metadata["wifi_token"]).upper()
            if len(token) != 16 or any(character not in "0123456789ABCDEF" for character in token):
                raise ValueError("Invalid Wi-Fi correlation token")
            if int(metadata["port"]) not in range(1, 65536):
                raise ValueError("Invalid transfer port")
            if not str(metadata["device_id"]) or not str(metadata["name"]):
                raise ValueError("Incomplete identity")
        except (KeyError, TypeError, ValueError, UnicodeError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"Invalid Bluetooth metadata: {exc}") from exc

        self.on_event(
            {
                "event": "bluetooth_paired",
                "address": address,
                "token": token,
                "name": str(metadata["name"]),
                "device_id": str(metadata["device_id"]),
                "port": int(metadata["port"]),
            }
        )

    def _start_wifi_direct(self) -> None:
        from winrt.windows.devices.wifidirect import (
            WiFiDirectAdvertisementListenStateDiscoverability,
            WiFiDirectAdvertisementPublisher,
            WiFiDirectConnectionListener,
            WiFiDirectInformationElement,
        )

        self.wifi_publisher = WiFiDirectAdvertisementPublisher()
        advertisement = self.wifi_publisher.advertisement
        advertisement.listen_state_discoverability = WiFiDirectAdvertisementListenStateDiscoverability.INTENSIVE
        advertisement.is_autonomous_group_owner_enabled = True
        element = WiFiDirectInformationElement()
        element.oui = self._buffer(CUSTOM_OUI)
        element.oui_type = 1
        identity = self.device_id.encode("utf-8")
        if len(identity) > 64:
            raise ValueError("device identity is too long for Wi-Fi Direct discovery")
        element.value = self._buffer(MAGIC + self.token + self.port.to_bytes(2, "big") + bytes((len(identity),)) + identity)
        advertisement.information_elements.append(element)
        token = self.wifi_publisher.add_status_changed(
            lambda _sender, args: self.on_event(
                {"event": "wifi_direct_status", "status": args.status.name, "error": args.error.name}
            )
        )
        self._remember_event(self.wifi_publisher, "status_changed", token)

        self.wifi_listener = WiFiDirectConnectionListener()
        token = self.wifi_listener.add_connection_requested(self._connection_requested)
        self._remember_event(self.wifi_listener, "connection_requested", token)
        self.wifi_publisher.start()

    def _connection_requested(self, _sender, args) -> None:
        request = args.get_connection_request()
        assert self.loop
        self.loop.call_soon_threadsafe(lambda: asyncio.create_task(self._approve_incoming_request(request)))

    async def _approve_incoming_request(self, request) -> None:
        decision = threading.Event()
        event = {
            "event": "wifi_direct_connection_request",
            "name": request.device_information.name or "Nearby device",
            "accepted": False,
            "_decision": decision,
        }
        self.on_event(event)
        decided = await asyncio.to_thread(decision.wait, 30)
        if not decided or not event["accepted"]:
            logger.info("Incoming Wi-Fi Direct request was declined or timed out")
            request.close()
            return
        await self._accept_request(request)

    async def _pair_for_wifi_direct(self, information):
        from winrt.windows.devices.enumeration import DevicePairingKinds, DevicePairingProtectionLevel
        from winrt.windows.devices.wifidirect import WiFiDirectConfigurationMethod, WiFiDirectConnectionParameters

        parameters = WiFiDirectConnectionParameters()
        parameters.preference_ordered_configuration_methods.append(WiFiDirectConfigurationMethod.PUSH_BUTTON)
        pairing = information.pairing
        if pairing.is_paired:
            return parameters
        if not pairing.can_pair:
            logger.warning("Endpoint says it cannot pair; attempting Wi-Fi Direct connection anyway")
            return parameters

        custom = pairing.custom
        kinds = WiFiDirectConnectionParameters.get_device_pairing_kinds(WiFiDirectConfigurationMethod.PUSH_BUTTON)

        def pairing_requested(_sender, args) -> None:
            logger.info("Windows Wi-Fi Direct pairing ceremony: %s", args.pairing_kind.name)
            if args.pairing_kind == DevicePairingKinds.CONFIRM_ONLY:
                args.accept()

        event_token = custom.add_pairing_requested(pairing_requested)
        try:
            result = await custom.pair_with_protection_level_and_settings_async(
                kinds, DevicePairingProtectionLevel.DEFAULT, parameters
            )
            if result.status.name not in {"PAIRED", "ALREADY_PAIRED"}:
                # Windows sometimes reports FAILED even though the P2P link was
                # created. FromIdAsync is the authoritative connection attempt.
                logger.warning("Windows pairing returned %s; attempting the connection anyway", result.status.name)
                self.on_event({"event": "wifi_direct_pairing_warning", "status": result.status.name})
        finally:
            custom.remove_pairing_requested(event_token)
        return parameters

    async def _accept_request(self, request) -> None:
        from winrt.windows.devices.wifidirect import WiFiDirectDevice

        try:
            parameters = await self._pair_for_wifi_direct(request.device_information)
            device = await WiFiDirectDevice.from_id_async(request.device_information.id, parameters)
            self._track_connection(device, request.device_information.name)
        except Exception as exc:
            logger.exception("Incoming Wi-Fi Direct request failed")
            self.on_event({"event": "wifi_direct_error", "message": str(exc)})
        finally:
            request.close()

    def scan_wifi_direct(self) -> None:
        self._schedule(self._scan_wifi_direct())

    async def _scan_wifi_direct(self) -> None:
        from winrt.windows.devices.enumeration import DeviceInformation
        from winrt.windows.devices.wifidirect import WiFiDirectDevice, WiFiDirectDeviceSelectorType

        if self.wifi_watcher is not None:
            self.on_event({"event": "wifi_direct_scan_complete", "count": len(self.wifi_scan_matches)})
            return
        selector = WiFiDirectDevice.get_device_selector(WiFiDirectDeviceSelectorType.ASSOCIATION_ENDPOINT)
        self.wifi_watcher = DeviceInformation.create_watcher_aqs_filter_and_additional_properties(
            selector, [IE_PROPERTY]
        )
        token = self.wifi_watcher.add_added(self._wifi_device_added)
        self._remember_event(self.wifi_watcher, "added", token)
        token = self.wifi_watcher.add_updated(self._wifi_device_updated)
        self._remember_event(self.wifi_watcher, "updated", token)
        token = self.wifi_watcher.add_removed(self._wifi_device_removed)
        self._remember_event(self.wifi_watcher, "removed", token)
        token = self.wifi_watcher.add_enumeration_completed(self._wifi_enumeration_completed)
        self._remember_event(self.wifi_watcher, "enumeration_completed", token)
        self.wifi_watcher.start()
        logger.info("On-demand Wi-Fi Direct watcher started")

    def _wifi_device_added(self, _sender, device) -> None:
        self.wifi_scan_devices[device.id] = device
        self._process_wifi_device(device)

    def _wifi_device_updated(self, _sender, update) -> None:
        device = self.wifi_scan_devices.get(update.id)
        if device is None:
            return
        device.update(update)
        self._process_wifi_device(device)

    def _wifi_device_removed(self, _sender, update) -> None:
        self.wifi_scan_devices.pop(update.id, None)
        self.wifi_scan_matches.discard(update.id)

    def _wifi_enumeration_completed(self, _sender, _args) -> None:
        count = len(self.wifi_scan_matches)
        self.on_event({"event": "wifi_direct_scan_complete", "count": count})
        logger.info(
            "Wi-Fi Direct watcher initial enumeration completed: %d endpoint(s), %d app match(es)",
            len(self.wifi_scan_devices), count,
        )

    def _process_wifi_device(self, device) -> None:
        from winrt.windows.devices.wifidirect import WiFiDirectInformationElement

        try:
            peer_token = None
            for element in WiFiDirectInformationElement.create_from_device_information(device):
                value = self._bytes(element.value)
                if element.oui_type == 1 and self._bytes(element.oui) == CUSTOM_OUI and len(value) >= 15 and value.startswith(MAGIC):
                    peer_token = value[4:12].hex().upper()
                    port = int.from_bytes(value[12:14], "big")
                    identity_length = value[14]
                    if len(value) != 15 + identity_length:
                        peer_token = None
                        continue
                    device_id = value[15:].decode("utf-8", errors="strict")
                    break
            if peer_token:
                self.wifi_scan_matches.add(device.id)
                self.on_event(
                    {"event": "wifi_direct_peer", "id": device.id, "name": device.name,
                     "paired": device.pairing.is_paired, "token": peer_token,
                     "port": port, "device_id": device_id}
                )
        except Exception:
            logger.exception("Could not inspect Wi-Fi Direct endpoint %s", getattr(device, "id", "unknown"))

    def connect_wifi_direct(self, device_id: str) -> None:
        self._schedule(self._connect_wifi_direct(device_id))

    async def _connect_wifi_direct(self, device_id: str) -> None:
        from winrt.windows.devices.enumeration import DeviceInformation
        from winrt.windows.devices.wifidirect import WiFiDirectDevice

        try:
            if self.wifi_watcher is not None:
                try:
                    self.wifi_watcher.stop()
                except Exception:
                    pass
            information = await DeviceInformation.create_from_id_async(device_id)
            parameters = await self._pair_for_wifi_direct(information)
            device = await WiFiDirectDevice.from_id_async(device_id, parameters)
            self._track_connection(device, information.name)
        except Exception as exc:
            logger.exception("Outgoing Wi-Fi Direct connection failed")
            self.on_event({"event": "wifi_direct_error", "message": str(exc)})

    def _track_connection(self, device, name: str) -> None:
        logger.info("Wi-Fi Direct connected to %s (%s)", name, device.device_id)
        self.connections[device.device_id] = device
        token = device.add_connection_status_changed(
            lambda sender, _args: self.on_event(
                {"event": "wifi_direct_connection_status", "id": sender.device_id, "status": sender.connection_status.name}
            )
        )
        self._remember_event(device, "connection_status_changed", token)
        for endpoint in device.get_connection_endpoint_pairs():
            self.on_event(
                {"event": "wifi_direct_connected", "id": device.device_id, "name": name,
                 "local_address": endpoint.local_host_name.canonical_name,
                 "remote_address": endpoint.remote_host_name.canonical_name}
            )

    def _schedule(self, coroutine, error_event: str = "wifi_direct_error") -> None:
        if not self.started or not self.loop:
            coroutine.close()
            raise RuntimeError(self.start_error or "Python WinRT radio is not running")
        future = asyncio.run_coroutine_threadsafe(coroutine, self.loop)
        future.add_done_callback(lambda completed: self._command_done(completed, error_event))

    def _command_done(self, future, error_event: str) -> None:
        try:
            future.result()
        except Exception as exc:
            logger.exception("Radio command failed", exc_info=exc)
            self.on_event({"event": error_event, "message": str(exc)})

    def _stop_radios(self) -> None:
        for owner, event, token in reversed(self.event_tokens):
            try:
                getattr(owner, f"remove_{event}")(token)
            except Exception:
                pass
        self.event_tokens.clear()
        for radio in (self.wifi_watcher, self.watcher, self.publisher, self.wifi_publisher):
            try:
                radio.stop()
            except Exception:
                pass
        for device in self.connections.values():
            try:
                device.close()
            except Exception:
                pass
        self.connections.clear()
        for device in self.bluetooth_connections.values():
            try:
                device.close()
            except Exception:
                pass
        self.bluetooth_connections.clear()
        if self.gatt_provider is not None:
            try:
                self.gatt_provider.stop_advertising()
            except Exception:
                pass

    def close(self) -> None:
        logger.info("Stopping Python WinRT radio backend")
        if self.loop and self.stop_event:
            self.loop.call_soon_threadsafe(self.stop_event.set)
        if self.thread:
            self.thread.join(timeout=4)
        self.started = False
