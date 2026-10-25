from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import platform
import socket
import sys
import threading
import time
import traceback
import uuid
from typing import Callable

MAGIC = b"LSS1"
CUSTOM_OUI = bytes((0xFA, 0xCE, 0x01))
IE_PROPERTY = "System.Devices.WiFiDirect.InformationElements"
CONTROL_SERVICE_UUID = uuid.UUID("68b12e50-6f7d-4d91-9f8a-c64f2bd24a10")
METADATA_CHARACTERISTIC_UUID = uuid.UUID("68b12e51-6f7d-4d91-9f8a-c64f2bd24a10")
logger = logging.getLogger("secure_share.radio.winrt")


PAIRING_STATUS_HELP = {
    "ACCESS_DENIED": "Windows denied Bluetooth pairing access. Check Bluetooth permissions and run the app normally, not elevated.",
    "AUTHENTICATION_FAILURE": "The devices could not authenticate each other. Remove any stale Windows Bluetooth association on both laptops and retry.",
    "OPERATION_ALREADY_IN_PROGRESS": "Windows is already pairing or unpairing this device. Wait for that operation to finish.",
    "PAIRING_CANCELED": "The Windows Bluetooth consent prompt was cancelled or timed out.",
    "PROTECTION_LEVEL_COULD_NOT_BE_MET": "The peer or Bluetooth adapter could not provide the required encrypted pairing protection.",
    "REMOTE_DEVICE_HAS_ASSOCIATION": "The peer has a stale Bluetooth association. Remove the device from Bluetooth settings on both laptops.",
    "REQUIRED_HANDLER_NOT_REGISTERED": "Windows requested a pairing ceremony for which no handler was registered.",
    "REJECTED_BY_HANDLER": "The Bluetooth pairing request was rejected by a pairing handler.",
}


class RadioOperationError(RuntimeError):
    def __init__(self, phase: str, message: str, *, status: str | None = None):
        super().__init__(message)
        self.phase = phase
        self.status = status


def _enum_name(value: object) -> str:
    return str(getattr(value, "name", value))


def _pairing_failure_message(status: str) -> str:
    detail = PAIRING_STATUS_HELP.get(status, "Windows returned an unspecified Bluetooth pairing failure.")
    return f"Bluetooth pairing failed: {status}. {detail}"


def _exception_event(error_event: str, exc: BaseException, attempt_id: str | None = None) -> dict:
    raw_hresult = getattr(exc, "hresult", getattr(exc, "winerror", None))
    if isinstance(raw_hresult, int):
        hresult = f"0x{raw_hresult & 0xFFFFFFFF:08X} ({raw_hresult})"
    else:
        hresult = None
    return {
        "event": error_event,
        "message": str(exc) or repr(exc),
        "phase": getattr(exc, "phase", "unknown"),
        "status": getattr(exc, "status", None),
        "exception_type": type(exc).__name__,
        "hresult": hresult,
        "traceback": "".join(traceback.format_exception(type(exc), exc, exc.__traceback__)),
        "attempt_id": attempt_id,
    }


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
    "winrt.windows.devices.bluetooth",
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
        self.started = False
        self.start_error: str | None = None
        self.main_task: asyncio.Task | None = None
        self.stopped = False
        self.watcher = None
        self.gatt_provider = None
        self.gatt_characteristic = None
        self.metadata = b""
        self.bluetooth_connections: dict[str, object] = {}
        self.ble_resolving: set[tuple[int, str]] = set()
        self.ble_peers: dict[tuple[int, str], dict] = {}
        self.ble_last_emitted: dict[tuple[int, str], float] = {}
        self.active_pairing_attempt: str | None = None
        self.pairing_future = None
        self.wifi_publisher = None
        self.wifi_group_owner = False
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
        try:
            self.loop = asyncio.get_event_loop()
        except RuntimeError:
            self.start_error = "The Qt asyncio event loop has not been installed"
            logger.exception("Python WinRT startup requires the Qt asyncio event loop")
            return False
        if self.loop.is_closed():
            self.start_error = "The Qt asyncio event loop is closed"
            return False
        logger.info("Starting in-process Python WinRT radio backend on the UI event loop")
        self.main_task = self.loop.create_task(self._run_main(), name="python-winrt-radio")
        return True

    async def _run_main(self) -> None:
        try:
            await self._main()
        except Exception as exc:
            logger.exception("Python WinRT radio task crashed")
            self.start_error = str(exc)
            event = _exception_event("fatal", exc)
            event["message"] = f"Python WinRT radio failed: {event['message']}"
            self.on_event(event)
        finally:
            self._stop_radios()

    async def _main(self) -> None:
        self.loop = asyncio.get_running_loop()
        self.stop_event = asyncio.Event()
        logger.info(
            "Radio diagnostics: Windows=%s Python=%s thread=%s",
            platform.platform(), sys.version.replace("\n", " "), threading.current_thread().name,
        )
        await self._log_bluetooth_adapter()
        await self._start_gatt_control()
        self._start_bluetooth()
        logger.info("Bluetooth LE GATT advertiser and watcher started")
        self.started = True
        self.on_event({"event": "ready", "bluetooth": True, "wifi_direct": False, "implementation": "python-winrt"})
        await self.stop_event.wait()

    async def _log_bluetooth_adapter(self) -> None:
        from winrt.windows.devices.bluetooth import BluetoothAdapter

        adapter = await BluetoothAdapter.get_default_async()
        if adapter is None:
            raise RadioOperationError("adapter_check", "Windows did not return a default Bluetooth adapter")
        logger.info(
            "Bluetooth adapter id=%s address=%012X low_energy=%s central=%s peripheral=%s "
            "secure_connections=%s extended_advertising=%s max_advertisement=%s",
            adapter.device_id, int(adapter.bluetooth_address), adapter.is_low_energy_supported,
            adapter.is_central_role_supported, adapter.is_peripheral_role_supported,
            adapter.are_low_energy_secure_connections_supported,
            adapter.is_extended_advertising_supported, adapter.max_advertisement_data_length,
        )
        if not adapter.is_low_energy_supported:
            raise RadioOperationError("adapter_check", "The Bluetooth adapter does not support Bluetooth Low Energy")
        if not adapter.is_peripheral_role_supported:
            raise RadioOperationError(
                "adapter_check", "The Bluetooth adapter cannot advertise the required connectable GATT service"
            )

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
            status = _enum_name(result.error)
            raise RadioOperationError(
                "gatt_server_create", f"Could not create Bluetooth control service: {status}", status=status
            )

        self.metadata = json.dumps(
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
        characteristic_result = await result.service_provider.service.create_characteristic_async(
            METADATA_CHARACTERISTIC_UUID, parameters
        )
        if characteristic_result.error.name != "SUCCESS" or characteristic_result.characteristic is None:
            status = _enum_name(characteristic_result.error)
            raise RadioOperationError(
                "gatt_characteristic_create",
                f"Could not create Bluetooth metadata characteristic: {status}",
                status=status,
            )

        advertising = GattServiceProviderAdvertisingParameters()
        advertising.is_connectable = True
        advertising.is_discoverable = True
        advertising.service_data = self._buffer(_encode_hostname(socket.gethostname()))
        self.gatt_provider = result.service_provider
        self.gatt_characteristic = characteristic_result.characteristic
        read_token = self.gatt_characteristic.add_read_requested(self._metadata_read_requested)
        self._remember_event(self.gatt_characteristic, "read_requested", read_token)
        status_token = self.gatt_provider.add_advertisement_status_changed(
            self._bluetooth_advertisement_status_changed
        )
        self._remember_event(self.gatt_provider, "advertisement_status_changed", status_token)
        self.gatt_provider.start_advertising_with_parameters(advertising)
        logger.info("Encrypted Bluetooth GATT control service started")

    def _bluetooth_advertisement_status_changed(self, _sender, args) -> None:
        status = _enum_name(args.status)
        error = _enum_name(args.error)
        logger.info("Bluetooth GATT advertisement status=%s error=%s", status, error)
        self.on_event({"event": "bluetooth_status", "status": status, "error": error})

    def _metadata_read_requested(self, _sender, args) -> None:
        if not self.loop:
            return
        deferral = args.get_deferral()
        self.loop.call_soon_threadsafe(
            lambda: asyncio.create_task(self._serve_metadata_read(args, deferral))
        )

    async def _serve_metadata_read(self, args, deferral) -> None:
        try:
            logger.info("Encrypted Bluetooth metadata read requested by a peer")
            request = await args.get_request_async()
            if request is None:
                raise RadioOperationError(
                    "gatt_server_read", "Windows denied access to the incoming Bluetooth metadata read"
                )
            # The metadata-serving/receiving side owns the temporary group;
            # the sender joins it after receiving the metadata response.
            self._ensure_wifi_direct_started("encrypted Bluetooth metadata request", prefer_group_owner=True)
            request.respond_with_value(self._buffer(self.metadata))
            self.on_event({"event": "bluetooth_metadata_received"})
            logger.info("Encrypted Bluetooth metadata returned; Wi-Fi Direct is now available")
        except Exception as exc:
            logger.exception("Incoming encrypted Bluetooth metadata read failed")
            self.on_event(_exception_event("bluetooth_pairing_error", exc))
        finally:
            deferral.complete()

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
            service_data_type = getattr(
                BluetoothLEAdvertisementDataTypes,
                "service_data128_bit_uuids",
                None,
            )
            if service_data_type is None:
                # Compatibility with projections that expose enum-like names.
                service_data_type = getattr(
                    BluetoothLEAdvertisementDataTypes,
                    "SERVICE_DATA_128_BIT_UUIDS",
                    None,
                )
            sections = (
                advertisement.get_sections_by_type(service_data_type)
                if service_data_type is not None
                else ()
            )
            for section in sections:
                data = self._bytes(section.data)
                if len(data) >= 16 and uuid.UUID(bytes_le=data[:16]) == CONTROL_SERVICE_UUID:
                    name = _decode_hostname(data[16:]) or name
                    break
                # Some Bluetooth stacks expose only the service-data payload;
                # the service UUID is already present in advertisement.service_uuids.
                name = _decode_hostname(data) or name
            address = f"{args.bluetooth_address:012X}"
            address_type_value = args.bluetooth_address_type
            address_type = _enum_name(address_type_value)
            key = (int(args.bluetooth_address), address_type)
            peer = self.ble_peers.get(key)
            if peer is not None:
                peer.update({"rssi": rssi, "name": peer.get("name") or name})
                now = time.monotonic()
                if now - self.ble_last_emitted.get(key, 0.0) < 10.0:
                    return
                self.ble_last_emitted[key] = now
                self.on_event(dict(peer))
                return
            if key in self.ble_resolving:
                return
            self.ble_resolving.add(key)
            discovered = {
                "event": "ble_peer",
                "address": address,
                "address_type": address_type,
                "token": address,
                "version": 1,
                "rssi": rssi,
                "name": name,
                "connectable": bool(args.is_connectable),
            }
            assert self.loop
            self.loop.call_soon_threadsafe(
                lambda k=key, at=address_type_value, d=discovered: asyncio.create_task(
                    self._resolve_ble_peer(k, at, d)
                )
            )
        except Exception:
            # WinRT invokes this callback outside the asyncio task. Never let a
            # bad advertisement escape into the projection's event dispatcher.
            logger.exception("Could not process a Bluetooth LE advertisement")

    async def _resolve_ble_peer(self, key: tuple[int, str], address_type, discovered: dict) -> None:
        from winrt.windows.devices.bluetooth import BluetoothLEDevice

        started = time.monotonic()
        try:
            logger.info(
                "Resolving Bluetooth association endpoint address=%s type=%s rssi=%s connectable=%s",
                discovered["address"], discovered["address_type"], discovered["rssi"], discovered["connectable"],
            )
            device = await BluetoothLEDevice.from_bluetooth_address_with_bluetooth_address_type_async(
                key[0], address_type
            )
            if device is None:
                raise RadioOperationError(
                    "ble_endpoint_resolution",
                    "Windows could not resolve the discovered Bluetooth advertisement to a device endpoint",
                )
            information = device.device_information
            pairing = information.pairing
            peer = {
                **discovered,
                "token": information.id,
                "device_id": information.id,
                "name": device.name or information.name or discovered.get("name"),
                "can_pair": bool(pairing.can_pair),
                "is_paired": bool(pairing.is_paired),
                "protection_level": _enum_name(pairing.protection_level),
                "access_status": _enum_name(device.device_access_information.current_status),
            }
            self.ble_peers[key] = peer
            self.ble_last_emitted[key] = time.monotonic()
            logger.info(
                "Resolved Bluetooth peer id=%s name=%r can_pair=%s is_paired=%s protection=%s access=%s elapsed=%.3fs",
                information.id, peer["name"], peer["can_pair"], peer["is_paired"],
                peer["protection_level"], peer["access_status"], time.monotonic() - started,
            )
            self.on_event(dict(peer))
            device.close()
        except Exception as exc:
            logger.exception(
                "Bluetooth endpoint resolution failed for address=%s type=%s",
                discovered.get("address"), discovered.get("address_type"),
            )
            self.on_event(_exception_event("bluetooth_discovery_error", exc))
        finally:
            self.ble_resolving.discard(key)

    def pair_bluetooth(self, device_id: str, address: str, address_type: str) -> None:
        if self.active_pairing_attempt:
            raise RuntimeError(f"Bluetooth pairing attempt {self.active_pairing_attempt} is already running")
        attempt_id = uuid.uuid4().hex[:8].upper()
        self.active_pairing_attempt = attempt_id
        try:
            self.pairing_future = self._schedule(
                self._pair_bluetooth_with_cleanup(device_id, address, address_type, attempt_id),
                "bluetooth_pairing_error",
                attempt_id,
            )
        except Exception:
            self.active_pairing_attempt = None
            raise

    def cancel_bluetooth_pairing(self) -> None:
        future = self.pairing_future
        if future is not None and not future.done():
            logger.warning("Cancelling Bluetooth pairing attempt=%s after application timeout", self.active_pairing_attempt)
            future.cancel()

    async def _pair_bluetooth_with_cleanup(
        self, device_id: str, address: str, address_type: str, attempt_id: str
    ) -> None:
        try:
            await self._pair_bluetooth(device_id, address, address_type, attempt_id)
        finally:
            if self.active_pairing_attempt == attempt_id:
                self.active_pairing_attempt = None
                self.pairing_future = None

    async def _pair_bluetooth(
        self, device_id: str, address: str, address_type: str, attempt_id: str
    ) -> None:
        from winrt.windows.devices.bluetooth import BluetoothCacheMode, BluetoothLEDevice
        from winrt.windows.devices.bluetooth.genericattributeprofile import GattCommunicationStatus
        from winrt.windows.devices.enumeration import DevicePairingKinds, DevicePairingProtectionLevel

        started = time.monotonic()
        numeric_address = int(address, 16)
        logger.info(
            "[%s] Bluetooth pairing start device_id=%s address=%s address_type=%s thread=%s",
            attempt_id, device_id, address, address_type, threading.current_thread().name,
        )
        self.on_event(
            {
                "event": "bluetooth_pairing_started",
                "attempt_id": attempt_id,
                "device_id": device_id,
                "address": address,
                "address_type": address_type,
            }
        )
        logger.info("[%s] Opening BluetoothLEDevice from canonical endpoint id on the UI thread", attempt_id)
        device = await BluetoothLEDevice.from_id_async(device_id)
        if device is None:
            raise RadioOperationError("device_open", "The Bluetooth device is no longer available")
        if int(device.bluetooth_address) != numeric_address:
            logger.warning(
                "[%s] BLE address rotated after discovery expected=%s current=%012X; canonical device id remains authoritative",
                attempt_id, address, int(device.bluetooth_address),
            )
        actual_address_type = _enum_name(device.bluetooth_address_type)
        if actual_address_type != address_type:
            logger.warning(
                "[%s] BLE address type changed after discovery expected=%s current=%s; canonical device id remains authoritative",
                attempt_id, address_type, actual_address_type,
            )
        previous_device = self.bluetooth_connections.get(device_id)
        if previous_device is not None and previous_device is not device:
            try:
                previous_device.close()
            except Exception:
                logger.debug("[%s] Previous discovery device handle was already closed", attempt_id)
        self.bluetooth_connections[device_id] = device

        pairing = device.device_information.pairing
        logger.info(
            "[%s] Endpoint name=%r can_pair=%s is_paired=%s protection=%s access=%s connection=%s",
            attempt_id, device.name, pairing.can_pair, pairing.is_paired,
            _enum_name(pairing.protection_level),
            _enum_name(device.device_access_information.current_status),
            _enum_name(device.connection_status),
        )
        if not pairing.is_paired:
            if not pairing.can_pair:
                raise RadioOperationError(
                    "pairing_precheck", "Windows reports that this Bluetooth association endpoint cannot be paired"
                )
            custom = pairing.custom
            ceremony_seen = False

            def pairing_requested(_sender, args) -> None:
                nonlocal ceremony_seen
                ceremony_seen = True
                ceremony = _enum_name(args.pairing_kind)
                pin = getattr(args, "pin", None)
                logger.info(
                    "[%s] Windows Bluetooth PairingRequested ceremony=%s pin=%r",
                    attempt_id, ceremony, pin,
                )
                self.on_event(
                    {
                        "event": "bluetooth_pairing_ceremony",
                        "attempt_id": attempt_id,
                        "ceremony": ceremony,
                        "pin": pin,
                    }
                )
                if args.pairing_kind == DevicePairingKinds.CONFIRM_ONLY:
                    args.accept()
                    logger.info("[%s] ConfirmOnly ceremony accepted; waiting for Windows consent UI", attempt_id)
                else:
                    logger.error("[%s] Unsupported Bluetooth pairing ceremony=%s", attempt_id, ceremony)

            event_token = custom.add_pairing_requested(pairing_requested)
            try:
                logger.info(
                    "[%s] Calling custom PairAsync kinds=CONFIRM_ONLY minimum_protection=ENCRYPTION",
                    attempt_id,
                )
                result = await custom.pair_with_protection_level_async(
                    DevicePairingKinds.CONFIRM_ONLY,
                    DevicePairingProtectionLevel.ENCRYPTION,
                )
            finally:
                custom.remove_pairing_requested(event_token)
            result_status = _enum_name(result.status)
            protection_used = _enum_name(getattr(result, "protection_level_used", "unknown"))
            logger.info(
                "[%s] Windows Bluetooth pairing completed status=%s protection_used=%s ceremony_seen=%s elapsed=%.3fs",
                attempt_id, result_status, protection_used, ceremony_seen, time.monotonic() - started,
            )
            if result_status not in {"PAIRED", "ALREADY_PAIRED"}:
                raise RadioOperationError(
                    "windows_pairing", _pairing_failure_message(result_status), status=result_status
                )
        else:
            logger.info("[%s] Endpoint is already paired; continuing to encrypted metadata", attempt_id)

        phase_started = time.monotonic()
        logger.info("[%s] Discovering uncached encrypted GATT metadata service", attempt_id)
        services = await device.get_gatt_services_for_uuid_with_cache_mode_async(
            CONTROL_SERVICE_UUID, BluetoothCacheMode.UNCACHED
        )
        if services.status != GattCommunicationStatus.SUCCESS or not services.services:
            status = _enum_name(services.status)
            raise RadioOperationError(
                "gatt_service_discovery", f"Bluetooth metadata service unavailable: {status}", status=status
            )
        service = services.services[0]
        try:
            characteristics = await service.get_characteristics_for_uuid_with_cache_mode_async(
                METADATA_CHARACTERISTIC_UUID, BluetoothCacheMode.UNCACHED
            )
            if characteristics.status != GattCommunicationStatus.SUCCESS or not characteristics.characteristics:
                status = _enum_name(characteristics.status)
                raise RadioOperationError(
                    "gatt_characteristic_discovery",
                    f"Bluetooth metadata characteristic unavailable: {status}",
                    status=status,
                )
            logger.info("[%s] Reading encryption-required Bluetooth metadata", attempt_id)
            read = await characteristics.characteristics[0].read_value_with_cache_mode_async(BluetoothCacheMode.UNCACHED)
        finally:
            for characteristic in (characteristics.characteristics or []):
                try:
                    characteristic.close()
                except Exception:
                    pass
            service.close()
        if read.status != GattCommunicationStatus.SUCCESS:
            status = _enum_name(read.status)
            raise RadioOperationError(
                "gatt_metadata_read", f"Could not read encrypted Bluetooth metadata: {status}", status=status
            )
        logger.info(
            "[%s] Encrypted Bluetooth metadata read succeeded in %.3fs secure_connection=%s",
            attempt_id, time.monotonic() - phase_started,
            getattr(device, "was_secure_connection_used_for_pairing", "unknown"),
        )

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
            raise RadioOperationError("gatt_metadata_validation", f"Invalid Bluetooth metadata: {exc}") from exc

        self._ensure_wifi_direct_started(
            "successful encrypted Bluetooth pairing and metadata read", prefer_group_owner=False
        )

        self.on_event(
            {
                "event": "bluetooth_paired",
                "attempt_id": attempt_id,
                "address": address,
                "address_type": address_type,
                "token": token,
                "name": str(metadata["name"]),
                "device_id": str(metadata["device_id"]),
                "port": int(metadata["port"]),
            }
        )
        logger.info("[%s] Bluetooth-first phase complete in %.3fs", attempt_id, time.monotonic() - started)

    def _ensure_wifi_direct_started(self, reason: str, *, prefer_group_owner: bool) -> None:
        if self.wifi_publisher is not None:
            return
        self.wifi_group_owner = prefer_group_owner
        logger.info("Starting Wi-Fi Direct after %s prefer_group_owner=%s", reason, prefer_group_owner)
        self.on_event(
            {"event": "wifi_direct_starting", "reason": reason, "prefer_group_owner": prefer_group_owner}
        )
        try:
            self._start_wifi_direct()
        except Exception as exc:
            raise RadioOperationError("wifi_direct_startup", f"Could not start Wi-Fi Direct: {exc}") from exc
        logger.info("Wi-Fi Direct publisher and connection listener started")

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
        advertisement.is_autonomous_group_owner_enabled = self.wifi_group_owner
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
        try:
            request = args.get_connection_request()
            information = request.device_information
            logger.info(
                "Incoming Wi-Fi Direct connection request id=%s name=%r paired=%s can_pair=%s",
                information.id, information.name, information.pairing.is_paired, information.pairing.can_pair,
            )
            assert self.loop
            self.loop.call_soon_threadsafe(
                lambda: asyncio.create_task(self._approve_incoming_request(request))
            )
        except Exception as exc:
            logger.exception("Could not open incoming Wi-Fi Direct connection request")
            event = _exception_event("wifi_direct_error", exc)
            event["phase"] = "wifi_direct_request"
            self.on_event(event)

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
        logger.info("Incoming Wi-Fi Direct request accepted by the user")
        await self._accept_request(request)

    @staticmethod
    def _wifi_connection_parameters():
        from winrt.windows.devices.wifidirect import WiFiDirectConfigurationMethod, WiFiDirectConnectionParameters

        parameters = WiFiDirectConnectionParameters()
        parameters.preference_ordered_configuration_methods.append(WiFiDirectConfigurationMethod.PUSH_BUTTON)
        return parameters

    async def _accept_request(self, request) -> None:
        from winrt.windows.devices.wifidirect import WiFiDirectDevice

        try:
            information = request.device_information
            parameters = self._wifi_connection_parameters()
            logger.info(
                "Accepting Wi-Fi Direct endpoint with FromIdAsync id=%s name=%r",
                information.id, information.name,
            )
            device = await WiFiDirectDevice.from_id_async(request.device_information.id, parameters)
            if device is None:
                raise RadioOperationError(
                    "wifi_direct_accept", "Windows returned no Wi-Fi Direct device for the accepted request"
                )
            self._track_connection(device, request.device_information.name)
        except Exception as exc:
            logger.exception("Incoming Wi-Fi Direct request failed")
            event = _exception_event("wifi_direct_error", exc)
            event["phase"] = "wifi_direct_accept"
            self.on_event(event)
        finally:
            request.close()

    def scan_wifi_direct(self) -> None:
        if self.wifi_publisher is None:
            raise RuntimeError("Wi-Fi Direct is locked until encrypted Bluetooth pairing succeeds")
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
        logger.info(
            "Wi-Fi Direct endpoint discovered id=%s name=%r paired=%s can_pair=%s",
            device.id, device.name, device.pairing.is_paired, device.pairing.can_pair,
        )
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
            elements = WiFiDirectInformationElement.create_from_device_information(device)
            logger.debug("Inspecting %d information element(s) for Wi-Fi Direct endpoint %s", len(elements), device.id)
            for element in elements:
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
                logger.info(
                    "Matched app Wi-Fi Direct endpoint id=%s name=%r token=%s port=%s device_id=%s",
                    device.id, device.name, peer_token, port, device_id,
                )
                self.on_event(
                    {"event": "wifi_direct_peer", "id": device.id, "name": device.name,
                     "paired": device.pairing.is_paired, "token": peer_token,
                     "port": port, "device_id": device_id}
                )
            else:
                logger.debug("Wi-Fi Direct endpoint %s did not contain the app information element", device.id)
        except Exception:
            logger.exception("Could not inspect Wi-Fi Direct endpoint %s", getattr(device, "id", "unknown"))

    def connect_wifi_direct(self, device_id: str) -> None:
        if self.wifi_publisher is None:
            raise RuntimeError("Wi-Fi Direct is locked until encrypted Bluetooth pairing succeeds")
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
            if information is None:
                raise RadioOperationError(
                    "wifi_direct_connect", "The selected Wi-Fi Direct endpoint disappeared before connection"
                )
            logger.info(
                "Starting Wi-Fi Direct FromIdAsync id=%s name=%r paired=%s can_pair=%s",
                device_id, information.name, information.pairing.is_paired, information.pairing.can_pair,
            )
            parameters = self._wifi_connection_parameters()
            device = await WiFiDirectDevice.from_id_async(device_id, parameters)
            if device is None:
                raise RadioOperationError(
                    "wifi_direct_connect", "Windows returned no Wi-Fi Direct device for the selected endpoint"
                )
            self._track_connection(device, information.name)
        except Exception as exc:
            logger.exception("Outgoing Wi-Fi Direct connection failed")
            event = _exception_event("wifi_direct_error", exc)
            event["phase"] = "wifi_direct_connect"
            self.on_event(event)

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

    def _schedule(
        self, coroutine, error_event: str = "wifi_direct_error", attempt_id: str | None = None
    ):
        if not self.started or not self.loop:
            coroutine.close()
            raise RuntimeError(self.start_error or "Python WinRT radio is not running")
        try:
            running_loop = asyncio.get_running_loop()
        except RuntimeError:
            running_loop = None
        if self.loop is running_loop:
            future = self.loop.create_task(coroutine)
        else:
            future = asyncio.run_coroutine_threadsafe(coroutine, self.loop)
        future.add_done_callback(
            lambda completed: self._command_done(completed, error_event, attempt_id)
        )
        return future

    def _command_done(self, future, error_event: str, attempt_id: str | None = None) -> None:
        try:
            future.result()
        except asyncio.CancelledError:
            logger.info("Radio command was cancelled event=%s attempt=%s", error_event, attempt_id)
        except Exception as exc:
            logger.exception(
                "Radio command failed event=%s attempt=%s phase=%s status=%s type=%s hresult=%r",
                error_event, attempt_id, getattr(exc, "phase", "unknown"), getattr(exc, "status", None),
                type(exc).__name__, getattr(exc, "hresult", getattr(exc, "winerror", None)),
                exc_info=exc,
            )
            event = _exception_event(error_event, exc, attempt_id)
            logger.error("Structured radio failure: %s", event)
            self.on_event(event)

    def _stop_radios(self) -> None:
        if self.stopped:
            return
        self.stopped = True
        for owner, event, token in reversed(self.event_tokens):
            try:
                getattr(owner, f"remove_{event}")(token)
            except Exception:
                pass
        self.event_tokens.clear()
        for radio in (self.wifi_watcher, self.watcher, self.wifi_publisher):
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
            self.stop_event.set()
        self._stop_radios()
        self.started = False
