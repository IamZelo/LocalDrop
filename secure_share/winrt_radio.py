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

from .identity import b64, unb64

MAGIC = b"LSS1"
CUSTOM_OUI = bytes((0xFA, 0xCE, 0x01))
IE_PROPERTY = "System.Devices.WiFiDirect.InformationElements"
CONTROL_SERVICE_UUID = uuid.UUID("68b12e50-6f7d-4d91-9f8a-c64f2bd24a10")
METADATA_CHARACTERISTIC_UUID = uuid.UUID("68b12e51-6f7d-4d91-9f8a-c64f2bd24a10")
logger = logging.getLogger("secure_share.radio.winrt")


class RadioOperationError(RuntimeError):
    def __init__(self, phase: str, message: str, *, status: str | None = None):
        super().__init__(message)
        self.phase = phase
        self.status = status


def _enum_name(value: object) -> str:
    return str(getattr(value, "name", value))


def _enum_member(enum_type, name: str):
    """Resolve enum names across PyWinRT projections that use lower/upper case."""
    for candidate in (name.lower(), name.upper(), name):
        value = getattr(enum_type, candidate, None)
        if value is not None:
            return value
    raise ValueError(f"Unsupported {enum_type.__name__} value: {name}")


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

    def __init__(
        self, device_id: str, port: int, on_event: Callable[[dict], None], public_key: str = ""
    ):
        self.device_id = device_id
        self.public_key = public_key
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
        self.bluetooth_sessions: dict[str, object] = {}
        self.ble_resolving: set[tuple[int, str]] = set()
        self.ble_peers: dict[tuple[int, str], dict] = {}
        self.ble_last_emitted: dict[tuple[int, str], float] = {}
        self.active_metadata_attempt: str | None = None
        self.metadata_future = None
        self.wifi_publisher = None
        self.wifi_group_owner = False
        self.wifi_listener = None
        self.wifi_watcher = None
        self.wifi_scan_devices: dict[str, object] = {}
        self.wifi_scan_matches: set[str] = set()
        self.connections: dict[str, object] = {}
        self.event_tokens: list[tuple[object, str, object]] = []
        self._wifi_direct_in_progress = False
        self._scanning = False
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
        wifi_ready = False
        try:
            self._start_wifi_direct()
            wifi_ready = True
            logger.info("Wi-Fi Direct publisher and connection listener started")
        except Exception as exc:
            logger.warning("Could not start Wi-Fi Direct at launch: %s", exc)
        self.started = True
        self.on_event({"event": "ready", "bluetooth": True, "wifi_direct": wifi_ready, "implementation": "python-winrt"})
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
                "public_key": self.public_key,
                "port": self.port,
                "wifi_token": self.token.hex().upper(),
            },
            separators=(",", ":"),
        ).encode("utf-8")
        parameters = GattLocalCharacteristicParameters()
        parameters.characteristic_properties = GattCharacteristicProperties.READ
        # This characteristic contains bootstrap data only. Durable identity
        # authentication still happens over TLS with the application's
        # short-code protocol after Wi-Fi Direct connects.
        parameters.read_protection_level = GattProtectionLevel.PLAIN
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
        # Do not attach service_data to GattServiceProviderAdvertisingParameters:
        # On standard 31-byte legacy Bluetooth LE controllers, 128-bit service data + 128-bit service UUID
        # exceeds the 31-byte limit, causing Windows to abort advertising with STARTED_WITHOUT_ALL_ADVERTISEMENT_DATA.
        # Hostnames are reliably discovered from Windows device enumeration (device.name).
        self.gatt_provider = result.service_provider
        self.gatt_characteristic = characteristic_result.characteristic
        read_token = self.gatt_characteristic.add_read_requested(self._metadata_read_requested)
        self._remember_event(self.gatt_characteristic, "read_requested", read_token)
        status_token = self.gatt_provider.add_advertisement_status_changed(
            self._bluetooth_advertisement_status_changed
        )
        self._remember_event(self.gatt_provider, "advertisement_status_changed", status_token)
        self.gatt_provider.start_advertising_with_parameters(advertising)
        logger.info("Bluetooth GATT bootstrap service started (OS pairing not required)")

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
            logger.info("Bluetooth bootstrap metadata read requested by a peer")
            request = await args.get_request_async()
            if request is None:
                raise RadioOperationError(
                    "gatt_server_read", "Windows denied access to the incoming Bluetooth metadata read"
                )
            request.respond_with_value(self._buffer(self.metadata))
            self.on_event({"event": "bluetooth_metadata_received"})
            logger.info("Bluetooth bootstrap metadata returned to the peer")
            # Respond before starting Wi-Fi Direct so radio reconfiguration cannot
            # delay the GATT response. The sender's Wi-Fi scan already retries.
            self._ensure_wifi_direct_started("Bluetooth bootstrap metadata request", prefer_group_owner=True)
            logger.info("Wi-Fi Direct is now available after the Bluetooth metadata response")
        except Exception as exc:
            logger.exception("Incoming Bluetooth bootstrap metadata read failed")
            self.on_event(_exception_event("bluetooth_metadata_error", exc))
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
                now = time.monotonic()
                peer.update({"rssi": rssi, "name": peer.get("name") or name, "seen_at": now})
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
                "seen_at": time.monotonic(),
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

    def prepare_bluetooth(self, device_id: str, address: str, address_type: str) -> None:
        if self.active_metadata_attempt:
            raise RuntimeError(f"Bluetooth metadata attempt {self.active_metadata_attempt} is already running")
        attempt_id = uuid.uuid4().hex[:8].upper()
        self.active_metadata_attempt = attempt_id
        try:
            self.metadata_future = self._schedule(
                self._prepare_bluetooth_with_cleanup(device_id, address, address_type, attempt_id),
                "bluetooth_metadata_error",
                attempt_id,
            )
        except Exception:
            self.active_metadata_attempt = None
            raise

    def cancel_bluetooth_preparation(self) -> None:
        future = self.metadata_future
        if future is not None and not future.done():
            logger.warning("Cancelling Bluetooth metadata attempt=%s after application timeout", self.active_metadata_attempt)
            future.cancel()

    async def _prepare_bluetooth_with_cleanup(
        self, device_id: str, address: str, address_type: str, attempt_id: str
    ) -> None:
        try:
            await self._prepare_bluetooth(device_id, address, address_type, attempt_id)
        finally:
            if self.active_metadata_attempt == attempt_id:
                self.active_metadata_attempt = None
                self.metadata_future = None

    async def _prepare_bluetooth(
        self, device_id: str, address: str, address_type: str, attempt_id: str
    ) -> None:
        from winrt.windows.devices.bluetooth import (
            BluetoothAddressType,
            BluetoothCacheMode,
            BluetoothLEDevice,
        )
        from winrt.windows.devices.bluetooth.genericattributeprofile import (
            GattCommunicationStatus,
            GattSession,
        )

        started = time.monotonic()
        requested_device_id = device_id
        requested_address = address
        requested_address_type = address_type
        selected_peer = next(
            (peer for peer in self.ble_peers.values() if peer.get("device_id") == device_id),
            None,
        )
        selected_name = str((selected_peer or {}).get("name") or "").strip().casefold()
        if selected_name:
            cutoff = time.monotonic() - 20.0
            aliases = [
                peer for peer in self.ble_peers.values()
                if str(peer.get("name") or "").strip().casefold() == selected_name
                and float(peer.get("seen_at", 0.0)) >= cutoff
                and peer.get("connectable", True)
            ]
            if aliases:
                preferred = max(
                    aliases,
                    key=lambda peer: (
                        bool(peer.get("is_paired")),
                        float(peer.get("seen_at", 0.0)),
                        int(peer.get("rssi", -999)),
                    ),
                )
                device_id = str(preferred.get("device_id") or preferred["token"])
                address = str(preferred["address"])
                address_type = str(preferred["address_type"])
                if address != requested_address:
                    logger.info(
                        "[%s] Selected alternate Windows BLE identity for %r requested=%s/%s "
                        "selected=%s/%s paired=%s rssi=%s aliases=%d",
                        attempt_id, preferred.get("name"), requested_address, requested_address_type,
                        address, address_type, preferred.get("is_paired"), preferred.get("rssi"), len(aliases),
                    )
        numeric_address = int(address, 16)
        logger.info(
            "[%s] Bluetooth metadata bootstrap start requested_device_id=%s selected_device_id=%s "
            "address=%s address_type=%s thread=%s",
            attempt_id, requested_device_id, device_id, address, address_type,
            threading.current_thread().name,
        )
        self.on_event(
            {
                "event": "bluetooth_metadata_started",
                "attempt_id": attempt_id,
                "device_id": device_id,
                "address": address,
                "address_type": address_type,
            }
        )
        address_type_value = _enum_member(BluetoothAddressType, address_type)
        logger.info(
            "[%s] Opening live BluetoothLEDevice address=%s type=%s on the UI thread",
            attempt_id, address, address_type,
        )
        device = await BluetoothLEDevice.from_bluetooth_address_with_bluetooth_address_type_async(
            numeric_address, address_type_value
        )
        if device is None:
            logger.warning(
                "[%s] Live-address open returned no device; falling back to canonical endpoint id=%s",
                attempt_id, device_id,
            )
            device = await BluetoothLEDevice.from_id_async(device_id)
        if device is None:
            raise RadioOperationError("device_open", "The Bluetooth device is no longer available")
        access_status = _enum_name(await device.request_access_async())
        logger.info("[%s] Bluetooth device access request returned %s", attempt_id, access_status)
        if access_status != "ALLOWED":
            raise RadioOperationError(
                "device_access",
                f"Windows denied access to the Bluetooth device: {access_status}",
                status=access_status,
            )
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
            "[%s] Endpoint name=%r can_pair=%s is_paired=%s protection=%s access=%s connection=%s; "
            "skipping persistent Windows Bluetooth pairing",
            attempt_id, device.name, pairing.can_pair, pairing.is_paired,
            _enum_name(pairing.protection_level),
            _enum_name(device.device_access_information.current_status),
            _enum_name(device.connection_status),
        )

        session = None
        try:
            session = await GattSession.from_device_id_async(device.bluetooth_device_id)
            if session is not None:
                if session.can_maintain_connection:
                    session.maintain_connection = True
                previous_session = self.bluetooth_sessions.get(device_id)
                if previous_session is not None and previous_session is not session:
                    previous_session.close()
                self.bluetooth_sessions[device_id] = session
                logger.info(
                    "[%s] GATT session status=%s can_maintain_connection=%s maintain_connection=%s",
                    attempt_id, _enum_name(session.session_status), session.can_maintain_connection,
                    session.maintain_connection,
                )
        except Exception:
            # Service discovery can still establish the link when GattSession is
            # unavailable on a particular Windows/PyWinRT combination.
            logger.exception("[%s] Could not create a maintained GATT session; continuing", attempt_id)

        phase_started = time.monotonic()
        services = None
        # Try cached service table first if the device was previously paired or connected
        if pairing.is_paired:
            try:
                cached_services = await device.get_gatt_services_for_uuid_with_cache_mode_async(
                    CONTROL_SERVICE_UUID, BluetoothCacheMode.CACHED
                )
                if cached_services.status == GattCommunicationStatus.SUCCESS and cached_services.services:
                    logger.info("[%s] Found cached GATT bootstrap service on paired device", attempt_id)
                    services = cached_services
            except Exception:
                pass

        if services is None or services.status != GattCommunicationStatus.SUCCESS or not services.services:
            for discovery_attempt in range(1, 4):
                logger.info(
                    "[%s] Discovering uncached Bluetooth bootstrap service attempt=%d/3 connection=%s",
                    attempt_id, discovery_attempt, _enum_name(device.connection_status),
                )
                services = await device.get_gatt_services_for_uuid_with_cache_mode_async(
                    CONTROL_SERVICE_UUID, BluetoothCacheMode.UNCACHED
                )
                status = _enum_name(services.status)
                logger.info(
                    "[%s] GATT service discovery attempt=%d status=%s services=%d connection=%s",
                    attempt_id, discovery_attempt, status, len(services.services or ()),
                    _enum_name(device.connection_status),
                )
                if services.status == GattCommunicationStatus.SUCCESS and services.services:
                    break
                if status != "UNREACHABLE" or discovery_attempt == 3:
                    break
                delay = 0.75 * discovery_attempt
                logger.warning(
                    "[%s] GATT peer is temporarily unreachable; keeping the session open and retrying in %.2fs",
                    attempt_id, delay,
                )
                await asyncio.sleep(delay)
        assert services is not None
        if services.status != GattCommunicationStatus.SUCCESS or not services.services:
            status = _enum_name(services.status)
            raise RadioOperationError(
                "gatt_service_discovery",
                f"Bluetooth metadata service unavailable after 3 attempts: {status}; "
                f"connection={_enum_name(device.connection_status)}",
                status=status,
            )
        service = services.services[0]
        characteristics = None
        try:
            for cache_mode in (BluetoothCacheMode.CACHED, BluetoothCacheMode.UNCACHED):
                try:
                    characteristics = await service.get_characteristics_for_uuid_with_cache_mode_async(
                        METADATA_CHARACTERISTIC_UUID, cache_mode
                    )
                    if characteristics.status == GattCommunicationStatus.SUCCESS and characteristics.characteristics:
                        break
                except Exception:
                    pass

            if characteristics is None or characteristics.status != GattCommunicationStatus.SUCCESS or not characteristics.characteristics:
                status = _enum_name(getattr(characteristics, "status", "UNKNOWN"))
                logger.warning("[%s] Bluetooth metadata characteristic unavailable: %s; Wi-Fi Direct will continue", attempt_id, status)
                return

            logger.info("[%s] Reading Bluetooth bootstrap metadata without creating an OS bond", attempt_id)
            read = None
            for read_mode in (BluetoothCacheMode.CACHED, BluetoothCacheMode.UNCACHED):
                try:
                    read = await characteristics.characteristics[0].read_value_with_cache_mode_async(read_mode)
                    if read.status == GattCommunicationStatus.SUCCESS:
                        break
                except Exception:
                    pass

            if read is None or read.status != GattCommunicationStatus.SUCCESS:
                status = _enum_name(getattr(read, "status", "UNKNOWN"))
                logger.warning("[%s] Could not read Bluetooth bootstrap metadata: %s; Wi-Fi Direct will continue", attempt_id, status)
                return
        finally:
            for characteristic in (characteristics.characteristics if characteristics is not None else ()):
                try:
                    characteristic.close()
                except Exception:
                    pass
            service.close()
        logger.info(
            "[%s] Bluetooth bootstrap metadata read succeeded in %.3fs",
            attempt_id, time.monotonic() - phase_started,
        )

        try:
            metadata = json.loads(self._bytes(read.value).decode("utf-8"))
            token = str(metadata["wifi_token"]).upper()
            if len(token) != 16 or any(character not in "0123456789ABCDEF" for character in token):
                raise ValueError("Invalid Wi-Fi correlation token")
            if int(metadata["port"]) not in range(1, 65536):
                raise ValueError("Invalid transfer port")
            if not str(metadata["device_id"]) or not str(metadata["name"]) or not str(metadata["public_key"]):
                raise ValueError("Incomplete identity")
        except (KeyError, TypeError, ValueError, UnicodeError, json.JSONDecodeError) as exc:
            raise RadioOperationError("gatt_metadata_validation", f"Invalid Bluetooth metadata: {exc}") from exc

        self._ensure_wifi_direct_started(
            "successful Bluetooth bootstrap metadata read", prefer_group_owner=False
        )

        self.on_event(
            {
                "event": "bluetooth_ready",
                "attempt_id": attempt_id,
                # Correlate the result with the UI selection even if Windows
                # supplied a better privacy/bond alias for the actual GATT link.
                "address": requested_address,
                "address_type": requested_address_type,
                "token": token,
                "name": str(metadata["name"]),
                "device_id": str(metadata["device_id"]),
                "public_key": str(metadata["public_key"]),
                "port": int(metadata["port"]),
            }
        )
        logger.info("[%s] Bluetooth bootstrap phase complete in %.3fs", attempt_id, time.monotonic() - started)

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
        advertisement.is_autonomous_group_owner_enabled = True
        element = WiFiDirectInformationElement()
        element.oui = self._buffer(CUSTOM_OUI)
        element.oui_type = 1
        identity = self.device_id.encode("utf-8")
        if len(identity) > 64:
            raise ValueError("device identity is too long for Wi-Fi Direct discovery")
        public_key_raw = unb64(self.public_key) if self.public_key else b""
        element.value = self._buffer(
            MAGIC + self.token + self.port.to_bytes(2, "big") + bytes((len(identity),)) + identity + public_key_raw
        )
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
        self._wifi_direct_in_progress = True
        try:
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
        finally:
            self._wifi_direct_in_progress = False

    async def _pair_for_wifi_direct(self, information, is_go_intent: bool = False):
        from winrt.windows.devices.enumeration import DeviceInformation
        from winrt.windows.devices.wifidirect import (
            WiFiDirectConfigurationMethod,
            WiFiDirectConnectionParameters,
            WiFiDirectPairingProcedure,
        )

        parameters = WiFiDirectConnectionParameters()
        parameters.preference_ordered_configuration_methods.append(WiFiDirectConfigurationMethod.PUSH_BUTTON)
        parameters.preferred_pairing_procedure = WiFiDirectPairingProcedure.INVITATION
        parameters.group_owner_intent = 15 if is_go_intent else 0

        pairing = getattr(information, "pairing", None)
        if pairing is None:
            return parameters, information

        if pairing.is_paired:
            logger.info("Wi-Fi Direct endpoint %s is marked paired; unpairing to clear stale session profile", information.id)
            try:
                unpair_res = await pairing.unpair_async()
                logger.info("Wi-Fi Direct unpairing status: %s", _enum_name(unpair_res.status))
            except Exception as exc:
                logger.warning("Wi-Fi Direct unpair exception: %s", exc)

            try:
                refreshed = await DeviceInformation.create_from_id_async(information.id)
                if refreshed is not None:
                    information = refreshed
            except Exception as exc:
                logger.warning("Could not refresh DeviceInformation after unpairing: %s", exc)

        return parameters, information

    async def _accept_request(self, request) -> None:
        from winrt.windows.devices.wifidirect import WiFiDirectDevice

        try:
            information = request.device_information
            logger.info(
                "Accepting incoming Wi-Fi Direct connection request id=%s name=%r",
                information.id, information.name,
            )
            device = await WiFiDirectDevice.from_id_async(information.id)
            if device is None:
                raise RadioOperationError(
                    "wifi_direct_accept", "Windows returned no Wi-Fi Direct device for the accepted request"
                )
            self._track_connection(device, information.name)
        except Exception as exc:
            logger.exception("Incoming Wi-Fi Direct request failed")
            event = _exception_event("wifi_direct_error", exc)
            event["phase"] = "wifi_direct_accept"
            self.on_event(event)
        finally:
            request.close()

    def scan_wifi_direct(self) -> None:
        if not self.started:
            raise RuntimeError("Wi-Fi Direct is locked until Bluetooth bootstrap metadata is exchanged")
        if self._wifi_direct_in_progress or self._scanning:
            return
        if self.wifi_publisher is None:
            self._start_wifi_direct()
        self._schedule(self._scan_wifi_direct())

    async def _scan_wifi_direct(self) -> None:
        from winrt.windows.devices.enumeration import DeviceInformation
        from winrt.windows.devices.wifidirect import WiFiDirectDevice, WiFiDirectDeviceSelectorType

        if self._wifi_direct_in_progress or self._scanning:
            return

        self._scanning = True
        try:
            selector = WiFiDirectDevice.get_device_selector(WiFiDirectDeviceSelectorType.ASSOCIATION_ENDPOINT)
            find_all = getattr(
                DeviceInformation,
                "find_all_async_aqs_filter_and_additional_properties",
                DeviceInformation.find_all_async,
            )
            devices = await find_all(selector, [IE_PROPERTY])
            found = 0
            for device in devices:
                self.wifi_scan_devices[device.id] = device
                if self._process_wifi_device(device):
                    found += 1
            self.on_event({"event": "wifi_direct_scan_complete", "count": found})
        except Exception as exc:
            logger.warning("Wi-Fi Direct scan failed: %s", exc)
        finally:
            self._scanning = False

    def _process_wifi_device(self, device) -> bool:
        from winrt.windows.devices.wifidirect import WiFiDirectInformationElement

        try:
            peer_token = None
            port = 0
            device_id = ""
            public_key = ""
            elements = WiFiDirectInformationElement.create_from_device_information(device)
            logger.debug("Inspecting %d information element(s) for Wi-Fi Direct endpoint %s", len(elements), device.id)
            for element in elements:
                value = self._bytes(element.value)
                if element.oui_type == 1 and self._bytes(element.oui) == CUSTOM_OUI and len(value) >= 15 and value.startswith(MAGIC):
                    peer_token = value[4:12].hex().upper()
                    port = int.from_bytes(value[12:14], "big")
                    identity_length = value[14]
                    if len(value) < 15 + identity_length:
                        peer_token = None
                        continue
                    device_id = value[15:15 + identity_length].decode("utf-8", errors="strict")
                    public_key_raw = value[15 + identity_length:15 + identity_length + 32]
                    public_key = b64(public_key_raw) if len(public_key_raw) == 32 else ""
                    break
            if peer_token:
                self.wifi_scan_matches.add(device.id)
                logger.info(
                    "Matched app Wi-Fi Direct endpoint id=%s name=%r token=%s port=%s device_id=%s has_key=%s",
                    device.id, device.name, peer_token, port, device_id, bool(public_key),
                )
                self.on_event(
                    {"event": "wifi_direct_peer", "id": device.id, "name": device.name,
                     "paired": device.pairing.is_paired, "token": peer_token,
                     "port": port, "device_id": device_id, "public_key": public_key}
                )
                return True
            else:
                logger.debug("Wi-Fi Direct endpoint %s did not contain the app information element", device.id)
                return False
        except OSError as exc:
            logger.debug("Wi-Fi Direct endpoint %s has no readable information elements: %s", getattr(device, "id", "unknown"), exc)
            return False
        except Exception as exc:
            logger.warning("Could not inspect Wi-Fi Direct endpoint %s: %s", getattr(device, "id", "unknown"), exc)
            return False

    def connect_wifi_direct(self, device_id: str) -> None:
        if not self.started:
            raise RuntimeError("Wi-Fi Direct is locked until Bluetooth bootstrap metadata is exchanged")
        if self.wifi_publisher is None:
            self._start_wifi_direct()
        self._schedule(self._connect_wifi_direct(device_id))

    async def _connect_wifi_direct(self, device_id: str) -> None:
        from winrt.windows.devices.enumeration import DeviceInformation
        from winrt.windows.devices.wifidirect import (
            WiFiDirectAdvertisementPublisherStatus,
            WiFiDirectDevice,
        )

        self._wifi_direct_in_progress = True
        publisher_stopped = False
        try:
            if self.wifi_watcher is not None:
                try:
                    self.wifi_watcher.stop()
                except Exception:
                    pass

            if self.wifi_publisher is not None:
                try:
                    if self.wifi_publisher.status == WiFiDirectAdvertisementPublisherStatus.STARTED:
                        logger.info("Stopping Wi-Fi Direct publisher to connect as client")
                        self.wifi_publisher.stop()
                        publisher_stopped = True
                except Exception as exc:
                    logger.warning("Could not stop Wi-Fi Direct publisher: %s", exc)

            information = await DeviceInformation.create_from_id_async(device_id)
            if information is None:
                raise RadioOperationError(
                    "wifi_direct_connect", "The selected Wi-Fi Direct endpoint disappeared before connection"
                )
            logger.info(
                "Starting Wi-Fi Direct connection id=%s name=%r paired=%s can_pair=%s",
                device_id, information.name, information.pairing.is_paired, information.pairing.can_pair,
            )
            parameters, information = await self._pair_for_wifi_direct(information, is_go_intent=False)
            from winrt.windows.devices.wifidirect import WiFiDirectPairingProcedure

            logger.info("Connecting to Wi-Fi Direct endpoint %s (procedure=INVITATION intent=0)", information.id)
            device = await WiFiDirectDevice.from_id_async(information.id, parameters)
            if device is None:
                logger.info("FromIdAsync with INVITATION returned None; trying with GROUP_OWNER_NEGOTIATION")
                parameters.preferred_pairing_procedure = WiFiDirectPairingProcedure.GROUP_OWNER_NEGOTIATION
                device = await WiFiDirectDevice.from_id_async(information.id, parameters)
            if device is None:
                logger.info("FromIdAsync with parameters returned None; trying without parameters")
                device = await WiFiDirectDevice.from_id_async(information.id)
            if device is None:
                raise RadioOperationError(
                    "wifi_direct_connect", "Windows returned no Wi-Fi Direct device for the selected endpoint"
                )
            self._track_connection(device, information.name)
        except Exception as exc:
            if publisher_stopped and self.wifi_publisher is not None:
                try:
                    logger.info("Restarting Wi-Fi Direct publisher after connection attempt failure")
                    self.wifi_publisher.start()
                except Exception as pub_exc:
                    logger.warning("Could not restart Wi-Fi Direct publisher: %s", pub_exc)
            logger.exception("Outgoing Wi-Fi Direct connection failed")
            event = _exception_event("wifi_direct_error", exc)
            event["phase"] = "wifi_direct_connect"
            self.on_event(event)
        finally:
            self._wifi_direct_in_progress = False

    def reset_wifi_direct(self) -> None:
        """Close active Wi-Fi Direct connections and restore the autonomous GO publisher."""
        if not self.started:
            return
        self._schedule(self._reset_wifi_direct())

    async def _reset_wifi_direct(self) -> None:
        from winrt.windows.devices.wifidirect import WiFiDirectAdvertisementPublisherStatus

        logger.info("Resetting Wi-Fi Direct state after transfer")
        for device_id, device in list(self.connections.items()):
            try:
                logger.info("Closing Wi-Fi Direct connection %s", device_id)
                device.close()
            except Exception as exc:
                logger.warning("Error closing Wi-Fi Direct device %s: %s", device_id, exc)
        self.connections.clear()

        if self.wifi_publisher is not None:
            try:
                if self.wifi_publisher.status != WiFiDirectAdvertisementPublisherStatus.STARTED:
                    logger.info("Restarting Wi-Fi Direct publisher")
                    self.wifi_publisher.start()
            except Exception as exc:
                logger.warning("Error restarting Wi-Fi Direct publisher: %s", exc)

    def _track_connection(self, device, name: str) -> None:
        logger.info("Wi-Fi Direct connected to %s (%s)", name, device.device_id)
        self.connections[device.device_id] = device

        def on_status_changed(sender, _args):
            status_name = _enum_name(sender.connection_status)
            logger.info("Wi-Fi Direct connection status changed: %s for %s", status_name, sender.device_id)
            self.on_event(
                {"event": "wifi_direct_connection_status", "id": sender.device_id, "status": status_name}
            )
            if status_name == "DISCONNECTED":
                try:
                    sender.close()
                except Exception:
                    pass
                self.connections.pop(sender.device_id, None)
                if self.wifi_publisher is not None:
                    try:
                        logger.info("Restarting Wi-Fi Direct publisher after disconnect")
                        self.wifi_publisher.start()
                    except Exception as exc:
                        logger.warning("Could not restart Wi-Fi Direct publisher: %s", exc)

        token = device.add_connection_status_changed(on_status_changed)
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
        for session in self.bluetooth_sessions.values():
            try:
                session.maintain_connection = False
                session.close()
            except Exception:
                pass
        self.bluetooth_sessions.clear()
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
