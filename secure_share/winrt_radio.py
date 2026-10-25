from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import platform
import sys
import threading
import traceback
from typing import Callable

from .identity import b64, unb64

MAGIC = b"LSS1"
CUSTOM_OUI = bytes((0xFA, 0xCE, 0x01))
IE_PROPERTY = "System.Devices.WiFiDirect.InformationElements"
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


REQUIRED_MODULES = (
    "winrt.runtime",
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
    """Windows Wi-Fi Direct discovery and connection control via PyWinRT."""

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
        self.connect_task = None
        self.command_tasks = set()
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
        self.publisher_ready = asyncio.Event()
        self._start_wifi_direct()
        try:
            await asyncio.wait_for(self.publisher_ready.wait(), 20)
        except TimeoutError as exc:
            raise RadioOperationError("wifi_direct_startup", "Windows did not start the Wi-Fi Direct publisher within 20 seconds. Check Wi-Fi, Mobile Hotspot, and adapter support.") from exc
        self.started = True
        self.on_event({"event": "ready", "wifi_direct": True, "implementation": "python-winrt"})
        await self.stop_event.wait()


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
        token = self.wifi_publisher.add_status_changed(self._publisher_status_changed)
        self._remember_event(self.wifi_publisher, "status_changed", token)

        self.wifi_listener = WiFiDirectConnectionListener()
        token = self.wifi_listener.add_connection_requested(self._connection_requested)
        self._remember_event(self.wifi_listener, "connection_requested", token)
        self.wifi_publisher.start()

    def _publisher_status_changed(self, _sender, args) -> None:
        status, error = _enum_name(args.status), _enum_name(args.error)
        logger.info("Wi-Fi Direct publisher status=%s error=%s", status, error)
        if status.startswith("STARTED") and self.loop and hasattr(self, "publisher_ready"):
            self.loop.call_soon_threadsafe(self.publisher_ready.set)
        self.on_event({"event": "wifi_direct_status", "status": status, "error": error})

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
                lambda: self._schedule(self._approve_incoming_request(request))
            )
        except Exception as exc:
            logger.exception("Could not open incoming Wi-Fi Direct connection request")
            event = _exception_event("wifi_direct_error", exc)
            event["phase"] = "wifi_direct_request"
            self.on_event(event)

    async def _approve_incoming_request(self, request) -> None:
        if self._wifi_direct_in_progress:
            request.close()
            return
        self._wifi_direct_in_progress = True
        try:
            decision = threading.Event()
            event = {
                "event": "wifi_direct_connection_request",
                "name": request.device_information.name or "Nearby device",
                "id": request.device_information.id,
                "accepted": False,
                "_decision": decision,
            }
            self.on_event(event)
            decided = await asyncio.to_thread(decision.wait, 30)
            if not decided or not event["accepted"]:
                logger.info("Incoming Wi-Fi Direct request was declined or timed out")
                return
            logger.info("Incoming transport accepted; file approval is still required")
            await asyncio.wait_for(self._accept_request(request), 90)
        except TimeoutError:
            self.on_event({"event": "wifi_direct_error", "phase": "wifi_direct_accept",
                           "message": "Incoming Wi-Fi Direct negotiation timed out after 90 seconds"})
        finally:
            request.close()
            self._wifi_direct_in_progress = False

    async def _pair_for_wifi_direct(self, information, is_go_intent: bool = False):
        from winrt.windows.devices.enumeration import (
            DevicePairingKinds,
            DevicePairingProtectionLevel,
        )
        from winrt.windows.devices.wifidirect import (
            WiFiDirectConfigurationMethod,
            WiFiDirectConnectionParameters,
            WiFiDirectPairingProcedure,
        )

        parameters = WiFiDirectConnectionParameters()
        parameters.preference_ordered_configuration_methods.append(WiFiDirectConfigurationMethod.PUSH_BUTTON)
        parameters.preferred_pairing_procedure = WiFiDirectPairingProcedure.GROUP_OWNER_NEGOTIATION
        parameters.group_owner_intent = 15 if is_go_intent else 0

        pairing = getattr(information, "pairing", None)
        if pairing is None:
            return parameters, information

        if pairing and pairing.can_pair and not pairing.is_paired:
            kinds = WiFiDirectConnectionParameters.get_device_pairing_kinds(WiFiDirectConfigurationMethod.PUSH_BUTTON)
            custom = pairing.custom

            def pairing_requested(_sender, args) -> None:
                kind_name = _enum_name(args.pairing_kind)
                logger.info("Wi-Fi Direct pairing ceremony requested: %s", kind_name)
                self.on_event({"event": "wifi_direct_pairing_ceremony", "kind": kind_name})
                if args.pairing_kind == DevicePairingKinds.CONFIRM_ONLY:
                    args.accept()

            event_token = custom.add_pairing_requested(pairing_requested)
            try:
                logger.info(
                    "Calling custom pair_with_protection_level_and_settings_async for Wi-Fi Direct (intent=%d)",
                    parameters.group_owner_intent,
                )
                result = await custom.pair_with_protection_level_and_settings_async(
                    kinds, DevicePairingProtectionLevel.DEFAULT, parameters
                )
                status_name = _enum_name(result.status)
                logger.info("Wi-Fi Direct pairing completed with status=%s", status_name)
                if status_name not in ("PAIRED", "ALREADY_PAIRED"):
                    self.on_event({"event": "wifi_direct_pairing_warning", "status": status_name})
            except Exception as exc:
                logger.warning("Wi-Fi Direct custom pairing exception: %s; continuing to FromIdAsync", exc)
            finally:
                try:
                    custom.remove_pairing_requested(event_token)
                except Exception:
                    pass
        elif pairing and not pairing.can_pair:
            logger.warning("Wi-Fi Direct endpoint reports can_pair=False; continuing to FromIdAsync")

        return parameters, information

    async def _accept_request(self, request) -> None:
        from winrt.windows.devices.wifidirect import WiFiDirectDevice

        try:
            information = request.device_information
            logger.info(
                "Accepting Wi-Fi Direct endpoint id=%s name=%r paired=%s can_pair=%s",
                information.id, information.name, information.pairing.is_paired, information.pairing.can_pair,
            )
            parameters, information = await self._pair_for_wifi_direct(information, is_go_intent=True)
            logger.info("Instantiating accepted Wi-Fi Direct device from %s", information.id)
            device = await WiFiDirectDevice.from_id_async(information.id, parameters)
            if device is None:
                logger.info("Parameterized accept returned None; retrying direct FromIdAsync")
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

    def scan_wifi_direct(self) -> None:
        if not self.started:
            raise RuntimeError("Wi-Fi Direct is not ready yet")
        if self._wifi_direct_in_progress or self._scanning:
            self.on_event({"event": "wifi_direct_scan_complete", "count": 0, "skipped": True})
            return
        if self.wifi_publisher is None:
            self._start_wifi_direct()
        self._schedule(self._scan_wifi_direct())

    async def _scan_wifi_direct(self) -> None:
        from winrt.windows.devices.enumeration import DeviceInformation
        from winrt.windows.devices.wifidirect import WiFiDirectDevice, WiFiDirectDeviceSelectorType

        if self._wifi_direct_in_progress or self._scanning:
            self.on_event({"event": "wifi_direct_scan_complete", "count": 0, "skipped": True})
            return

        self._scanning = True
        try:
            selector = WiFiDirectDevice.get_device_selector(WiFiDirectDeviceSelectorType.ASSOCIATION_ENDPOINT)
            find_all = getattr(
                DeviceInformation,
                "find_all_async_aqs_filter_and_additional_properties",
                DeviceInformation.find_all_async,
            )
            devices = await asyncio.wait_for(find_all(selector, [IE_PROPERTY]), 25)
            found = 0
            for device in devices:
                self.wifi_scan_devices[device.id] = device
                if self._process_wifi_device(device):
                    found += 1
            self.on_event({"event": "wifi_direct_scan_complete", "count": found})
        except Exception as exc:
            logger.exception("Wi-Fi Direct scan failed")
            self.on_event(_exception_event("wifi_direct_scan_error", exc))
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
            if peer_token and port and device_id and len(public_key_raw) == 32 and device_id != self.device_id:
                self.wifi_scan_matches.add(device.id)
                logger.info(
                    "Matched Wi-Fi Direct endpoint id=%s name=%r token=%s port=%s device_id=%s has_key=%s",
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

    def connect_wifi_direct(self, device_id: str, attempt_id: str) -> None:
        if not self.started:
            raise RuntimeError("Wi-Fi Direct is not ready yet")
        if self.wifi_publisher is None:
            self._start_wifi_direct()
        if self._wifi_direct_in_progress or (self.connect_task and not self.connect_task.done()):
            raise RuntimeError("A Wi-Fi Direct connection is already in progress")
        self.connect_task = self._schedule(self._connect_attempt(device_id, attempt_id))

    async def _connect_attempt(self, device_id: str, attempt_id: str) -> None:
        try:
            await asyncio.wait_for(self._connect_wifi_direct(device_id, attempt_id), 90)
        except TimeoutError:
            self.on_event({"event": "wifi_direct_error", "attempt_id": attempt_id,
                           "phase": "wifi_direct_connect", "message": "Wi-Fi Direct connection timed out after 90 seconds"})


    async def _connect_wifi_direct(self, device_id: str, attempt_id: str) -> None:
        from winrt.windows.devices.enumeration import DeviceInformation
        from winrt.windows.devices.wifidirect import (
            WiFiDirectAdvertisementPublisherStatus,
            WiFiDirectDevice,
        )

        self._wifi_direct_in_progress = True
        publisher_stopped = False
        try:
            while self._scanning:
                await asyncio.sleep(0.1)
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
            # A previously paired Windows endpoint already has its negotiation
            # profile. Starting another PushButton ceremony first can make
            # FromIdAsync return None on some Windows 11 adapters. Try the
            # direct endpoint before applying explicit parameters.
            logger.info("Opening Wi-Fi Direct endpoint directly before pairing parameters")
            device = await WiFiDirectDevice.from_id_async(information.id)
            if device is None:
                logger.warning("Direct FromIdAsync returned None; retrying with PushButton parameters")
                device = await WiFiDirectDevice.from_id_async(information.id, parameters)
            if device is None:
                await asyncio.sleep(1.0)
                refreshed = await DeviceInformation.create_from_id_async(information.id)
                if refreshed is not None:
                    logger.info("Retrying Wi-Fi Direct endpoint after fresh DeviceInformation lookup")
                    device = await WiFiDirectDevice.from_id_async(refreshed.id)
                    if device is None:
                        device = await WiFiDirectDevice.from_id_async(refreshed.id, parameters)
            if device is None:
                raise RadioOperationError(
                    "wifi_direct_connect", "Windows returned no Wi-Fi Direct device for the selected endpoint"
                )
            self._track_connection(device, information.name, attempt_id)
        except Exception as exc:
            if publisher_stopped and self.wifi_publisher is not None:
                try:
                    logger.info("Restarting Wi-Fi Direct publisher after connection attempt failure")
                    self.wifi_publisher.start()
                except Exception as pub_exc:
                    logger.warning("Could not restart Wi-Fi Direct publisher: %s", pub_exc)
            logger.exception("Outgoing Wi-Fi Direct connection failed")
            event = _exception_event("wifi_direct_error", exc, attempt_id)
            event["phase"] = "wifi_direct_connect"
            self.on_event(event)
        finally:
            self._wifi_direct_in_progress = False

    def reset_wifi_direct(self) -> None:
        """Close active Wi-Fi Direct connections and restore the autonomous GO publisher."""
        if not self.started:
            return
        if self.connect_task and not self.connect_task.done():
            self.connect_task.cancel()
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

    def _track_connection(self, device, name: str, attempt_id: str | None = None) -> None:
        logger.info("Wi-Fi Direct connected to %s (%s)", name, device.device_id)
        previous = self.connections.get(device.device_id)
        if previous is not None and previous is not device:
            previous.close()
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
                {"event": "wifi_direct_connected", "id": device.device_id, "name": name, "attempt_id": attempt_id,
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
        self.command_tasks.add(future)
        future.add_done_callback(self.command_tasks.discard)
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
        for task in list(self.command_tasks):
            task.cancel()
        for owner, event, token in reversed(self.event_tokens):
            try:
                getattr(owner, f"remove_{event}")(token)
            except Exception:
                pass
        self.event_tokens.clear()
        for radio in (self.wifi_watcher, self.wifi_publisher):
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

    def close(self) -> None:
        logger.info("Stopping Python WinRT radio backend")
        if self.loop and self.stop_event:
            self.stop_event.set()
        self._stop_radios()
        self.started = False
