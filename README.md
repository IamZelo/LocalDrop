# Local Secure Share

A backendless desktop file-sharing application for Windows, macOS, and Linux. It discovers nearby devices and transfers files over the local network or a manually created hotspot. It does not use cloud storage, accounts, telemetry, STUN, TURN, or any internet API.

## Current implementation

- PySide6 drag-and-drop desktop interface
- mDNS discovery on the local link
- TLS 1.3 transport
- Ed25519 device identities and certificate pinning
- SPAKE2 one-time-code pairing
- Explicit incoming-transfer approval and destination selection
- Streaming transfers with SHA-256 verification and bounded memory use
- Encrypted local trusted-device and recent-transfer data
- Direct-address and one-hop restrictions that prevent routed internet transfers

Native Wi-Fi Direct group creation is available through the optional Windows helper below and is always initiated visibly by the user. Linux and Apple require different native adapters; until those are added, their fallback remains an existing LAN or manually created hotspot.

## Native Bluetooth and Wi-Fi Direct on Windows

The Windows 11 build uses PyWinRT directly inside the Python process to:

- advertise a connectable Bluetooth LE GATT service containing the hostname in its discovery payload;
- resolve advertisements to canonical Windows Bluetooth association endpoints, including their public/random address type;
- request Windows-managed encrypted Bluetooth pairing and exchange app metadata over GATT;
- start and scan for Windows Wi-Fi Direct endpoints only after that encrypted metadata exchange;
- creates or accepts a Wi-Fi Direct link; and
- reports the new local endpoint to the Python application, which restarts mDNS discovery on that link.

Install the Python dependencies on each computer before starting the application:

```powershell
python -m pip install -r requirements.txt
python main.py
```

The UI presents one Bluetooth-derived nearby-device list. Drop files, select a computer, approve the Windows Bluetooth consent prompt, and then approve the incoming Wi-Fi Direct connection on the receiver. The app's one-time-code identity check remains a separate end-to-end security layer for first-time devices.

Bluetooth discovery broadcasts only a shortened hostname and the app service UUID. Stable device identity, the rotating Wi-Fi correlation token, transfer port, filenames, and IP addresses are not exposed in the advertisement; identity metadata is read only from the encryption-required GATT characteristic.

The runtime uses one radio path: in-process Python WinRT. The older source under `native/windows` is retained for reference but is not selected as a fallback.

For detailed console diagnostics on either laptop, run:

```powershell
python -m secure_share.diagnostics
```

This prints the selected radio backend, missing Python modules, Bluetooth status, Wi-Fi Direct status, scan results, native exceptions, and any legacy-helper exit code.

## Run

Use Python 3.12 or newer:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python main.py
```

On macOS/Linux, activate with `source .venv/bin/activate` instead.

Allow the application through the local firewall when prompted. On Windows with the WinRT packages installed, the normal flow is:

1. Drop or add one or more files.
2. Click one device in the single **Nearby devices** list. Only devices whose rotating token was observed over Bluetooth are enabled.
3. Windows creates the Wi-Fi Direct link. First-time devices complete the short-code identity check.
4. The receiver sees the verified filenames and sizes and chooses **Accept** or **Decline**.
5. File bytes are streamed only after acceptance.

An existing LAN/hotspot remains available as the local transport fallback.

## Security notes

- Pair only when you can see both computers and verify which machine displays the code.
- A paired identity change is rejected; use **Forget** before intentionally pairing a reinstalled device.
- If an OS credential store is unavailable, the app warns that its secrets are protected only by local file permissions.
- Incomplete files use a `.part` suffix and are deleted after a failed integrity check.
