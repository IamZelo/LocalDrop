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

The Windows build uses PyWinRT directly inside the Python process to:

- advertises a rotating, anonymous application token over Bluetooth LE;
- scans for nearby application advertisements;
- advertises and scans for Windows Wi-Fi Direct endpoints;
- creates or accepts a Wi-Fi Direct link; and
- reports the new local endpoint to the Python application, which restarts mDNS discovery on that link.

Install the Python dependencies on each computer before starting the application:

```powershell
python -m pip install -r requirements.txt
python main.py
```

The UI shows Bluetooth proximity separately from Windows Wi-Fi Direct endpoints. Select the corresponding nearby computer under **Wi-Fi Direct devices**, click **Connect directly**, then use the normal one-time-code application pairing. Windows may show its own radio-pairing consent dialog first.

Bluetooth discovery deliberately does not broadcast a username, stable device ID, filename, or IP address. The rotating BLE token is used only to indicate that another copy of the app is physically nearby; cryptographic identity is established later by the application pairing code.

The older .NET radio helper remains in `native/windows` as a compatibility fallback, but it is not required when the `winrt-*` packages are installed.

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
