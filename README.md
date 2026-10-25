# Local Secure Share

A backendless desktop file-sharing application for Windows, macOS, and Linux. It discovers nearby devices and transfers files over the local network or a manually created hotspot. It does not use cloud storage, accounts, telemetry, STUN, TURN, or any internet API.

## Current implementation

- PySide6 drag-and-drop desktop interface
- mDNS discovery on the local link
- TLS 1.3 transport
- Ed25519 device identities and certificate pinning
- Signed first-transfer trust with certificate pinning
- One incoming-transfer approval, saved directly to Downloads
- Streaming transfers with SHA-256 verification and bounded memory use
- Encrypted local trusted-device and recent-transfer data
- Direct-address and one-hop restrictions that prevent routed internet transfers

Native Wi-Fi Direct group creation is handled in-process on Windows after Bluetooth bootstrap. Linux and Apple require different native adapters; until those are added, their fallback remains an existing LAN or manually created hotspot.

## Native Bluetooth and Wi-Fi Direct on Windows

The Windows 11 build uses PyWinRT directly inside the Python process to:

- advertise a connectable Bluetooth LE GATT service containing the hostname in its discovery payload;
- resolve advertisements to canonical Windows Bluetooth association endpoints, including their public/random address type;
- exchange non-sensitive Wi-Fi bootstrap metadata over Bluetooth GATT without creating a Windows Bluetooth bond;
- start and scan for Windows Wi-Fi Direct endpoints only after that metadata exchange;
- creates or accepts a Wi-Fi Direct link; and
- reports the new local endpoint to the Python application, which restarts mDNS discovery on that link.

Install the Python dependencies on each computer before starting the application:

```powershell
python -m pip install -r requirements.txt
python main.py
```

The UI presents one Bluetooth-derived nearby-device list. Drop files and select a computer; the Wi-Fi Direct transport is created automatically. The receiver sees one file offer with filenames and sizes. Accepting it stores the sender identity and saves the verified files to Downloads. No Windows Bluetooth pairing is required.

Bluetooth discovery broadcasts only a shortened hostname and the app service UUID. The GATT bootstrap response supplies the local transfer port, rotating Wi-Fi correlation token, app identity, and public key needed to locate and authenticate the peer. It never contains file names, file contents, credentials, or private keys.

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
3. Windows creates the Wi-Fi Direct link without an application prompt.
4. The receiver sees the signed filenames and sizes and chooses **Accept** or **Deny**.
5. File bytes are streamed only after acceptance and saved to Downloads.

An existing LAN/hotspot remains available as the local transport fallback.

## Security notes

- Approve a first transfer only when you recognize the nearby computer and expected files.
- A trusted identity change is rejected; use **Forget** before intentionally trusting a reinstalled device.
- If an OS credential store is unavailable, the app warns that its secrets are protected only by local file permissions.
- Incomplete files use a `.part` suffix and are deleted after a failed integrity check.
