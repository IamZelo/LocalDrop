# Local Secure Share

A local file-sharing application for Windows 11, macOS, and Linux. It discovers peers on the existing LAN immediately. Windows can fall back to in-process Python WinRT Wi-Fi Direct for another Windows peer; macOS and Linux are strictly LAN-only. Bluetooth is not used. There is no internet relay, cloud service, or account server.

## Setup on both computers

Use Python 3.12 or newer and install the same application version on both computers.

### Windows

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python main.py
```

### Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python main.py
```

### macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python main.py
```

Keep Wi-Fi enabled and the application open on both computers. On Windows, the packaged manifest declares the Wi-Fi Direct device capability. macOS and Linux never load WinRT or start wireless-direct discovery.

Allow this Python executable's inbound connections in Windows Firewall on the network profile used by the Wi-Fi Direct interface. The application logs its actual listening port at startup. Do not disable the firewall. Windows Mobile Hotspot can interfere with Wi-Fi Direct; turn it off when diagnosing connection failures.

## Transfer flow

1. Drop or add files.
2. Select a computer in the merged nearby-device list. LAN and Wi-Fi Direct observations are grouped by application identity.
3. The route policy is LAN first, then (for two capable Windows peers only) Wi-Fi Direct. Fallback is permitted only after a pre-offer connection failure.
4. The receiver sees filenames and sizes and chooses **Accept** or **Deny**. The sender allows five minutes for approval.
5. Accepted files stream over TLS 1.3 into Downloads, with SHA-256 verification. Existing files are given unique destination names.

Wi-Fi Direct advertisements carry the current file-server port, rotating session token, application identity, and public key. They contain no files or private keys. Incomplete advertisements are ignored; the application never guesses a fallback port. The outgoing socket binds to the local address supplied by the Wi-Fi Direct connection.

Only the selected outgoing transfer can start sending. Incoming links and duplicate or expired connection events cannot send staged files. The application limits connection negotiation to 90 seconds, TCP/TLS operations to 20 seconds, and file-stream inactivity to 60 seconds. Native radio failures and network failures include phase and endpoint details in the console.

## Diagnostics and validation

```powershell
python -m secure_share.diagnostics
python -m unittest discover -s tests -v
```

The diagnostic command reports mDNS interfaces and, on Windows, publisher status, nearby endpoints, and native errors. On macOS it reports that Wi-Fi Direct is not applicable without importing WinRT. The tests cover protocol validation, route policy, and application control flow with GUI, cryptography, and native boundaries mocked where needed; they do not prove a physical wireless connection works.

Hardware acceptance checklist:

- Run with Bluetooth disabled on both PCs; discover each other by hostname.
- Transfer a small file and a large file in each direction; compare hashes.
- Wait over 20 seconds before accepting; verify success and the Downloads destination.
- Deny a transfer; verify no file is written.
- Retry after a failed connection and after completing a transfer.
- Stage files on the receiver; accepting an incoming transfer must not send them back.
- Interrupt Wi-Fi or deny firewall access; verify a bounded failure with an actionable status and console traceback.

## Security boundaries

Transfers use TLS 1.3 with the discovered public key pinned to the server certificate, and signed file offers. Previously trusted key changes and blocked devices are rejected. First-contact discovery is not independently authenticated: accepting a familiar hostname alone does not establish the owner's identity against an active attacker. This retains trust-on-first-use without an additional code prompt.

Incomplete files use a `.part` suffix and are removed on transfer failure. Device identities and history stay local; an OS-keychain fallback warning appears if secrets must be stored using local file permissions. No Bluetooth pairing, Bluetooth packages, legacy radio helper, or mDNS discovery is used by the application.
