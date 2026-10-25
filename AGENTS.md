# Repository Guidelines

## Project Structure & Module Organization

This is a Python desktop application for local file sharing on Windows 11.

- `secure_share/` contains the application: PySide6 UI (`app.py`), Windows Wi-Fi Direct integration (`winrt_radio.py`, `native_radio.py`), TLS file transport (`network.py`), identity and encrypted local storage, and protocol helpers.
- `tests/` contains `unittest` tests for protocol validation, radio control flow, network transfer timeouts, and UI workflow state. `tests/radio_test_support.py` supplies lightweight test boundaries.
- `main.py` is the normal entry point. `native/` contains historical Windows helper sources and build configuration; the active backend is in-process Python WinRT.

## Build, Test, and Development Commands

Create an environment and install dependencies on Windows:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Run the application with `python main.py`. Run diagnostics with `python -m secure_share.diagnostics`; this reports WinRT package availability and Wi-Fi Direct publisher/scan events. Run all tests with `python -m unittest discover -s tests -v`. Check syntax without hardware using `python -m compileall -q secure_share tests`.

## Coding Style & Naming Conventions

Use Python 3.12+ syntax, four-space indentation, type annotations, and descriptive `snake_case` names. Use `PascalCase` for classes and `UPPER_SNAKE_CASE` for protocol constants. Keep UI callbacks on the Qt event loop; keep blocking socket and file work in worker threads. Use the module logger (`logging.getLogger(...)`) for diagnostics rather than `print`.

## Testing Guidelines

Tests use the standard library `unittest` framework and are named `test_*.py` with methods named `test_<behavior>`. Add regression coverage for state transitions, duplicate events, timeout phases, and malformed discovery metadata. Physical Wi-Fi Direct validation requires two Windows machines and cannot be replaced by unit tests.

## Commit & Pull Request Guidelines

Use short, imperative commit subjects that describe one change, for example `Fix Wi-Fi Direct transfer timeout`. Pull requests should explain the user-visible behavior, affected Windows/WinRT assumptions, test commands and results, and any hardware or firewall prerequisites. Include console logs or screenshots when changing connection or transfer status UI.

## Security & Configuration Tips

Transfers are local-only and use TLS 1.3, signed offers, and public-key pinning. Do not commit identity keys, local databases, received files, or generated build output. Preserve validation that rejects incomplete Wi-Fi Direct advertisements and never introduce a guessed fallback port.
