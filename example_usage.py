"""
Example usage of MaynDrive API Client

This script can either:
  • Reuse a Bearer token and scooter metadata captured by the Frida tooling,
    or
  • Walk through the full login flow with your own credentials.

Environment variables (all optional):
  MAYNDRIVE_USE_CAPTURE_TOKEN   -> "true"/"1" to prefer captured token
  MAYNDRIVE_CAPTURE_JSON        -> path to CAPTURED_API_DECRYPT.json
  MAYNDRIVE_CAPTURE_TXT         -> path to CAPTURED_API_DECRYPT.txt
  MAYNDRIVE_EMAIL               -> fallback email for login
  MAYNDRIVE_PASSWORD            -> fallback password for login
  MAYNDRIVE_SERIAL              -> scooter serial number
  MAYNDRIVE_LATITUDE            -> latitude
  MAYNDRIVE_LONGITUDE           -> longitude
  MAYNDRIVE_ENV                 -> MaynDrive environment (default: production)
"""

import json
import os
import re
import getpass
from pathlib import Path
from typing import Callable, Dict, Optional, Tuple

from mayn_drive_api import MaynDriveAPI, print_response

CAPTURE_JSON_DEFAULT = Path("CAPTURED_API_DECRYPT.json")
CAPTURE_TEXT_DEFAULT = Path("CAPTURED_API_DECRYPT.txt")

_TRUE_VALUES = {"1", "true", "yes", "y", "on"}
_FALSE_VALUES = {"0", "false", "no", "n", "off"}


# ---------------------------------------------------------------------------
# Capture helpers
# ---------------------------------------------------------------------------

def _normalize_bearer(token: Optional[str]) -> Optional[str]:
    if not token:
        return None
    token = token.strip()
    if token.lower().startswith("bearer "):
        token = token[7:]
    return token or None


def _extract_from_json(path: Path) -> Tuple[Optional[str], Dict[str, object]]:
    try:
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (FileNotFoundError, json.JSONDecodeError):
        return None, {}

    token = None
    metadata: Dict[str, object] = {}

    if isinstance(data, list):
        for entry in reversed(data):
            if not isinstance(entry, dict):
                continue

            if token is None:
                token = _normalize_bearer(
                    entry.get("authorization")
                    or entry.get("Authorization")
                    or entry.get("token")
                )

            for key in ("serial", "serial_number", "serialNumber"):
                if metadata.get("serial") is None and entry.get(key):
                    metadata["serial"] = entry[key]

            for key in ("latitude", "lat"):
                if metadata.get("latitude") is None and entry.get(key) is not None:
                    try:
                        metadata["latitude"] = float(entry[key])
                    except (TypeError, ValueError):
                        pass

            for key in ("longitude", "lng"):
                if metadata.get("longitude") is None and entry.get(key) is not None:
                    try:
                        metadata["longitude"] = float(entry[key])
                    except (TypeError, ValueError):
                        pass

            for key in ("vehicleId", "vehicle_id"):
                if metadata.get("vehicle_id") is None and entry.get(key) is not None:
                    metadata["vehicle_id"] = entry[key]

            if token and metadata.get("serial") and metadata.get("latitude") and metadata.get("longitude"):
                break

    return token, metadata


def _extract_from_text(path: Path) -> Tuple[Optional[str], Dict[str, object]]:
    try:
        content = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None, {}

    metadata: Dict[str, object] = {}

    token_re = re.compile(
        r"Authorization:\s*(?:Bearer\s+)?([A-Za-z0-9_\-\.]+)",
        re.IGNORECASE,
    )
    meta_serial_re = re.compile(r"Serial(?: Number)?:\s*([A-Z0-9_\-\.]+)", re.IGNORECASE)
    latitude_re = re.compile(r"Latitude:\s*([-+0-9\.]+)", re.IGNORECASE)
    longitude_re = re.compile(r"Longitude:\s*([-+0-9\.]+)", re.IGNORECASE)

    token = None
    matches = list(token_re.finditer(content))
    if matches:
        token = _normalize_bearer(matches[-1].group(1))

    serial_match = list(meta_serial_re.finditer(content))
    if serial_match:
        metadata["serial"] = serial_match[-1].group(1)

    lat_match = list(latitude_re.finditer(content))
    if lat_match:
        try:
            metadata["latitude"] = float(lat_match[-1].group(1))
        except (TypeError, ValueError):
            pass

    lng_match = list(longitude_re.finditer(content))
    if lng_match:
        try:
            metadata["longitude"] = float(lng_match[-1].group(1))
        except (TypeError, ValueError):
            pass

    return token, metadata


def load_from_capture(
    json_path: Optional[Path] = None,
    text_path: Optional[Path] = None,
) -> Tuple[Optional[str], Dict[str, object], Optional[Path]]:
    json_path = Path(json_path) if json_path else CAPTURE_JSON_DEFAULT
    text_path = Path(text_path) if text_path else CAPTURE_TEXT_DEFAULT

    token = None
    metadata: Dict[str, object] = {}
    source: Optional[Path] = None

    if json_path.exists():
        token, metadata = _extract_from_json(json_path)
        if token or metadata:
            source = json_path

    if text_path.exists():
        token_txt, metadata_txt = _extract_from_text(text_path)
        if not token and token_txt:
            token = token_txt
            source = text_path
        for key, value in metadata_txt.items():
            metadata.setdefault(key, value)
        if metadata_txt and source is None:
            source = text_path

    return token, metadata, source


# ---------------------------------------------------------------------------
# Prompt helpers
# ---------------------------------------------------------------------------

def _get_bool_env(key: str) -> Optional[bool]:
    value = os.environ.get(key)
    if value is None:
        return None
    lowered = value.strip().lower()
    if lowered in _TRUE_VALUES:
        return True
    if lowered in _FALSE_VALUES:
        return False
    return None


def _prompt_value(
    env_key: str,
    prompt_text: str,
    *,
    secret: bool = False,
    cast: Optional[Callable[[str], object]] = None,
    allow_empty: bool = False,
    default: Optional[object] = None,
) -> Optional[object]:
    env_raw = os.environ.get(env_key)
    if env_raw:
        if cast is None:
            return env_raw
        try:
            return cast(env_raw)
        except (TypeError, ValueError):
            print(f"Invalid value for {env_key}: {env_raw}. You'll be prompted instead.\n")

    display_default = None
    if default is not None:
        if isinstance(default, float):
            display_default = f"{default:.6f}".rstrip("0").rstrip(".")
        else:
            display_default = str(default)

    while True:
        full_prompt = prompt_text
        if display_default is not None:
            full_prompt = f"{prompt_text} [{display_default}]: "
        else:
            full_prompt = prompt_text

        raw = (
            getpass.getpass(full_prompt)
            if secret
            else input(full_prompt)
        ).strip()

        if not raw:
            if default is not None:
                value = default
                return value
            if allow_empty:
                return None
            print("This value is required.\n")
            continue

        if cast is None:
            return raw
        try:
            return cast(raw)
        except (TypeError, ValueError):
            print("Please provide a valid value.\n")


def _prompt_optional(prompt_text: str) -> bool:
    response = input(prompt_text).strip().lower()
    return response in _TRUE_VALUES


# ---------------------------------------------------------------------------
# Configuration loading
# ---------------------------------------------------------------------------

def load_runtime_config() -> Dict[str, object]:
    config: Dict[str, object] = {}

    use_capture = _get_bool_env("MAYNDRIVE_USE_CAPTURE_TOKEN")
    if use_capture is None:
        use_capture = _prompt_optional(
            "Use Bearer token from capture logs if available? [y/N]: "
        )
    config["use_capture_token"] = use_capture

    capture_json = Path(
        os.environ.get("MAYNDRIVE_CAPTURE_JSON", str(CAPTURE_JSON_DEFAULT))
    )
    capture_text = Path(
        os.environ.get("MAYNDRIVE_CAPTURE_TXT", str(CAPTURE_TEXT_DEFAULT))
    )
    config["capture_json"] = capture_json
    config["capture_text"] = capture_text

    captured_token, captured_meta, capture_source = load_from_capture(
        capture_json, capture_text
    )
    config["captured_token"] = captured_token
    config["captured_metadata"] = captured_meta
    config["metadata_source"] = capture_source

    config["environment"] = os.environ.get("MAYNDRIVE_ENV", "production")

    serial_default = captured_meta.get("serial")
    latitude_default = captured_meta.get("latitude")
    longitude_default = captured_meta.get("longitude")

    config["serial"] = _prompt_value(
        "MAYNDRIVE_SERIAL",
        "Scooter serial number: ",
        default=serial_default,
    )
    config["latitude"] = _prompt_value(
        "MAYNDRIVE_LATITUDE",
        "Latitude (e.g. 48.8566): ",
        cast=float,
        default=latitude_default,
    )
    config["longitude"] = _prompt_value(
        "MAYNDRIVE_LONGITUDE",
        "Longitude (e.g. 2.3522): ",
        cast=float,
        default=longitude_default,
    )

    config["email"] = os.environ.get("MAYNDRIVE_EMAIL")
    config["password"] = os.environ.get("MAYNDRIVE_PASSWORD")

    return config


# ---------------------------------------------------------------------------
# API setup and authentication
# ---------------------------------------------------------------------------

def initialize_api(environment: str = "production") -> MaynDriveAPI:
    print("Initializing MaynDrive API Client...")
    return MaynDriveAPI(environment=environment)


def authenticate(
    api: MaynDriveAPI,
    config: Dict[str, object],
    *,
    label: str = "Login Response",
) -> Dict[str, object]:
    result: Dict[str, object] = {
        "success": False,
        "used_capture_token": False,
        "token_source": None,
        "token": None,
        "login_data": None,
    }

    use_capture = bool(config.get("use_capture_token"))
    captured_token = config.get("captured_token")
    capture_source = config.get("metadata_source")

    if use_capture and captured_token:
        api.access_token = captured_token
        result.update(
            success=True,
            used_capture_token=True,
            token_source=capture_source,
            token=captured_token,
        )
        return result

    if use_capture and not captured_token:
        print("[!] No Bearer token found in capture files. Falling back to login.\n")

    email = config.get("email")
    if not email:
        email = _prompt_value("MAYNDRIVE_EMAIL", "Email: ")
        config["email"] = email

    password = config.get("password")
    if not password:
        password = _prompt_value(
            "MAYNDRIVE_PASSWORD", "Password: ", secret=True
        )
        config["password"] = password

    success, login_data = api.login(str(email), str(password))
    print_response(success, login_data, label)

    result.update(success=success, login_data=login_data)
    return result


# ---------------------------------------------------------------------------
# Example flows
# ---------------------------------------------------------------------------

def _render_capture_context(config: Dict[str, object]):
    metadata_source = config.get("metadata_source")
    captured_meta = config.get("captured_metadata") or {}

    if metadata_source and captured_meta:
        info = {
            "serial": captured_meta.get("serial"),
            "latitude": captured_meta.get("latitude"),
            "longitude": captured_meta.get("longitude"),
            "source": str(metadata_source),
        }
        print_response(True, info, "Metadata from capture")


def main(config: Optional[Dict[str, object]] = None):
    if config is None:
        config = load_runtime_config()

    api = initialize_api(str(config["environment"]))

    serial_number = str(config["serial"])
    latitude = float(config["latitude"])
    longitude = float(config["longitude"])

    _render_capture_context(config)

    print("\n" + "=" * 60)
    print("STEP 1: Authenticate")
    print("=" * 60)

    auth = authenticate(api, config)
    if not auth["success"]:
        print("✗ Unable to authenticate. Exiting.")
        return

    if auth["used_capture_token"]:
        token = auth.get("token") or ""
        preview = f"{token[:20]}..." if len(token) > 20 else token
        source = auth.get("token_source")
        info = {
            "access_token_preview": preview,
            "source": str(source) if source else "capture",
        }
        print_response(True, info, "Loaded Capture Token")
    else:
        print("✓ Login successful.")

    print("\n" + "=" * 60)
    print("STEP 2: Get User Profile")
    print("=" * 60)
    success, profile = api.get_user_profile()
    print_response(success, profile, "User Profile")

    print("\n" + "=" * 60)
    print("STEP 3: Unlock Vehicle (Regular)")
    print("=" * 60)
    success, unlock_data = api.unlock_vehicle(
        serial_number=serial_number,
        latitude=latitude,
        longitude=longitude,
    )
    print_response(success, unlock_data, "Regular Unlock Response")

    print("\n" + "=" * 60)
    print("STEP 4: Unlock Vehicle (Admin)")
    print("=" * 60)
    success, admin_unlock = api.unlock_vehicle_admin(
        serial_number=serial_number,
        latitude=latitude,
        longitude=longitude,
        force=False,
    )
    print_response(success, admin_unlock, "Admin Unlock Response")

    print("\n" + "=" * 60)
    print("STEP 5: Get Vehicle Information")
    print("=" * 60)
    success, vehicle_info = api.get_vehicle_info(serial_number, admin=False)
    print_response(success, vehicle_info, "Vehicle Info (Basic)")
    success, admin_info = api.get_vehicle_info(serial_number, admin=True)
    print_response(success, admin_info, "Vehicle Info (Admin)")

    print("\n" + "=" * 60)
    print("STEP 6: Refresh Vehicle Data from IoT")
    print("=" * 60)
    success, refresh_data = api.refresh_vehicle_admin(serial_number)
    print_response(success, refresh_data, "Refresh Vehicle Data")

    print("\n" + "=" * 60)
    print("STEP 7: Identify Vehicle (Beep/Flash)")
    print("=" * 60)
    success, identify_data = api.identify_vehicle_admin(serial_number)
    print_response(success, identify_data, "Identify Vehicle")

    print("\n" + "=" * 60)
    print("STEP 8: Get Available Vehicle Models")
    print("=" * 60)
    success, models = api.get_vehicle_models()
    print_response(success, models, "Vehicle Models")

    print("\n" + "=" * 60)
    print("STEP 9: Open Battery Compartment")
    print("=" * 60)
    success, battery_data = api.open_battery_compartment(serial_number)
    print_response(success, battery_data, "Battery Compartment")

    print("\n" + "=" * 60)
    print("STEP 10: Get Wallet Information")
    print("=" * 60)
    success, wallet = api.get_wallet(currency="USD", network_id=1)
    print_response(success, wallet, "Wallet Information")

    print("\n" + "=" * 60)
    print("STEP 11: Get Rent History")
    print("=" * 60)
    success, rents = api.get_rents()
    print_response(success, rents, "Rent History")

    print("\n" + "=" * 60)
    print("STEP 12: Lock Vehicle (Admin)")
    print("=" * 60)
    success, lock_data = api.lock_vehicle_admin(
        serial_number=serial_number,
        latitude=latitude,
        longitude=longitude,
    )
    print_response(success, lock_data, "Admin Lock Response")

    print("\n✓ Example script completed!")


def quick_unlock_example(config: Optional[Dict[str, object]] = None):
    if config is None:
        config = load_runtime_config()

    api = initialize_api(str(config["environment"]))
    _render_capture_context(config)

    auth = authenticate(api, config, label="Quick Unlock Login")
    if not auth["success"]:
        print("✗ Unable to authenticate. Exiting.")
        return

    serial_number = str(config["serial"])
    latitude = float(config["latitude"])
    longitude = float(config["longitude"])

    success, data = api.unlock_vehicle_admin(
        serial_number=serial_number,
        latitude=latitude,
        longitude=longitude,
        force=False,
    )

    if success:
        print("✓ Scooter unlocked successfully!")
    else:
        print(f"✗ Failed to unlock: {data}")


def update_vehicle_settings_example(config: Optional[Dict[str, object]] = None):
    if config is None:
        config = load_runtime_config()

    api = initialize_api(str(config["environment"]))
    _render_capture_context(config)

    auth = authenticate(api, config, label="Update Settings Login")
    if not auth["success"]:
        print("✗ Unable to authenticate. Exiting.")
        return

    serial_number = str(config["serial"])
    settings = {
        "max_speed": 25,
        "eco_mode": True,
        "maintenance_mode": False,
    }

    success, data = api.update_vehicle_settings(serial_number, settings)
    print_response(success, data, "Update Settings")


if __name__ == "__main__":
    banner = """
    ┌─────────────────────────────────────────────────────────┐
    │         MaynDrive API Client - Example Usage             │
    │                                                         │
    │  Token and metadata can be reused from CAPTURED_API_*    │
    │  or you can provide credentials interactively.           │
    └─────────────────────────────────────────────────────────┘
    """
    print(banner)

    choice = input(
        "\nChoose an option:\n"
        "1. Run full example\n"
        "2. Quick unlock only\n"
        "3. Update settings\n\nChoice (1-3): "
    ).strip()

    if choice not in {"1", "2", "3"}:
        print("Invalid choice!")
    else:
        runtime_config = load_runtime_config()
        if choice == "1":
            main(runtime_config)
        elif choice == "2":
            quick_unlock_example(runtime_config)
        elif choice == "3":
            update_vehicle_settings_example(runtime_config)
