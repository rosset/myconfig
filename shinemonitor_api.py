"""
ShineMonitor Open API – Python Client
Based on: https://humless.com/documents/go-200-user-manual.pdf

Authentication flow
-------------------
1. Call `auth()` – generates a signed request and returns (secret, token).
2. Pass secret + token to every subsequent call.  The client caches them
   automatically and refreshes via `update_token()` before expiry.

Signature rules
---------------
Auth request:
    sign = SHA1(salt + SHA1(pwd) + "&action=auth&usr=<usr>&company-key=<key>")

All other requests:
    sign = SHA1(salt + secret + token + "&action=<action>[&param=value...]")

Usage example
-------------
    client = ShineMonitorClient(
        usr="vplant",
        pwd="vplant",
        company_key="0123456789ABCDEF",
    )
    client.auth()                          # login / get token
    plants = client.query_plants()         # list power stations
    energy = client.query_plant_energy_day(plant_id=1)
"""

import hashlib
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any

import requests


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

BASE_URL = "http://api.shinemonitor.com/public/"


def _sha1(text: str) -> str:
    """Return lowercase hex SHA-1 digest of *text* (UTF-8 encoded)."""
    return hashlib.sha1(text.encode("utf-8")).hexdigest()


def _salt() -> str:
    """Return a salt string based on the current epoch in milliseconds."""
    return str(int(time.time() * 1000))


def _build_auth_sign(salt: str, pwd_sha1: str, usr: str, company_key: str) -> str:
    """
    sign = SHA1(salt + SHA1(pwd) + "&action=auth&usr=<usr>&company-key=<key>")
    """
    action_part = f"&action=auth&usr={usr}&company-key={company_key}"
    return _sha1(salt + pwd_sha1 + action_part)


def _build_sign(salt: str, secret: str, token: str, action_and_params: str) -> str:
    """
    sign = SHA1(salt + secret + token + "&action=<action>[&params...]")
    """
    return _sha1(salt + secret + token + action_and_params)


# ---------------------------------------------------------------------------
# Session state
# ---------------------------------------------------------------------------

@dataclass
class AuthSession:
    secret: str = ""
    token: str = ""
    expires_at: float = 0.0           # epoch seconds
    role: int = 0

    @property
    def is_valid(self) -> bool:
        return bool(self.token) and time.time() < self.expires_at - 60


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class ShineMonitorError(Exception):
    """Raised when the API returns a non-zero error code."""

    ERROR_CODES = {
        0x0000: "ERR_NONE",
        0x0001: "ERR_FAIL",
        0x0002: "ERR_TIMEOUT",
        0x0003: "ERR_SYSTEM_EXCEPTION",
        0x0004: "ERR_SIGN",
        0x0005: "ERR_SALT",
        0x0006: "ERR_FORMAT_ERROR",
        0x0007: "ERR_MISSING_PARAMETER",
        0x0008: "ERR_FORBIDDEN",
        0x0009: "ERR_UNSUPPORTED",
        0x000A: "ERR_NO_AUTH",
        0x000B: "ERR_NO_PERMISSION",
        0x000C: "ERR_NO_RECORD",
        0x000D: "ERR_OVER_LIMITED",
        0x000E: "ERR_DUPLICATE_OPER",
        0x000F: "ERR_NOT_FOUND_COMPANY_KEY",
        0x0010: "ERR_PASSWORD_VERIF_FAIL",
        0x0100: "ERR_NOT_FOUND_API",
        0x0101: "ERR_NOT_FOUND_COLLECTOR",
        0x0102: "ERR_NOT_FOUND_DEVICE",
        0x0103: "ERR_INVALID_PN",
        0x0104: "ERR_NOT_FOUND_PLANT",
        0x0105: "ERR_NOT_FOUND_USR",
        0x0106: "ERR_DEVICE_OFFLINE",
        0x0107: "ERR_COLLECTOR_OFFLINE",
    }

    def __init__(self, err: int, desc: str):
        name = self.ERROR_CODES.get(err, "UNKNOWN")
        super().__init__(f"[0x{err:04X}] {name}: {desc}")
        self.err = err
        self.desc = desc


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------

class ShineMonitorClient:
    """
    High-level client for the ShineMonitor Open API.

    Parameters
    ----------
    usr : str
        Account username assigned by the platform.
    pwd : str
        Account password (plain text – hashed internally).
    company_key : str
        Manufacturer identification assigned by the platform.
    timeout : int
        HTTP request timeout in seconds (default: 15).
    """

    def __init__(self, usr: str, pwd: str, company_key: str, timeout: int = 15):
        self.usr = usr
        self.pwd = pwd
        self.company_key = company_key
        self.timeout = timeout
        self._session = AuthSession()
        self._http = requests.Session()

    # ------------------------------------------------------------------
    # Low-level request helpers
    # ------------------------------------------------------------------

    def _get(self, params: dict[str, Any]) -> dict:
        """Send a GET request and return the parsed JSON body."""
        resp = self._http.get(BASE_URL, params=params, timeout=self.timeout)
        resp.raise_for_status()
        data = resp.json()
        if data.get("err", 0) != 0:
            raise ShineMonitorError(data["err"], data.get("desc", ""))
        return data.get("dat", {})

    def _signed_get(self, action: str, extra: dict[str, Any] | None = None) -> dict:
        """
        Build a signed request for any action that requires an active session.
        Auto-refreshes the token if it is about to expire.
        """
        if not self._session.is_valid:
            self.auth()

        extra = extra or {}
        salt = _salt()

        # action_and_params must be exactly "&action=<action>[&k=v...]"
        extra_str = "".join(f"&{k}={urllib.parse.quote(str(v), safe='')}"
                            for k, v in extra.items())
        action_and_params = f"&action={action}{extra_str}"

        sign = _build_sign(salt, self._session.secret, self._session.token,
                           action_and_params)

        params: dict[str, Any] = {
            "sign": sign,
            "salt": salt,
            "token": self._session.token,
            "action": action,
        }
        params.update(extra)
        return self._get(params)

    # ------------------------------------------------------------------
    # 2.1  Authentication
    # ------------------------------------------------------------------

    def auth(self) -> AuthSession:
        """
        Authenticate with the platform and store the session credentials.
        Returns the populated AuthSession.
        """
        salt = _salt()
        pwd_sha1 = _sha1(self.pwd)
        sign = _build_auth_sign(salt, pwd_sha1, self.usr, self.company_key)

        params = {
            "sign": sign,
            "salt": salt,
            "action": "auth",
            "usr": self.usr,
            "company-key": self.company_key,
        }
        data = self._get(params)

        self._session.secret = data["secret"]
        self._session.token = data["token"]
        self._session.expires_at = time.time() + data["expire"]
        self._session.role = data.get("role", 0)
        return self._session

    # ------------------------------------------------------------------
    # 2.2  Update / refresh token
    # ------------------------------------------------------------------

    def update_token(self) -> AuthSession:
        """Refresh the session token without a full re-login."""
        data = self._signed_get("updateToken")
        self._session.secret = data["secret"]
        self._session.token = data["token"]
        self._session.expires_at = time.time() + data["expire"]
        return self._session

    # ------------------------------------------------------------------
    # 2.4  Account
    # ------------------------------------------------------------------

    def query_account_info(self, uid: int | None = None) -> dict:
        """
        Return information about the current account (or a sub-account).

        Parameters
        ----------
        uid : int, optional
            Sub-account user ID.  Omit to query the logged-in account.
        """
        extra = {}
        if uid is not None:
            extra["uid"] = uid
        return self._signed_get("queryAccountInfo", extra)

    # ------------------------------------------------------------------
    # 3.x  Power stations
    # ------------------------------------------------------------------

    def query_plant_count(self, status: int | None = None) -> int:
        """Return the total number of power stations owned by the account."""
        extra = {}
        if status is not None:
            extra["status"] = status
        data = self._signed_get("queryPlantCount", extra)
        return data["count"]

    def query_plants(
        self,
        status: int | None = None,
        order_by: str = "ascPlantName",
        plant_name: str | None = None,
        page: int = 0,
        page_size: int = 20,
    ) -> dict:
        """
        Return a paginated list of power stations.

        Parameters
        ----------
        status : int, optional
            Filter by station status (0=online, 1=offline, 4=warning…).
        order_by : str
            Sort order.  One of: ascPlantName, descPlantName, ascInstall,
            descInstall, ascStatus, descStatus.
        plant_name : str, optional
            Fuzzy name filter.
        page : int
            Zero-based page number.
        page_size : int
            Records per page (1–50).
        """
        extra: dict[str, Any] = {
            "orderBy": order_by,
            "page": page,
            "pagesize": min(max(page_size, 1), 50),
        }
        if status is not None:
            extra["status"] = status
        if plant_name:
            extra["plantName"] = plant_name
        return self._signed_get("queryPlants", extra)

    def query_plant_info(self, plant_id: int) -> dict:
        """Return detailed information about a single power station."""
        return self._signed_get("queryPlantInfo", {"plantid": plant_id})

    def query_plant_device_view(self, plant_id: int) -> dict:
        """Return the tree view of collectors and devices under a station."""
        return self._signed_get("queryPlantDeviceView", {"plantid": plant_id})

    def query_plant_device_status(self, plant_id: int) -> dict:
        """Return the working status of all collectors/devices in a station."""
        return self._signed_get("queryPlantDeviceStatus", {"plantid": plant_id})

    # Energy queries -------------------------------------------------------

    def query_plant_energy_day(self, plant_id: int, date: str | None = None) -> str:
        """
        Return total kWh generated by a station on a given day.

        Parameters
        ----------
        plant_id : int
        date : str, optional
            Format: 'YYYY-MM-DD'.  Defaults to today (station timezone).
        """
        extra: dict[str, Any] = {"plantid": plant_id}
        if date:
            extra["date"] = date
        return self._signed_get("queryPlantEnergyDay", extra)["energy"]

    def query_plant_energy_month(self, plant_id: int, date: str | None = None) -> str:
        """Return total kWh generated in a given month ('YYYY-MM')."""
        extra: dict[str, Any] = {"plantid": plant_id}
        if date:
            extra["date"] = date
        return self._signed_get("queryPlantEnergyMonth", extra)["energy"]

    def query_plant_energy_month_per_day(
        self, plant_id: int, date: str | None = None
    ) -> list[dict]:
        """Return daily kWh breakdown for every day in a month."""
        extra: dict[str, Any] = {"plantid": plant_id}
        if date:
            extra["date"] = date
        return self._signed_get("queryPlantEnergyMonthPerDay", extra)["perday"]

    def query_plant_energy_year(self, plant_id: int, date: str | None = None) -> str:
        """Return total kWh generated in a given year ('YYYY')."""
        extra: dict[str, Any] = {"plantid": plant_id}
        if date:
            extra["date"] = date
        return self._signed_get("queryPlantEnergyYear", extra)["energy"]

    def query_plant_energy_year_per_month(
        self, plant_id: int, date: str | None = None
    ) -> list[dict]:
        """Return monthly kWh breakdown for every month in a year."""
        extra: dict[str, Any] = {"plantid": plant_id}
        if date:
            extra["date"] = date
        return self._signed_get("queryPlantEnergyYearPerMonth", extra)["permonth"]

    def query_plant_energy_total(self, plant_id: int) -> str:
        """Return all-time total kWh generated by a station."""
        return self._signed_get("queryPlantEnergyTotal", {"plantid": plant_id})["energy"]

    def query_plant_active_power_current(self, plant_id: int) -> str:
        """Return the current output active power of a station (kW)."""
        return self._signed_get(
            "queryPlantActiveOuputPowerCurrent", {"plantid": plant_id}
        )["outputPower"]

    def query_plant_active_power_one_day(
        self, plant_id: int, date: str | None = None
    ) -> list[dict]:
        """Return sampled active power (5-min intervals) for a given day."""
        extra: dict[str, Any] = {"plantid": plant_id}
        if date:
            extra["date"] = date
        return self._signed_get("queryPlantActiveOuputPowerOneDay", extra)["outputPower"]

    # Alarms ---------------------------------------------------------------

    def query_plant_warning_count(
        self,
        plant_id: int,
        level: int | None = None,
        handled: bool | None = None,
        start_date: str | None = None,
        end_date: str | None = None,
    ) -> int:
        """Return the number of alarms in a station."""
        extra: dict[str, Any] = {"plantid": plant_id}
        if level is not None:
            extra["level"] = level
        if handled is not None:
            extra["handle"] = str(handled).lower()
        if start_date:
            extra["sdate"] = start_date
        if end_date:
            extra["edate"] = end_date
        return self._signed_get("queryPlantWarningCount", extra)["count"]

    def query_plant_warnings(
        self,
        plant_id: int,
        level: int | None = None,
        handled: bool | None = None,
        i18n: str = "en_US",
        page: int = 0,
        page_size: int = 20,
    ) -> dict:
        """Return paginated alarm list for a station."""
        extra: dict[str, Any] = {
            "plantid": plant_id,
            "i18n": i18n,
            "page": page,
            "pagesize": min(max(page_size, 1), 50),
        }
        if level is not None:
            extra["level"] = level
        if handled is not None:
            extra["handle"] = str(handled).lower()
        return self._signed_get("queryPlantWarning", extra)

    # ------------------------------------------------------------------
    # 4.x  Data collectors
    # ------------------------------------------------------------------

    def query_collectors(
        self,
        status: int | None = None,
        page: int = 0,
        page_size: int = 20,
    ) -> dict:
        """Return a paginated list of data collectors."""
        extra: dict[str, Any] = {
            "page": page,
            "pagesize": min(max(page_size, 1), 50),
        }
        if status is not None:
            extra["status"] = status
        return self._signed_get("queryCollectors", extra)

    def query_collector_count(self, status: int | None = None) -> int:
        """Return the total number of data collectors."""
        extra = {}
        if status is not None:
            extra["status"] = status
        return self._signed_get("queryCollectorCount", extra)["count"]

    def query_collector_status(self, pns: list[str]) -> list[dict]:
        """
        Return status for one or more collectors.

        Parameters
        ----------
        pns : list[str]
            List of collector PN numbers (max 256).
        """
        return self._signed_get(
            "queryCollectorStatus", {"pn": ",".join(pns)}
        )["collector"]

    # ------------------------------------------------------------------
    # 5.x  Devices
    # ------------------------------------------------------------------

    def query_device_count(
        self,
        plant_id: int | None = None,
        status: int | None = None,
        dev_type: int | None = None,
    ) -> int:
        """Return the number of devices, optionally filtered."""
        extra: dict[str, Any] = {}
        if plant_id is not None:
            extra["plantid"] = plant_id
        if status is not None:
            extra["status"] = status
        if dev_type is not None:
            extra["devtype"] = dev_type
        return self._signed_get("queryDeviceCount", extra)["count"]

    def query_devices(
        self,
        plant_id: int | None = None,
        status: int | None = None,
        dev_type: int | None = None,
        pn: str | None = None,
        alias: str | None = None,
        page: int = 0,
        page_size: int = 20,
    ) -> dict:
        """Return a paginated list of devices."""
        extra: dict[str, Any] = {
            "page": page,
            "pagesize": min(max(page_size, 1), 50),
        }
        if plant_id is not None:
            extra["plantid"] = plant_id
        if status is not None:
            extra["status"] = status
        if dev_type is not None:
            extra["devtype"] = dev_type
        if pn:
            extra["pn"] = pn
        if alias:
            extra["alias"] = alias
        return self._signed_get("queryDevices", extra)

    def query_device_status(self, devices: list[dict]) -> list[dict]:
        """
        Return status for one or more devices.

        Parameters
        ----------
        devices : list of dicts with keys: pn, devcode, devaddr, sn
        """
        device_str = ";".join(
            f"{d['pn']},{d['devcode']},{d['devaddr']},{d['sn']}"
            for d in devices
        )
        return self._signed_get("queryDeviceStatus", {"device": device_str})["device"]

    def query_device_data_one_day(
        self,
        pn: str,
        devcode: int,
        devaddr: int,
        sn: str,
        date: str | None = None,
        i18n: str = "en_US",
    ) -> dict:
        """
        Return all field readings for a device on a given day.

        Returns
        -------
        dict with keys 'title' (list of field names/units) and 'row' (data rows).
        """
        extra: dict[str, Any] = {
            "pn": pn,
            "devcode": devcode,
            "devaddr": devaddr,
            "sn": sn,
            "i18n": i18n,
        }
        if date:
            extra["date"] = date
        return self._signed_get("queryDeviceDataOneDay", extra)

    def query_device_warning_count(
        self,
        pn: str,
        devcode: int,
        devaddr: int,
        sn: str,
        level: int | None = None,
        handled: bool | None = None,
    ) -> int:
        """Return the number of alarms on a specific device."""
        extra: dict[str, Any] = {
            "pn": pn,
            "devcode": devcode,
            "devaddr": devaddr,
            "sn": sn,
        }
        if level is not None:
            extra["level"] = level
        if handled is not None:
            extra["handle"] = str(handled).lower()
        return self._signed_get("queryDeviceWarningCount", extra)["count"]

    # ------------------------------------------------------------------
    # 6.x  Inverter / generating equipment energy
    # ------------------------------------------------------------------

    def query_device_energy_day(
        self,
        pn: str,
        devcode: int,
        devaddr: int,
        sn: str,
        date: str | None = None,
    ) -> str:
        """Return kWh generated by a device on a given day."""
        extra: dict[str, Any] = {
            "pn": pn,
            "devcode": devcode,
            "devaddr": devaddr,
            "sn": sn,
        }
        if date:
            extra["date"] = date
        return self._signed_get("queryDeviceEnergyDay", extra)["energy"]

    def query_device_energy_month(
        self,
        pn: str,
        devcode: int,
        devaddr: int,
        sn: str,
        date: str,
    ) -> str:
        """Return kWh generated by a device in a given month ('YYYY-MM')."""
        extra: dict[str, Any] = {
            "pn": pn,
            "devcode": devcode,
            "devaddr": devaddr,
            "sn": sn,
            "date": date,
        }
        return self._signed_get("queryDeviceEnergyMonth", extra)["energy"]

    def query_device_energy_month_per_day(
        self,
        pn: str,
        devcode: int,
        devaddr: int,
        sn: str,
        date: str | None = None,
    ) -> list[dict]:
        """Return daily kWh breakdown for a device in a given month."""
        extra: dict[str, Any] = {
            "pn": pn,
            "devcode": devcode,
            "devaddr": devaddr,
            "sn": sn,
        }
        if date:
            extra["date"] = date
        return self._signed_get("queryDeviceEnergyMonthPerDay", extra)["perday"]

    # ------------------------------------------------------------------
    # Convenience: pretty-print helpers
    # ------------------------------------------------------------------

    @property
    def session(self) -> AuthSession:
        return self._session

    def __repr__(self) -> str:
        status = "authenticated" if self._session.is_valid else "not authenticated"
        return f"<ShineMonitorClient usr={self.usr!r} [{status}]>"


# ---------------------------------------------------------------------------
# Demo / quick-start
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import json

    # ── Replace these with your real credentials ──────────────────────────
    USR = "vplant"
    PWD = "vplant"
    COMPANY_KEY = "company-key"
    # ──────────────────────────────────────────────────────────────────────

    client = ShineMonitorClient(usr=USR, pwd=PWD, company_key=COMPANY_KEY)

    print("=== Authenticating ===")
    session = client.auth()
    print(f"  token     : {session.token[:24]}…")
    print(f"  secret    : {session.secret[:24]}…")
    print(f"  role      : {session.role}")
    print()

    print("=== Account info ===")
    account = client.query_account_info()
    print(json.dumps(account, indent=2))
    print()

    print("=== Power station count ===")
    count = client.query_plant_count()
    print(f"  Total stations: {count}")
    print()

    print("=== Power stations (page 0, up to 10) ===")
    plants_data = client.query_plants(page=0, page_size=10)
    plants = plants_data.get("plant", [])
    for p in plants:
        print(f"  [{p['pid']}] {p['name']}  status={p['status']}")
    print()

    if plants:
        pid = plants[0]["pid"]

        print(f"=== Station {pid}: today's energy ===")
        energy = client.query_plant_energy_day(pid)
        print(f"  Energy today: {energy} kWh")
        print()

        print(f"=== Station {pid}: current active power ===")
        try:
            power = client.query_plant_active_power_current(pid)
            print(f"  Active power: {power} kW")
        except ShineMonitorError as exc:
            print(f"  (no live data: {exc})")
        print()

        print(f"=== Station {pid}: device tree ===")
        view = client.query_plant_device_view(pid)
        print(json.dumps(view, indent=2))
