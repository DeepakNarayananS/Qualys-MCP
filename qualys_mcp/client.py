"""Qualys API client.

A small synchronous wrapper around the Qualys APIs. It resolves the platform
(POD) to both the FO/QPS base URL and the Gateway URL, and handles all three
authentication styles Qualys uses:

  * FO / VMDR API  -> session cookie (login once, reuse the cookie). Falls back
    to Basic auth when the account allows it.
  * Gateway API    -> bearer JWT (POST /auth).

It does simple retries and parses XML responses, so the MCP server can expose a
handful of clean workflow tools.
"""

from __future__ import annotations

import base64
import json
import os
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass

import httpx

# Qualys platform (POD) -> (FO/QPS base URL, Gateway URL).
# See https://www.qualys.com/platform-identification/
POD_MAP = {
    "US1": ("https://qualysapi.qualys.com", "https://gateway.qg1.apps.qualys.com"),
    "US2": ("https://qualysapi.qg2.apps.qualys.com", "https://gateway.qg2.apps.qualys.com"),
    "US3": ("https://qualysapi.qg3.apps.qualys.com", "https://gateway.qg3.apps.qualys.com"),
    "US4": ("https://qualysapi.qg4.apps.qualys.com", "https://gateway.qg4.apps.qualys.com"),
    "EU1": ("https://qualysapi.qualys.eu", "https://gateway.qg1.apps.qualys.eu"),
    "EU2": ("https://qualysapi.qg2.apps.qualys.eu", "https://gateway.qg2.apps.qualys.eu"),
    "EU3": ("https://qualysapi.qg3.apps.qualys.eu", "https://gateway.qg3.apps.qualys.eu"),
    "IN1": ("https://qualysapi.qg1.apps.qualys.in", "https://gateway.qg1.apps.qualys.in"),
    "CA1": ("https://qualysapi.qg1.apps.qualys.ca", "https://gateway.qg1.apps.qualys.ca"),
    "AE1": ("https://qualysapi.qg1.apps.qualys.ae", "https://gateway.qg1.apps.qualys.ae"),
    "UK1": ("https://qualysapi.qg1.apps.qualys.co.uk", "https://gateway.qg1.apps.qualys.co.uk"),
    "AU1": ("https://qualysapi.qg1.apps.qualys.com.au", "https://gateway.qg1.apps.qualys.com.au"),
    "KSA1": ("https://qualysapi.qg1.apps.qualys.sa", "https://gateway.qg1.apps.qualys.sa"),
}

SESSION_ENDPOINT = "/api/2.0/fo/session/"
SCAN_ENDPOINT = "/api/2.0/fo/scan/"
REPORT_ENDPOINT = "/api/2.0/fo/report/"
QPS_HOSTASSET = "/qps/rest/2.0/search/am/hostasset"
QPS_HOSTASSET_COUNT = "/qps/rest/2.0/count/am/hostasset"
RETRY_STATUS = (429, 502, 503, 504)
TOKEN_TTL_SECONDS = 12600  # gateway JWT lives ~4h; refresh a little early


class QualysError(Exception):
    """Raised when a Qualys API call fails or the client is misconfigured."""


@dataclass
class QualysConfig:
    """Connection settings, populated from the environment by default."""

    username: str = ""
    password: str = ""
    pod: str = ""
    base_url: str = ""
    gateway_url: str = ""
    ssl_verify: bool = True
    timeout: int = 30
    max_retries: int = 3

    @classmethod
    def from_env(cls) -> "QualysConfig":
        cfg = cls(
            username=os.environ.get("QUALYS_USERNAME", ""),
            password=os.environ.get("QUALYS_PASSWORD", ""),
            pod=os.environ.get("QUALYS_POD", "").strip().upper(),
            base_url=os.environ.get("QUALYS_BASE_URL", "").rstrip("/"),
            gateway_url=os.environ.get("QUALYS_GATEWAY_URL", "").rstrip("/"),
            ssl_verify=os.environ.get("QUALYS_SSL_VERIFY", "true").strip().lower()
            not in ("0", "false", "no"),
            timeout=int(os.environ.get("QUALYS_TIMEOUT", "30")),
            max_retries=int(os.environ.get("QUALYS_MAX_RETRIES", "3")),
        )
        if cfg.pod in POD_MAP:
            pod_base, pod_gateway = POD_MAP[cfg.pod]
            cfg.base_url = cfg.base_url or pod_base
            cfg.gateway_url = cfg.gateway_url or pod_gateway
        return cfg

    @property
    def configured(self) -> bool:
        return bool(self.base_url and self.username and self.password)


class QualysClient:
    """Qualys client supporting FO (session/Basic) and Gateway (bearer) auth."""

    def __init__(self, config: QualysConfig | None = None):
        self.config = config or QualysConfig.from_env()
        self._http = httpx.Client(timeout=self.config.timeout, verify=self.config.ssl_verify)
        self._logged_in = False
        self._token = ""
        self._token_time = 0.0

    def close(self) -> None:
        self._http.close()

    # ------------------------------------------------------------------
    # Config / auth helpers
    # ------------------------------------------------------------------

    def _check_config(self) -> None:
        if not self.config.configured:
            missing = []
            if not self.config.username:
                missing.append("QUALYS_USERNAME")
            if not self.config.password:
                missing.append("QUALYS_PASSWORD")
            if not self.config.base_url:
                missing.append("QUALYS_POD or QUALYS_BASE_URL")
            raise QualysError("Qualys is not configured. Set " + ", ".join(missing) + ".")

    @property
    def _basic_auth(self) -> str:
        raw = f"{self.config.username}:{self.config.password}".encode()
        return "Basic " + base64.b64encode(raw).decode()

    def login(self, force: bool = False) -> None:
        """Establish an FO session cookie. Safe to call repeatedly."""
        self._check_config()
        if self._logged_in and not force:
            return
        try:
            response = self._http.post(
                f"{self.config.base_url}{SESSION_ENDPOINT}",
                data={"action": "login", "username": self.config.username,
                      "password": self.config.password},
                headers={"X-Requested-With": "qualys-mcp"},
            )
        except httpx.RequestError as exc:
            raise QualysError(f"connection error: {exc}") from exc
        if response.status_code == 200:
            self._logged_in = True
            return
        raise QualysError(
            f"FO session login failed (HTTP {response.status_code}): "
            f"{_simple_text(response.text) or response.text[:200]}"
        )

    def logout(self) -> None:
        """End the FO session so we don't leak concurrent logins (CODE 2014)."""
        if not self._logged_in:
            return
        try:
            self._http.post(f"{self.config.base_url}{SESSION_ENDPOINT}",
                            data={"action": "logout"},
                            headers={"X-Requested-With": "qualys-mcp"})
        except httpx.RequestError:
            pass
        finally:
            self._logged_in = False

    def __enter__(self) -> "QualysClient":
        return self

    def __exit__(self, *exc) -> None:
        self.logout()
        self.close()

    def get_bearer_token(self, force: bool = False) -> str:
        """Acquire (and cache) a Gateway bearer token."""
        self._check_config()
        if not self.config.gateway_url:
            raise QualysError("No gateway URL resolved for this POD.")
        if self._token and not force and time.time() - self._token_time < TOKEN_TTL_SECONDS:
            return self._token
        try:
            response = self._http.post(
                f"{self.config.gateway_url}/auth",
                data={"username": self.config.username, "password": self.config.password,
                      "token": "true"},
                headers={"Content-Type": "application/x-www-form-urlencoded",
                         "X-Requested-With": "qualys-mcp"},
            )
        except httpx.RequestError as exc:
            raise QualysError(f"connection error: {exc}") from exc
        if response.status_code in (200, 201):
            self._token = response.text.strip()
            self._token_time = time.time()
            return self._token
        raise QualysError(
            f"Gateway auth failed (HTTP {response.status_code}): {response.text[:200]}"
        )

    # ------------------------------------------------------------------
    # FO request (session cookie, with Basic-auth fallback)
    # ------------------------------------------------------------------

    def fo_request(self, method: str, path: str, params: dict | None = None,
                   data: dict | None = None, timeout: int | None = None) -> str:
        """Call the classic FO/VMDR API. Logs in for a session cookie first."""
        self._check_config()
        self.login()
        url = f"{self.config.base_url}{path}"
        headers = {"X-Requested-With": "qualys-mcp"}

        def send():
            return self._http.request(method, url, params=params, data=data,
                                      headers=headers, timeout=timeout or self.config.timeout)

        return self._retry(send, on_401=lambda: self.login(force=True)).text

    # ------------------------------------------------------------------
    # Gateway request (bearer token)
    # ------------------------------------------------------------------

    def gw_request(self, method: str, path: str, params: dict | None = None,
                   json_body: dict | None = None, timeout: int | None = None):
        """Call a Gateway API endpoint. Returns parsed JSON (or {} on 204)."""
        self._check_config()
        url = f"{self.config.gateway_url}{path}"

        def send():
            headers = {"Authorization": f"Bearer {self.get_bearer_token()}",
                       "X-Requested-With": "qualys-mcp", "Accept": "application/json"}
            if json_body is not None:
                headers["Content-Type"] = "application/json"
            return self._http.request(method, url, params=params, json=json_body,
                                      headers=headers, timeout=timeout or self.config.timeout)

        response = self._retry(send, on_401=lambda: self.get_bearer_token(force=True))
        if response.status_code == 204 or not response.text.strip():
            return {}
        try:
            return response.json()
        except json.JSONDecodeError:
            return {"raw": response.text}

    def _retry(self, send, on_401) -> httpx.Response:
        """Shared retry loop: backoff on transient errors, one refresh on 401."""
        last_error = ""
        for attempt in range(self.config.max_retries):
            is_last = attempt == self.config.max_retries - 1
            try:
                response = send()
            except httpx.RequestError as exc:
                last_error = f"connection error: {exc}"
                _backoff_or_raise(last_error, attempt, is_last, exc)
                continue
            if response.status_code in (200, 204):
                return response
            if response.status_code in RETRY_STATUS and not is_last:
                time.sleep(_retry_after(response, attempt))
                continue
            if response.status_code == 401 and attempt == 0:
                on_401()
                continue
            raise QualysError(_http_error(response))
        raise QualysError(last_error or "request failed")

    # ------------------------------------------------------------------
    # QPS request (Asset Management — header credentials)
    # ------------------------------------------------------------------

    def qps_request(self, path: str, xml_body: str = "") -> dict:
        """POST to a QPS Asset Management endpoint.

        QPS uses lightweight header credentials (lowercase ``user``/``password``),
        which work even when an account has HTTP Basic auth disabled for the API.
        Returns the parsed ``ServiceResponse`` dict.
        """
        self._check_config()
        body = xml_body or "<ServiceRequest></ServiceRequest>"
        headers = {
            "X-Requested-With": "qualys-mcp",
            "Content-Type": "application/xml",
            "Accept": "application/json",
            "user": self.config.username,
            "password": self.config.password,
        }

        def send():
            return self._http.post(f"{self.config.base_url}{path}", content=body,
                                   headers=headers, timeout=self.config.timeout)

        response = self._retry(send, on_401=lambda: None)
        try:
            data = response.json().get("ServiceResponse", {})
        except json.JSONDecodeError:
            raise QualysError(f"QPS returned non-JSON: {response.text[:200]}")
        if data.get("responseCode") not in (None, "SUCCESS"):
            raise QualysError(
                f"QPS {data.get('responseCode')}: "
                f"{data.get('responseErrorDetails', {}).get('errorMessage', '')}")
        return data

    # ------------------------------------------------------------------
    # FO convenience methods
    # ------------------------------------------------------------------

    def about(self) -> bool:
        """Validate FO access by establishing a session login.

        The session login returns HTTP 200 with a SIMPLE_RETURN on success, so
        it is the most reliable FO health check (the legacy /msp/about.php path
        does not honor session cookies on all subscriptions).
        """
        self.login()
        return True

    def list_scans(self, state: str = "", scan_ref: str = "") -> list[dict]:
        params = {"action": "list", "show_status": "1"}
        if state:
            params["state"] = state
        if scan_ref:
            params["scan_ref"] = scan_ref
        return parse_scan_list(self.fo_request("GET", SCAN_ENDPOINT, params=params))

    def list_host_assets(self, limit: int = 100, name: str = "") -> list[dict]:
        """List host assets via the QPS Asset Management API (works with header
        credentials, including Cloud Agent assets)."""
        filt = (f'<filters><Criteria field="name" operator="CONTAINS">{name}'
                f'</Criteria></filters>' if name else "")
        xml = (f"<ServiceRequest><preferences><limitResults>{limit}</limitResults>"
               f"</preferences>{filt}</ServiceRequest>")
        data = self.qps_request(QPS_HOSTASSET, xml)
        return parse_hostassets(data)

    def list_scanners(self) -> list[dict]:
        params = {"action": "list", "output_mode": "full"}
        return parse_appliance_list(self.fo_request("GET", "/api/2.0/fo/appliance/", params=params))

    def list_option_profiles(self) -> str:
        return self.fo_request("GET", "/api/2.0/fo/subscription/option_profile/vm/",
                               params={"action": "list"})

    def search_knowledgebase(self, qids: str = "", cve: str = "", severity: int = 0,
                             limit: int = 50) -> list[dict]:
        params: dict[str, str] = {"action": "list", "truncation_limit": str(limit), "details": "Basic"}
        if qids:
            params["ids"] = qids
        if cve:
            params["cve_id"] = cve
        if severity:
            params["severities"] = str(severity)
        return parse_knowledgebase(self.fo_request("GET", "/api/2.0/fo/knowledge_base/vuln/", params=params))

    def host_detections(self, severity: int = 0, qids: str = "", ips: str = "",
                        limit: int = 200) -> list[dict]:
        """List per-host vulnerability detections via the QPS Asset Management
        API (``hostinstancevuln``), which works with header credentials."""
        criteria = []
        if severity:
            criteria.append(f'<Criteria field="severity" operator="EQUALS">{severity}</Criteria>')
        if qids:
            first_qid = qids.split(",")[0].strip()
            criteria.append(f'<Criteria field="qid" operator="EQUALS">{first_qid}</Criteria>')
        filt = f"<filters>{''.join(criteria)}</filters>" if criteria else ""
        xml = (f"<ServiceRequest><preferences><limitResults>{limit}</limitResults>"
               f"</preferences>{filt}</ServiceRequest>")
        data = self.qps_request("/qps/rest/2.0/search/am/hostinstancevuln", xml)
        return parse_hostinstancevuln(data)

    def launch_scan(self, title: str, ip: str, option_profile_id: str, iscanner_name: str = "") -> dict:
        data = {"action": "launch", "scan_title": title, "ip": ip, "option_id": option_profile_id}
        if iscanner_name:
            data["iscanner_name"] = iscanner_name
        return parse_simple_return(self.fo_request("POST", SCAN_ENDPOINT, data=data, timeout=60))

    # ------------------------------------------------------------------
    # Reporting (FO Report API)
    # ------------------------------------------------------------------

    def list_reports(self, report_id: str = "") -> list[dict]:
        params = {"action": "list"}
        if report_id:
            params["id"] = report_id
        return parse_report_list(self.fo_request("GET", REPORT_ENDPOINT, params=params))

    def list_report_templates(self) -> list[dict]:
        return parse_template_list(
            self.fo_request("GET", "/api/2.0/fo/report/template/scan/", params={"action": "list"}))

    def launch_report(self, template_id: str, title: str = "",
                      output_format: str = "pdf", report_type: str = "Scan") -> dict:
        data = {"action": "launch", "template_id": template_id,
                "output_format": output_format, "report_type": report_type}
        if title:
            data["report_title"] = title
        return parse_simple_return(self.fo_request("POST", REPORT_ENDPOINT, data=data, timeout=60))

    def fetch_report(self, report_id: str) -> bytes:
        """Download a finished report's content as raw bytes."""
        self._check_config()
        self.login()
        params = {"action": "fetch", "id": report_id}

        def send():
            return self._http.get(f"{self.config.base_url}{REPORT_ENDPOINT}", params=params,
                                  headers={"X-Requested-With": "qualys-mcp"},
                                  timeout=self.config.timeout)

        return self._retry(send, on_401=lambda: self.login(force=True)).content

    def delete_report(self, report_id: str) -> dict:
        data = {"action": "delete", "id": report_id}
        return parse_simple_return(self.fo_request("POST", REPORT_ENDPOINT, data=data))

    # ------------------------------------------------------------------
    # Gateway convenience methods (Patch Management, Container, Cloud)
    # ------------------------------------------------------------------

    def pm_patch_count(self, platform: str = "Windows", group_by: str = "", status: str = "") -> dict:
        params = {"platform": platform}
        if group_by:
            params["groupBy"] = group_by
        if status:
            params["status"] = status
        return self.gw_request("GET", "/pm/v1/patches/count", params=params)

    def pm_jobs(self, platform: str = "Windows", limit: int = 10, status: str = "") -> list:
        params = {"platform": platform, "pageSize": str(limit)}
        if status:
            params["status"] = status
        result = self.gw_request("GET", "/pm/v1/deploymentjobs", params=params)
        return result if isinstance(result, list) else []

    def container_image_count(self) -> dict:
        return self.gw_request("GET", "/csapi/v1.3/images", params={"limit": "1"})

    def cloud_connectors(self, provider: str = "aws") -> dict:
        return self.gw_request("GET", f"/cloudview-api/rest/v1/{provider}/connectors",
                               params={"pageSize": "10"})


# ----------------------------------------------------------------------
# Response / error helpers
# ----------------------------------------------------------------------

def _backoff_or_raise(message: str, attempt: int, is_last: bool, exc: Exception) -> None:
    if is_last:
        raise QualysError(message) from exc
    time.sleep(2**attempt)


def _retry_after(response: httpx.Response, attempt: int) -> float:
    header = response.headers.get("Retry-After") or response.headers.get("X-RateLimit-ToWait-Sec")
    try:
        return float(header) if header else 2**attempt
    except ValueError:
        return 2**attempt


def _http_error(response: httpx.Response) -> str:
    if response.status_code == 401:
        return "Authentication failed (HTTP 401). Check QUALYS_USERNAME/PASSWORD."
    return f"Qualys API returned HTTP {response.status_code}: {response.text[:300]}"


def _simple_text(text: str) -> str:
    root = _root(text)
    if root is None:
        return ""
    return root.findtext(".//RESPONSE/TEXT", "")


# ----------------------------------------------------------------------
# XML parsing helpers
# ----------------------------------------------------------------------

def _root(text: str) -> ET.Element | None:
    try:
        return ET.fromstring(text)
    except ET.ParseError:
        return None


def parse_simple_return(text: str) -> dict:
    root = _root(text)
    if root is None:
        return {"ok": False, "error": "invalid_xml", "raw": text[:300]}
    response = root.find(".//RESPONSE")
    if response is None:
        return {"ok": False, "error": "missing_response", "raw": text[:300]}
    result: dict = {
        "ok": True,
        "datetime": response.findtext("DATETIME", ""),
        "code": response.findtext("CODE", ""),
        "text": response.findtext("TEXT", ""),
        "items": {},
    }
    for item in response.findall(".//ITEM"):
        key = item.findtext("KEY", "")
        if key:
            result["items"][key.lower()] = item.findtext("VALUE", "")
    return result


def parse_scan_list(text: str) -> list[dict]:
    root = _root(text)
    if root is None:
        return []
    return [{
        "ref": s.findtext("REF", ""),
        "title": s.findtext("TITLE", ""),
        "state": s.findtext("STATUS/STATE", ""),
        "target": s.findtext("TARGET", ""),
        "type": s.findtext("TYPE", ""),
        "scanner": s.findtext("SCANNER_APPLIANCE/FRIENDLY_NAME", ""),
        "launched": s.findtext("LAUNCH_DATETIME", ""),
    } for s in root.findall(".//SCAN")]


def parse_host_list(text: str) -> list[dict]:
    root = _root(text)
    if root is None:
        return []
    return [{
        "id": h.findtext("ID", ""),
        "ip": h.findtext("IP", ""),
        "dns": h.findtext("DNS", ""),
        "netbios": h.findtext("NETBIOS", ""),
        "os": h.findtext("OS", ""),
        "last_scan": h.findtext("LAST_SCAN_DATETIME", ""),
    } for h in root.findall(".//HOST")]


def parse_appliance_list(text: str) -> list[dict]:
    root = _root(text)
    if root is None:
        return []
    return [{
        "id": a.findtext("ID", ""),
        "name": a.findtext("NAME", "") or a.findtext("FRIENDLY_NAME", ""),
        "status": a.findtext("STATUS", ""),
        "running_scans": a.findtext("RUNNING_SCAN_COUNT", ""),
    } for a in root.findall(".//APPLIANCE")]


def parse_knowledgebase(text: str) -> list[dict]:
    root = _root(text)
    if root is None:
        return []
    return [{
        "qid": v.findtext("QID", ""),
        "title": v.findtext("TITLE", ""),
        "severity": v.findtext("SEVERITY_LEVEL", ""),
        "category": v.findtext("CATEGORY", ""),
        "published": v.findtext("PUBLISHED_DATETIME", ""),
        "cve": [c.findtext("ID", "") for c in v.findall(".//CVE_ID")],
    } for v in root.findall(".//VULN")]


def parse_detections(text: str) -> list[dict]:
    root = _root(text)
    if root is None:
        return []
    hosts = []
    for host in root.findall(".//HOST"):
        dets = [{
            "qid": d.findtext("QID", ""),
            "type": d.findtext("TYPE", ""),
            "severity": d.findtext("SEVERITY", ""),
            "status": d.findtext("STATUS", ""),
            "last_found": d.findtext("LAST_FOUND_DATETIME", ""),
        } for d in host.findall(".//DETECTION")]
        hosts.append({
            "id": host.findtext("ID", ""),
            "ip": host.findtext("IP", ""),
            "dns": host.findtext("DNS", ""),
            "os": host.findtext("OS", ""),
            "detections": dets,
        })
    return hosts


def parse_report_list(text: str) -> list[dict]:
    root = _root(text)
    if root is None:
        return []
    return [{
        "id": r.findtext("ID", ""),
        "title": r.findtext("TITLE", ""),
        "type": r.findtext("TYPE", ""),
        "status": r.findtext("STATUS/STATE", ""),
        "format": r.findtext("OUTPUT_FORMAT", ""),
        "size": r.findtext("SIZE", ""),
        "launched": r.findtext("LAUNCH_DATETIME", ""),
        "expires": r.findtext("EXPIRATION_DATETIME", ""),
    } for r in root.findall(".//REPORT")]


def parse_template_list(text: str) -> list[dict]:
    root = _root(text)
    if root is None:
        return []
    templates = []
    for t in root.findall(".//REPORT_TEMPLATE"):
        templates.append({
            "id": t.findtext("ID", ""),
            "title": t.findtext("TITLE", ""),
            "type": t.findtext("TYPE", ""),
            "template_type": t.findtext("TEMPLATE_TYPE", ""),
            "global": t.findtext("GLOBAL", ""),
        })
    return templates


def parse_hostassets(service_response: dict) -> list[dict]:
    """Parse a QPS Asset Management ServiceResponse into a flat host list."""
    hosts = []
    for item in service_response.get("data", []):
        ha = item.get("HostAsset", {})
        agent = ha.get("agentInfo", {}) or {}
        hosts.append({
            "id": ha.get("id"),
            "name": ha.get("name", ""),
            "ip": ha.get("address", ""),
            "dns": ha.get("dnsHostName", "") or ha.get("fqdn", ""),
            "netbios": ha.get("netbiosName", ""),
            "os": ha.get("os", ""),
            "tracking": ha.get("trackingMethod", ""),
            "qweb_host_id": ha.get("qwebHostId"),
            "agent_status": agent.get("status", ""),
            "last_checkin": agent.get("lastCheckedIn", ""),
            "last_system_boot": ha.get("lastSystemBoot", ""),
        })
    return hosts


def parse_hostinstancevuln(service_response: dict) -> list[dict]:
    """Parse a QPS HostInstanceVuln ServiceResponse into a flat detection list.

    Field names follow the QPS Asset Management schema; missing keys default to
    empty so the parser is resilient across pod/schema variations.
    """
    dets = []
    for item in service_response.get("data", []):
        v = item.get("HostInstanceVuln", item.get("HostAssetVuln", {})) or {}
        dets.append({
            "qid": str(v.get("qid", "")),
            "severity": str(v.get("severity", "")),
            "type": v.get("type", ""),
            "status": v.get("status", ""),
            "host_id": v.get("hostId") or v.get("assetId"),
            "first_found": v.get("firstFound", ""),
            "last_found": v.get("lastFound", ""),
            "port": v.get("port", ""),
            "protocol": v.get("protocol", ""),
        })
    return dets
