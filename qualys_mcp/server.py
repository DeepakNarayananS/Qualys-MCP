"""Qualys MCP server.

Exposes Qualys as a small set of workflow-style tools. Each tool pulls from one
or more Qualys APIs and synthesises a compact, AI-friendly answer:

  check_connection   - verify both auth paths (FO session + Gateway bearer)
  security_overview  - scanners, scans, assets, and patch posture at a glance
  investigate        - deep-dive a CVE / QID (KnowledgeBase + affected hosts)
  assess_risk        - vulnerability + patch severity breakdown, module presence
  plan_remediation   - patch priorities and deployment-job status
  list_assets        - host inventory
  run_scan           - list or launch VM scans (launch is guarded)

Credentials are read from the environment (QUALYS_USERNAME, QUALYS_PASSWORD,
and QUALYS_POD or QUALYS_BASE_URL) so they never appear in tool arguments.
"""

from __future__ import annotations

import logging
import os
from collections import Counter

from fastmcp import FastMCP

from .client import QualysClient, QualysError

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("qualys-mcp")

mcp = FastMCP("qualys-mcp")

_SEVERITY_NAME = {"5": "Critical", "4": "High", "3": "Medium", "2": "Low", "1": "Info"}

# Single source of truth for the tool catalog — used by check_connection's
# chat output and kept in sync with the README table.
TOOL_CATALOG = [
    ("check_connection", "Verify connectivity and list available tools"),
    ("security_overview", "Daily briefing — scanners, scan status, assets, patch posture"),
    ("investigate", "Deep-dive a CVE or QID — KnowledgeBase details and affected hosts"),
    ("assess_risk", "Cross-domain risk — vulnerabilities, patches, cloud, containers"),
    ("plan_remediation", "Patch priorities by severity and deployment-job status"),
    ("list_assets", "Host inventory — IP, DNS, OS, last scan time"),
    ("run_scan", "List VM scans, or launch a new one"),
    ("reports", "Generate, list, download, and manage Qualys reports"),
]


def _tool_table() -> str:
    """Render the tool catalog as an aligned GitHub-style Markdown table."""
    name_w = max(len(n) for n, _ in TOOL_CATALOG)
    desc_w = max(len(d) for _, d in TOOL_CATALOG)
    name_w = max(name_w, len("Tool"))
    desc_w = max(desc_w, len("What it answers"))
    rows = [f"| {'Tool'.ljust(name_w)} | {'What it answers'.ljust(desc_w)} |",
            f"| {'-' * name_w} | {'-' * desc_w} |"]
    for name, desc in TOOL_CATALOG:
        rows.append(f"| {name.ljust(name_w)} | {desc.ljust(desc_w)} |")
    return "\n".join(rows)


_CLIENT: QualysClient | None = None


def _client() -> QualysClient:
    """Return a shared client (one FO session per server process).

    Reusing a single client avoids opening a new Qualys session on every tool
    call, which would otherwise hit the concurrent-login limit (CODE 2014).
    """
    global _CLIENT
    if _CLIENT is None:
        _CLIENT = QualysClient()
    return _CLIENT


def _safe(fn, default):
    """Run a client call, returning (value, error) so one failing module does
    not sink a whole workflow response."""
    try:
        return fn(), None
    except QualysError as exc:
        return default, str(exc)


# ---------------------------------------------------------------------------
# Connection
# ---------------------------------------------------------------------------

@mcp.tool
def check_connection() -> dict:
    """Verify Qualys connectivity and show the available tools.

    Tests both authentication paths (FO/VMDR session login and Gateway bearer
    token) and returns a chat-friendly status banner — healthy in green or not
    connected in red — followed by the tool catalog. Call this first.
    """
    client = _client()
    if not client.config.configured:
        report = ("## 🔴 Qualys MCP — Not Connected\n\n"
                  "Credentials are not configured. Set `QUALYS_USERNAME`, "
                  "`QUALYS_PASSWORD`, and `QUALYS_POD` (or `QUALYS_BASE_URL`).\n\n"
                  "### Available tools\n\n" + _tool_table())
        return {"status": "failed", "connected": False,
                "error": "Qualys not configured. Set QUALYS_USERNAME, QUALYS_PASSWORD, "
                         "and QUALYS_POD (or QUALYS_BASE_URL).",
                "report": report}

    fo_ok, fo_err = _safe(lambda: client.about() or True, False)
    gw_ok, gw_err = _safe(lambda: bool(client.get_bearer_token(force=True)), False)
    connected = bool(fo_ok or gw_ok)

    return {
        "status": "success" if connected else "failed",
        "connected": connected,
        "pod": client.config.pod or "(custom URL)",
        "base_url": client.config.base_url,
        "gateway_url": client.config.gateway_url,
        "username": client.config.username,
        "fo_api": {"ok": bool(fo_ok), "detail": fo_err or "session authenticated"},
        "gateway_api": {"ok": bool(gw_ok), "detail": gw_err or "bearer token acquired"},
        "report": _connection_report(client, connected, bool(fo_ok), fo_err,
                                     bool(gw_ok), gw_err),
    }


def _connection_report(client: QualysClient, connected: bool, fo_ok: bool,
                       fo_err: str, gw_ok: bool, gw_err: str) -> str:
    """Build the chat-friendly Markdown status banner + tool table."""
    if connected:
        header = "## 🟢 Qualys MCP — Connection Healthy"
    else:
        header = "## 🔴 Qualys MCP — Not Connected"

    fo_line = f"- {'🟢' if fo_ok else '🔴'} **FO / VMDR API** — {fo_err or 'session authenticated'}"
    gw_line = f"- {'🟢' if gw_ok else '🔴'} **Gateway API** — {gw_err or 'bearer token acquired'}"

    return (
        f"{header}\n\n"
        f"**Platform:** {client.config.pod or '(custom URL)'}  |  "
        f"**User:** {client.config.username}\n\n"
        f"{fo_line}\n{gw_line}\n\n"
        f"### Available tools\n\n{_tool_table()}"
    )


# ---------------------------------------------------------------------------
# Overview
# ---------------------------------------------------------------------------

@mcp.tool
def security_overview(quick: bool = False) -> dict:
    """A daily-briefing snapshot: scanners, scans, assets and patch posture.

    Args:
        quick: If true, skip the slower host-asset inventory call.
    """
    client = _client()
    scanners, scanners_err = _safe(client.list_scanners, [])
    scans, scans_err = _safe(lambda: client.list_scans(), [])
    patches, patches_err = _safe(
        lambda: client.pm_patch_count(group_by="vendorSeverity"), {})

    overview = {
        "status": "success",
        "scanners": {"count": len(scanners), "appliances": scanners,
                     "error": scanners_err},
        "scans": {"count": len(scans),
                  "running": [s for s in scans if s.get("state") == "Running"],
                  "recent": scans[:10], "error": scans_err},
        "patches_by_severity": patches.get("vendorSeverity", patches) or {},
        "patches_error": patches_err,
    }
    if not quick:
        hosts, hosts_err = _safe(lambda: client.list_host_assets(limit=500), [])
        overview["assets"] = {"count": len(hosts), "error": hosts_err}
    return overview


# ---------------------------------------------------------------------------
# Investigate
# ---------------------------------------------------------------------------

@mcp.tool
def investigate(target: str, limit: int = 25) -> dict:
    """Deep-dive a CVE or QID: KnowledgeBase details plus affected hosts.

    Args:
        target: A CVE ID (e.g. 'CVE-2024-3400') or a Qualys QID (e.g. '38906').
        limit: Max KnowledgeBase entries / hosts to return.
    """
    if not target:
        return {"status": "failed", "error": "target is required (a CVE ID or QID)"}
    client = _client()
    is_cve = target.upper().startswith("CVE-")
    kb, kb_err = _safe(
        lambda: client.search_knowledgebase(
            cve=target if is_cve else "",
            qids="" if is_cve else target,
            limit=limit),
        [])
    qids = ",".join(v["qid"] for v in kb if v.get("qid")) or ("" if is_cve else target)
    dets, dets_err = _safe(
        lambda: client.host_detections(qids=qids, limit=limit) if qids else [], [])
    # Group detections by host_id
    by_host = {}
    for d in dets:
        hid = d.get("host_id", "unknown")
        by_host.setdefault(hid, []).append(d)
    affected = [{"host_id": hid, "detections": len(ds)} for hid, ds in by_host.items()]
    return {
        "status": "success",
        "target": target,
        "knowledgebase": kb,
        "knowledgebase_error": kb_err,
        "affected_hosts": affected,
        "affected_count": len(affected),
        "detections_error": dets_err,
    }


# ---------------------------------------------------------------------------
# Risk
# ---------------------------------------------------------------------------

@mcp.tool
def assess_risk(scope: str = "all") -> dict:
    """Cross-domain risk snapshot.

    Args:
        scope: 'all', 'vulns' (host vulnerability severities), 'patches'
            (missing-patch severities), 'cloud', or 'containers'.
    """
    client = _client()
    result: dict = {"status": "success", "scope": scope}
    if scope in ("all", "vulns"):
        _risk_vulns(client, result)
    if scope in ("all", "patches"):
        _risk_patches(client, result)
    if scope in ("all", "cloud"):
        _risk_cloud(client, result)
    if scope in ("all", "containers"):
        _risk_containers(client, result)
    return result


def _risk_vulns(client: QualysClient, result: dict) -> None:
    dets, err = _safe(lambda: client.host_detections(limit=1000), [])
    sev = Counter()
    hosts_with_findings = set()
    for d in dets:
        sev[_SEVERITY_NAME.get(d.get("severity", ""), "Unknown")] += 1
        if d.get("host_id"):
            hosts_with_findings.add(d["host_id"])
    result["vulnerabilities_by_severity"] = dict(sev)
    result["hosts_with_findings"] = len(hosts_with_findings)
    if err:
        result["vulnerabilities_error"] = err


def _risk_patches(client: QualysClient, result: dict) -> None:
    patches, err = _safe(lambda: client.pm_patch_count(group_by="vendorSeverity"), {})
    result["missing_patches_by_severity"] = patches.get("vendorSeverity", {})
    if err:
        result["patches_error"] = err


def _risk_cloud(client: QualysClient, result: dict) -> None:
    cloud, err = _safe(lambda: client.cloud_connectors("aws"), {})
    content = cloud.get("content", []) if isinstance(cloud, dict) else []
    result["cloud_aws_connectors"] = len(content)
    if err:
        result["cloud_error"] = err


def _risk_containers(client: QualysClient, result: dict) -> None:
    _, err = _safe(client.container_image_count, {})
    result["container_module"] = "unavailable" if err else "available"
    if err:
        result["containers_error"] = err


# ---------------------------------------------------------------------------
# Remediation
# ---------------------------------------------------------------------------

@mcp.tool
def plan_remediation(platform: str = "Windows", severity: str = "") -> dict:
    """Patch priorities and deployment-job status from Patch Management.

    Args:
        platform: 'Windows', 'Linux', or 'Mac'.
        severity: Optional patch status filter, e.g. 'Missing' or 'Installed'.
    """
    client = _client()
    by_sev, sev_err = _safe(
        lambda: client.pm_patch_count(platform=platform, group_by="vendorSeverity",
                                      status=severity), {})
    total, total_err = _safe(lambda: client.pm_patch_count(platform=platform), {})
    jobs, jobs_err = _safe(lambda: client.pm_jobs(platform=platform, limit=10), [])
    return {
        "status": "success",
        "platform": platform,
        "total_patches": total.get("patches", {}).get("count") if isinstance(total, dict) else None,
        "patches_by_severity": by_sev.get("vendorSeverity", {}),
        "deployment_jobs": jobs,
        "errors": {k: v for k, v in
                   {"severity": sev_err, "total": total_err, "jobs": jobs_err}.items() if v},
    }


# ---------------------------------------------------------------------------
# Assets
# ---------------------------------------------------------------------------

@mcp.tool
def list_assets(limit: int = 100) -> dict:
    """List host assets in the subscription (IP, DNS, OS, last scan time).

    Args:
        limit: Maximum number of hosts to return (default 100).
    """
    try:
        hosts = _client().list_host_assets(limit=max(1, limit))
        return {"status": "success", "count": len(hosts), "hosts": hosts}
    except QualysError as exc:
        return {"status": "failed", "error": str(exc)}


# ---------------------------------------------------------------------------
# Scans
# ---------------------------------------------------------------------------

@mcp.tool
def run_scan(action: str = "list", state: str = "", title: str = "", ip: str = "",
             option_profile_id: str = "", scanner_name: str = "") -> dict:
    """List VM scans, or launch a new one.

    Args:
        action: 'list' (default) or 'launch'.
        state: For 'list', optional filter, e.g. 'Running', 'Finished', 'Error'.
        title: For 'launch', the scan title.
        ip: For 'launch', target IP or range (e.g. '10.0.0.5').
        option_profile_id: For 'launch', the option profile ID.
        scanner_name: For 'launch', optional scanner appliance for internal scans.

    Launching performs a real scan in Qualys — keep this tool out of autoApprove.
    """
    client = _client()
    if action == "launch":
        if not (title and ip and option_profile_id):
            return {"status": "failed",
                    "error": "launch requires title, ip and option_profile_id "
                             "(see list_option_profiles via the API)"}
        try:
            return {"status": "success", "result":
                    client.launch_scan(title, ip, option_profile_id, scanner_name)}
        except QualysError as exc:
            return {"status": "failed", "error": str(exc)}
    try:
        scans = client.list_scans(state=state)
        return {"status": "success", "count": len(scans), "scans": scans}
    except QualysError as exc:
        return {"status": "failed", "error": str(exc)}


def main() -> None:
    """Entry point used by ``python -m qualys_mcp``."""
    logger.info("Starting Qualys MCP server")
    mcp.run()


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------

@mcp.tool
def reports(action: str = "list", report_id: str = "", template_id: str = "",
            title: str = "", output_format: str = "pdf",
            report_type: str = "Scan") -> dict:
    """Generate, list, download, or delete Qualys reports.

    Args:
        action: 'list' (default), 'templates', 'launch', 'fetch', or 'delete'.
        report_id: Report ID — required for 'fetch' and 'delete'.
        template_id: Report template ID — required for 'launch' (see action='templates').
        title: Optional report title for 'launch'.
        output_format: For 'launch', e.g. 'pdf', 'csv', 'xml', 'html'.
        report_type: For 'launch', e.g. 'Scan', 'Patch', 'Map'.

    'fetch' downloads the finished report to ~/Documents/Qualys_Reports/ and
    returns the saved path (report content is binary, so it is not inlined).
    'launch' and 'delete' change state in Qualys — keep this out of autoApprove
    if you want a click before generating or removing reports.
    """
    client = _client()
    try:
        if action == "list":
            items = client.list_reports(report_id=report_id)
            return {"status": "success", "count": len(items), "reports": items}
        if action == "templates":
            tmpls = client.list_report_templates()
            return {"status": "success", "count": len(tmpls), "templates": tmpls}
        if action == "launch":
            if not template_id:
                return {"status": "failed",
                        "error": "launch requires template_id (see action='templates')"}
            return {"status": "success",
                    "result": client.launch_report(template_id, title, output_format, report_type)}
        if action == "fetch":
            if not report_id:
                return {"status": "failed", "error": "fetch requires report_id"}
            return _save_report(client, report_id)
        if action == "delete":
            if not report_id:
                return {"status": "failed", "error": "delete requires report_id"}
            return {"status": "success", "result": client.delete_report(report_id)}
        return {"status": "failed",
                "error": f"unknown action '{action}'. Use list, templates, launch, fetch, or delete."}
    except QualysError as exc:
        return {"status": "failed", "error": str(exc)}


def _save_report(client: QualysClient, report_id: str) -> dict:
    content = client.fetch_report(report_id)
    out_dir = os.path.join(os.path.expanduser("~"), "Documents", "Qualys_Reports")
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, f"qualys_report_{report_id}.{_sniff_ext(content)}")
    with open(path, "wb") as fh:
        fh.write(content)
    return {"status": "success", "report_id": report_id, "bytes": len(content),
            "saved_to": path}


def _sniff_ext(content: bytes) -> str:
    """Guess a file extension from the report's leading bytes."""
    if content[:4] == b"%PDF":
        return "pdf"
    if content[:5] == b"<?xml":
        return "xml"
    if content[:2] == b"PK":
        return "zip"
    return "dat"


if __name__ == "__main__":
    main()
