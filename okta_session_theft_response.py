#!/usr/bin/env python3
"""Dependency-free response automation for suspected Okta session cookie theft."""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import json
import os
import re
import sys
import textwrap
import time
from dataclasses import dataclass
from email.message import EmailMessage
from pathlib import Path
from typing import Any
from urllib import error, parse, request


DETECTION_NAME = "Suspected Okta Session Cookie Theft"

# Transient HTTP statuses worth retrying with backoff.
RETRYABLE_STATUSES = frozenset({429, 500, 502, 503, 504})
MAX_RETRIES = 3
BACKOFF_BASE_SECONDS = 1.0


class ApiError(RuntimeError):
    pass


@dataclass
class Config:
    okta_org_url: str
    okta_api_token: str
    virustotal_api_key: str
    openai_api_key: str
    openai_model: str
    slack_bot_token: str
    gmail_access_token: str
    gmail_user_id: str
    gmail_from_email: str
    soc_slack_channel: str | None

    @classmethod
    def from_env(cls) -> "Config":
        return cls(
            okta_org_url=os.getenv("OKTA_ORG_URL", "").rstrip("/"),
            okta_api_token=os.getenv("OKTA_API_TOKEN", ""),
            virustotal_api_key=os.getenv("VIRUSTOTAL_API_KEY", ""),
            openai_api_key=os.getenv("OPENAI_API_KEY", ""),
            openai_model=os.getenv("OPENAI_MODEL", "gpt-5-mini"),
            slack_bot_token=os.getenv("SLACK_BOT_TOKEN", ""),
            gmail_access_token=os.getenv("GMAIL_ACCESS_TOKEN", ""),
            gmail_user_id=os.getenv("GMAIL_USER_ID", "me"),
            gmail_from_email=os.getenv("GMAIL_FROM_EMAIL", ""),
            soc_slack_channel=os.getenv("SOC_SLACK_CHANNEL") or None,
        )

    def require_env(self, required: dict[str, str], context: str = "live run") -> None:
        missing = [name for name, value in required.items() if not value]
        if missing:
            raise SystemExit(
                f"Missing required environment variables for {context}: "
                + ", ".join(missing)
            )


@dataclass
class IpEnrichment:
    compact: dict[str, Any]
    verdict: dict[str, Any]


def load_dotenv(path: Path) -> None:
    if not path.exists():
        return

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        os.environ.setdefault(key, value)


def http_json(
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    body: dict[str, Any] | None = None,
    expected_statuses: tuple[int, ...] = (200,),
    max_retries: int = MAX_RETRIES,
) -> dict[str, Any]:
    merged_headers = headers.copy() if headers else {}
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        merged_headers.setdefault("Content-Type", "application/json")

    req = request.Request(url, data=data, headers=merged_headers, method=method)

    for attempt in range(max_retries + 1):
        try:
            with request.urlopen(req, timeout=30) as resp:
                raw = resp.read().decode("utf-8")
                if resp.status not in expected_statuses:
                    raise ApiError(f"{method} {url} returned HTTP {resp.status}: {raw}")
                return json.loads(raw) if raw else {}
        except error.HTTPError as exc:
            retryable = exc.code in RETRYABLE_STATUSES
            reason, delay = f"HTTP {exc.code}", _retry_after_seconds(exc, attempt)
            detail = f"returned HTTP {exc.code}: {exc.read().decode('utf-8', errors='replace')}"
        except error.URLError as exc:
            retryable = True
            reason = str(exc.reason)
            delay = BACKOFF_BASE_SECONDS * (2 ** attempt)
            detail = f"failed: {reason}"

        if retryable and attempt < max_retries:
            print(
                f"[~] {method} {url} {reason}; retrying in {delay:.1f}s "
                f"({attempt + 1}/{max_retries})...",
                file=sys.stderr,
            )
            time.sleep(delay)
            continue
        raise ApiError(f"{method} {url} {detail}")

    raise ApiError(f"{method} {url} failed after {max_retries} retries")


def _retry_after_seconds(exc: error.HTTPError, attempt: int) -> float:
    retry_after = exc.headers.get("Retry-After") if exc.headers else None
    if retry_after:
        try:
            return max(0.0, float(retry_after))
        except ValueError:
            pass
    return BACKOFF_BASE_SECONDS * (2 ** attempt)


_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def is_valid_email(value: str | None) -> bool:
    return bool(value) and bool(_EMAIL_RE.match(value.strip()))


def first_value(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        return str(value[0]) if value else ""
    return str(value)


def normalize_alert(raw_alert: dict[str, Any]) -> dict[str, Any]:
    """Normalize a clean sample payload or a Chronicle-style outcome payload."""
    activity_fields = {
        "ip": "ip{n}",
        "asn": "e{e}_asn",
        "city": "e{e}_cities",
        "user_agent": "e{e}_ua",
        "timestamp": "e{e}_timestamp",
    }

    def build_activity(source: dict[str, Any], event: int) -> dict[str, str]:
        return {
            field: first_value(
                source.get(field) or raw_alert.get(fmt.format(e=event, n=event))
            )
            for field, fmt in activity_fields.items()
        }

    normalized = {
        "detection_name": raw_alert.get("detection_name", DETECTION_NAME),
        "severity": raw_alert.get("severity", "High"),
        "user_id": first_value(raw_alert.get("user_id") or raw_alert.get("userid")),
        "user_email": first_value(raw_alert.get("user_email") or raw_alert.get("user_id")),
        "slack_channel": first_value(raw_alert.get("slack_channel") or raw_alert.get("slack_user_id")),
        "external_session_id": first_value(
            raw_alert.get("external_session_id") or raw_alert.get("externalSessionId")
        ),
        "original_activity": build_activity(raw_alert.get("original_activity", {}), 1),
        "suspicious_activity": build_activity(raw_alert.get("suspicious_activity", {}), 2),
    }

    required = {
        "user_id": normalized["user_id"],
        "external_session_id": normalized["external_session_id"],
        "original_activity.ip": normalized["original_activity"]["ip"],
        "suspicious_activity.ip": normalized["suspicious_activity"]["ip"],
    }
    missing = [name for name, value in required.items() if not value]
    if missing:
        raise SystemExit(f"Alert payload is missing required fields: {', '.join(missing)}")

    return normalized


def get_virustotal_ip_report(ip: str, api_key: str) -> dict[str, Any]:
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{parse.quote(ip)}"
    return http_json(
        "GET",
        url,
        headers={"x-apikey": api_key, "Accept": "application/json"},
    )


def deterministic_vt_verdict(vt_report: dict[str, Any]) -> dict[str, Any]:
    """Compute a hard-signal verdict from VirusTotal data before LLM analysis."""
    attributes = vt_report.get("data", {}).get("attributes", {})
    stats = attributes.get("last_analysis_stats") or {}
    malicious = int(stats.get("malicious") or 0)
    suspicious = int(stats.get("suspicious") or 0)
    votes = attributes.get("total_votes") or {}
    malicious_votes = int(votes.get("malicious") or 0)

    if malicious >= 3 or (malicious >= 1 and malicious_votes >= 1):
        verdict, confidence = "malicious", "high"
    elif malicious >= 1 or suspicious >= 2 or malicious_votes >= 2:
        verdict, confidence = "suspicious", "medium"
    else:
        verdict, confidence = "benign", "low"

    return {
        "verdict": verdict,
        "confidence": confidence,
        "malicious_engines": malicious,
        "suspicious_engines": suspicious,
        "community_malicious_votes": malicious_votes,
    }


_VT_FIELDS = (
    "reputation",
    "last_analysis_stats",
    "tags",
    "as_owner",
    "asn",
    "network",
    "country",
    "regional_internet_registry",
    "crowdsourced_context",
    "total_votes",
)


def compact_vt_report(
    vt_report: dict[str, Any], verdict: dict[str, Any] | None = None
) -> dict[str, Any]:
    data = vt_report.get("data", {})
    attributes = data.get("attributes", {})
    compact = {field: attributes.get(field) for field in _VT_FIELDS}
    compact["id"] = data.get("id")
    compact["deterministic_verdict"] = verdict or deterministic_vt_verdict(vt_report)
    return compact


def build_ip_enrichment(vt_report: dict[str, Any]) -> IpEnrichment:
    verdict = deterministic_vt_verdict(vt_report)
    return IpEnrichment(
        compact=compact_vt_report(vt_report, verdict),
        verdict=verdict,
    )


_INFRA_TYPES = ["vpn", "proxy", "tor", "hosting", "residential", "corporate", "malicious", "unknown"]

_IP_ASSESSMENT_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "infrastructure_type": {"type": "string", "enum": _INFRA_TYPES},
        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
        "rationale": {"type": "string"},
    },
    "required": ["infrastructure_type", "confidence", "rationale"],
}

_OPENAI_RESPONSE_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "original_ip": _IP_ASSESSMENT_SCHEMA,
        "suspicious_ip": _IP_ASSESSMENT_SCHEMA,
        "summary": {"type": "string"},
    },
    "required": ["original_ip", "suspicious_ip", "summary"],
}


def analyze_ip_context_with_openai(
    alert: dict[str, Any],
    original_ip: IpEnrichment,
    suspicious_ip: IpEnrichment,
    config: Config,
) -> dict[str, Any]:
    prompt_payload = {
        "detection": alert,
        "virustotal": {
            "original_ip": original_ip.compact,
            "suspicious_ip": suspicious_ip.compact,
        },
    }

    body = {
        "model": config.openai_model,
        "temperature": 0,
        "instructions": (
            "You are a SOC analyst. Analyze VirusTotal IP enrichment for an Okta "
            "session-cookie theft alert. For each IP classify its infrastructure "
            "type and give a 0-1 confidence with a short evidence-based rationale. "
            "Treat the provided deterministic_verdict as the authoritative "
            "malicious/benign signal and do not contradict it; your job is to "
            "characterize the kind of infrastructure. Be concise."
        ),
        "input": json.dumps(prompt_payload, separators=(",", ":")),
        "text": {
            "format": {
                "type": "json_schema",
                "name": "ip_context_assessment",
                "strict": True,
                "schema": _OPENAI_RESPONSE_SCHEMA,
            }
        },
    }

    response = http_json(
        "POST",
        "https://api.openai.com/v1/responses",
        headers={
            "Authorization": f"Bearer {config.openai_api_key}",
            "Content-Type": "application/json",
        },
        body=body,
    )
    return extract_openai_json(response)


def extract_openai_json(response: dict[str, Any]) -> dict[str, Any]:
    text = response.get("output_text")
    if not text:
        chunks: list[str] = []
        for item in response.get("output", []):
            for content in item.get("content", []):
                if content.get("type") in {"output_text", "text"} and content.get("text"):
                    chunks.append(content["text"])
        text = "\n".join(chunks).strip()

    if not text:
        return {"summary": "No OpenAI output returned.", "raw": response}

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {"summary": text.strip()}


def format_openai_analysis(analysis: dict[str, Any]) -> str:
    lines: list[str] = []
    for label, key in (("Original IP", "original_ip"), ("Suspicious IP", "suspicious_ip")):
        item = analysis.get(key)
        if isinstance(item, dict):
            infra = item.get("infrastructure_type", "unknown")
            conf = item.get("confidence")
            rationale = item.get("rationale", "")
            conf_str = f"{conf:.2f}" if isinstance(conf, (int, float)) else str(conf)
            lines.append(f"{label}: {infra} (confidence {conf_str}) - {rationale}")
    summary = analysis.get("summary")
    if summary:
        lines.append(str(summary))
    return "\n".join(lines) if lines else json.dumps(analysis, indent=2)


def clear_okta_user_sessions(user_id: str, config: Config) -> dict[str, Any]:
    encoded_user = parse.quote(user_id, safe="")
    url = f"{config.okta_org_url}/api/v1/users/{encoded_user}/sessions?oauthTokens=true"
    return http_json(
        "DELETE",
        url,
        headers={
            "Authorization": f"SSWS {config.okta_api_token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        },
        expected_statuses=(200, 204),
    )


def post_slack_message(channel: str, text: str, config: Config) -> dict[str, Any]:
    response = http_json(
        "POST",
        "https://slack.com/api/chat.postMessage",
        headers={
            "Authorization": f"Bearer {config.slack_bot_token}",
            "Content-Type": "application/json",
        },
        body={"channel": channel, "text": text},
    )
    if not response.get("ok"):
        raise ApiError(f"Slack API error: {response}")
    return response


def send_gmail_message(to_email: str, subject: str, body: str, config: Config) -> dict[str, Any]:
    message = EmailMessage()
    message["To"] = to_email
    if config.gmail_from_email:
        message["From"] = config.gmail_from_email
    message["Subject"] = subject
    message.set_content(body)

    encoded_message = base64.urlsafe_b64encode(message.as_bytes()).decode("utf-8")
    url = (
        "https://gmail.googleapis.com/gmail/v1/users/"
        f"{parse.quote(config.gmail_user_id, safe='')}/messages/send"
    )
    return http_json(
        "POST",
        url,
        headers={
            "Authorization": f"Bearer {config.gmail_access_token}",
            "Content-Type": "application/json",
        },
        body={"raw": encoded_message},
    )


SEVERITY_LADDER = ["Low", "Medium", "High", "Critical"]


def escalate_severity(alert_severity: str, overall_verdict: str) -> str:
    try:
        current_index = SEVERITY_LADDER.index(alert_severity.capitalize())
    except (ValueError, AttributeError):
        current_index = SEVERITY_LADDER.index("High")

    floor_by_verdict = {
        "malicious": SEVERITY_LADDER.index("Critical"),
        "suspicious": SEVERITY_LADDER.index("High"),
        "benign": 0,
    }
    target_index = max(current_index, floor_by_verdict.get(overall_verdict, 0))
    return SEVERITY_LADDER[target_index]


def build_case_summary(
    alert: dict[str, Any],
    original_ip: IpEnrichment,
    suspicious_ip: IpEnrichment,
    openai_analysis: dict[str, Any],
    containment_status: str,
) -> dict[str, Any]:
    severity_rank = {"benign": 0, "suspicious": 1, "malicious": 2}
    overall_verdict = max(
        original_ip.verdict["verdict"],
        suspicious_ip.verdict["verdict"],
        key=lambda v: severity_rank.get(v, 0),
    )
    effective_severity = escalate_severity(alert["severity"], overall_verdict)
    return {
        "case_created_at": dt.datetime.now(dt.UTC).isoformat(),
        "detection_name": alert["detection_name"],
        "severity": effective_severity,
        "alert_severity": alert["severity"],
        "user_id": alert["user_id"],
        "user_email": alert["user_email"],
        "reused_external_session_id": alert["external_session_id"],
        "original_activity": alert["original_activity"],
        "suspicious_activity": alert["suspicious_activity"],
        "detection_reason": (
            "Same Okta externalSessionId was observed for the same user from a "
            "different IP, ASN, and user agent within the detection window."
        ),
        "deterministic_verdict": {
            "overall": overall_verdict,
            "original_ip": original_ip.verdict,
            "suspicious_ip": suspicious_ip.verdict,
        },
        "virustotal_summary": {
            "original_ip": original_ip.compact,
            "suspicious_ip": suspicious_ip.compact,
        },
        "openai_ip_assessment": openai_analysis,
        "containment": {
            "action": "Clear Okta user sessions with oauthTokens=true",
            "status": containment_status,
        },
        "user_verification": {
            "email_sent_to": alert["user_email"],
            "slack_channel_or_user": alert["slack_channel"],
            "question": "Do you recognize this Okta activity?",
        },
    }


def build_user_message(alert: dict[str, Any], sessions_cleared: bool) -> str:
    suspicious = alert["suspicious_activity"]
    containment_line = (
        "As a precaution, your Okta sessions have been cleared and you may need to sign in again."
        if sessions_cleared
        else "In a live containment run, your Okta sessions would be cleared before this message is sent."
    )
    return textwrap.dedent(
        f"""
        Hi {alert['user_id']},

        Security check: we detected unusual Okta session activity on your account.

        Suspicious activity:
        - IP: {suspicious['ip']}
        - ASN: {suspicious['asn']}
        - City: {suspicious['city']}
        - User agent: {suspicious['user_agent']}
        - Time: {suspicious['timestamp']}

        {containment_line}

        Please reply YES if you recognize this activity, or NO if you do not.
        """
    ).strip()


def write_case_summary(case_summary: dict[str, Any], output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%SZ")
    user = case_summary["user_id"].replace("@", "_at_").replace("/", "_")
    path = output_dir / f"okta_session_theft_case_{user}_{stamp}.json"
    path.write_text(json.dumps(case_summary, indent=2), encoding="utf-8")
    return path


def mock_vt_report(ip: str, as_owner: str = "DRY-RUN-NETWORK") -> dict[str, Any]:
    return {
        "data": {
            "id": ip,
            "attributes": {
                "reputation": 0,
                "last_analysis_stats": {
                    "malicious": 0,
                    "suspicious": 0,
                    "harmless": 0,
                    "undetected": 0,
                },
                "tags": ["dry-run"],
                "as_owner": as_owner,
                "asn": 64512,
                "network": f"{ip}/32",
                "country": "ZZ",
                "crowdsourced_context": [],
                "total_votes": {"harmless": 0, "malicious": 0},
            },
        }
    }


def dry_run_openai_analysis() -> dict[str, Any]:
    dry_ip = {
        "infrastructure_type": "unknown",
        "confidence": 0.0,
        "rationale": "Dry-run: no live enrichment performed.",
    }
    return {
        "original_ip": dict(dry_ip),
        "suspicious_ip": dict(dry_ip),
        "summary": (
            "Dry-run assessment: no live enrichment was performed. In a live "
            "run, OpenAI would classify each IP's infrastructure type with a "
            "confidence and rationale."
        ),
    }


def collect_ip_enrichments(
    alert: dict[str, Any], config: Config, dry_run: bool
) -> tuple[IpEnrichment, IpEnrichment]:
    original_ip = alert["original_activity"]["ip"]
    suspicious_ip = alert["suspicious_activity"]["ip"]

    if dry_run:
        return (
            build_ip_enrichment(mock_vt_report(original_ip)),
            build_ip_enrichment(mock_vt_report(suspicious_ip)),
        )

    print("[+] Querying VirusTotal for original IP...")
    original = get_virustotal_ip_report(original_ip, config.virustotal_api_key)

    print("[+] Querying VirusTotal for suspicious IP...")
    suspicious = get_virustotal_ip_report(suspicious_ip, config.virustotal_api_key)
    return build_ip_enrichment(original), build_ip_enrichment(suspicious)


def analyze_ip_context(
    alert: dict[str, Any],
    original_ip: IpEnrichment,
    suspicious_ip: IpEnrichment,
    config: Config,
    dry_run: bool,
) -> dict[str, Any]:
    if dry_run:
        return dry_run_openai_analysis()

    print("[+] Asking OpenAI for concise SOC IP assessment...")
    return analyze_ip_context_with_openai(alert, original_ip, suspicious_ip, config)


def perform_containment(
    alert: dict[str, Any], config: Config, dry_run: bool, skip_containment: bool
) -> str:
    if dry_run:
        return "dry-run: Okta sessions not cleared"
    if skip_containment:
        print("[+] Skipping Okta containment by request.")
        return "skipped by --skip-containment"

    print("[+] Clearing Okta user sessions...")
    clear_okta_user_sessions(alert["user_id"], config)
    return "completed"


def validate_live_requirements(
    alert: dict[str, Any], config: Config, skip_containment: bool
) -> None:
    required = {
        "VIRUSTOTAL_API_KEY": config.virustotal_api_key,
        "OPENAI_API_KEY": config.openai_api_key,
    }
    if not skip_containment:
        required.update(
            {
                "OKTA_ORG_URL": config.okta_org_url,
                "OKTA_API_TOKEN": config.okta_api_token,
            }
        )
    if config.soc_slack_channel or alert["slack_channel"]:
        required["SLACK_BOT_TOKEN"] = config.slack_bot_token
    if is_valid_email(alert["user_email"]):
        required["GMAIL_ACCESS_TOKEN"] = config.gmail_access_token
    config.require_env(required)


def send_notifications(
    alert: dict[str, Any],
    case_summary: dict[str, Any],
    case_path: Path,
    openai_analysis: dict[str, Any],
    user_message: str,
    config: Config,
) -> None:
    if config.soc_slack_channel:
        soc_text = (
            f"*{case_summary['detection_name']}* for `{case_summary['user_id']}`\n"
            f"Case summary written to: `{case_path}`\n"
            f"OpenAI assessment:\n{format_openai_analysis(openai_analysis)}"
        )
        print("[+] Sending SOC Slack summary...")
        post_slack_message(config.soc_slack_channel, soc_text, config)

    if alert["slack_channel"]:
        print("[+] Sending Slack message to user...")
        post_slack_message(alert["slack_channel"], user_message, config)
    else:
        print("[!] No slack_channel/slack_user_id in alert payload; skipping user Slack message.")

    if is_valid_email(alert["user_email"]):
        print("[+] Sending Gmail message to user...")
        send_gmail_message(
            alert["user_email"],
            "Security check: unusual Okta session activity",
            user_message,
            config,
        )
    elif alert["user_email"]:
        print(
            f"[!] user_email '{alert['user_email']}' is not a valid email address; "
            "skipping Gmail message."
        )
    else:
        print("[!] No user_email in alert payload; skipping Gmail message.")


def run(args: argparse.Namespace) -> int:
    load_dotenv(Path(args.dotenv))
    config = Config.from_env()

    raw_alert = json.loads(Path(args.alert_file).read_text(encoding="utf-8"))
    alert = normalize_alert(raw_alert)
    if not args.dry_run:
        validate_live_requirements(alert, config, args.skip_containment)

    print(f"[+] Loaded alert for user: {alert['user_id']}")
    print(f"[+] Detection: {alert['detection_name']}")

    if args.dry_run:
        print("[dry-run] Skipping live VirusTotal, OpenAI, Okta, Slack, and Gmail calls.")

    original_ip, suspicious_ip = collect_ip_enrichments(alert, config, args.dry_run)
    openai_analysis = analyze_ip_context(
        alert, original_ip, suspicious_ip, config, args.dry_run
    )
    containment_status = perform_containment(
        alert, config, args.dry_run, args.skip_containment
    )

    case_summary = build_case_summary(
        alert,
        original_ip,
        suspicious_ip,
        openai_analysis,
        containment_status,
    )
    case_path = write_case_summary(case_summary, Path(args.output_dir))
    print(f"[+] Wrote SOC case summary: {case_path}")

    sessions_cleared = containment_status == "completed"
    user_message = build_user_message(alert, sessions_cleared)

    if args.dry_run:
        print("[dry-run] User email body:")
        print(user_message)
        return 0

    send_notifications(alert, case_summary, case_path, openai_analysis, user_message, config)
    print("[+] Automation response completed.")
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Respond to suspected Okta session cookie theft alerts."
    )
    parser.add_argument("--alert-file", required=True, help="Path to JSON alert payload.")
    parser.add_argument("--dotenv", default=".env", help="Optional .env file with API credentials.")
    parser.add_argument("--output-dir", default="cases", help="Directory for SOC case summaries.")
    parser.add_argument("--dry-run", action="store_true", help="Do not call live APIs.")
    parser.add_argument(
        "--skip-containment", action="store_true", help="In live mode, skip clearing Okta sessions."
    )
    return parser.parse_args()


if __name__ == "__main__":
    try:
        raise SystemExit(run(parse_args()))
    except ApiError as exc:
        print(f"[!] API error: {exc}", file=sys.stderr)
        raise SystemExit(1)
