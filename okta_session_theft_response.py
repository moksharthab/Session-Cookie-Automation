#!/usr/bin/env python3
"""
Automated response for suspected Okta session cookie theft alerts.

The script fetches case details from Google SecOps/Chronicle with the SecOps SDK.
It creates a SOC case summary, enriches original/attacker IPs with VirusTotal,
clears Okta user sessions, and notifies the user over email and Slack.

Secrets are read from environment variables. The script always clears Okta user
sessions and always sends email and Slack notifications.
"""

from __future__ import annotations

import argparse
import json
import os
import smtplib
import ssl
import textwrap
import time
import urllib.parse
from email.message import EmailMessage
from typing import Any

import requests
from secops import SecOpsClient


DETECTION_NAME = "suspected Okta session cookie theft"


def object_to_jsonable(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, dict):
        return {str(key): object_to_jsonable(item) for key, item in value.items()}
    if isinstance(value, list):
        return [object_to_jsonable(item) for item in value]
    if hasattr(value, "model_dump"):
        return object_to_jsonable(value.model_dump())
    if hasattr(value, "to_dict"):
        return object_to_jsonable(value.to_dict())
    if hasattr(value, "__dict__"):
        return object_to_jsonable(vars(value))
    return str(value)


def create_chronicle_client():
    customer_id = os.getenv("SECOPS_CUSTOMER_ID")
    project_id = os.getenv("SECOPS_PROJECT_ID")
    region = os.getenv("SECOPS_REGION", "us")
    if not customer_id or not project_id:
        raise RuntimeError("Set SECOPS_CUSTOMER_ID and SECOPS_PROJECT_ID.")

    client = SecOpsClient()
    return client.chronicle(
        customer_id=customer_id,
        project_id=project_id,
        region=region,
    )


def fetch_secops_case_details(case_id: str) -> dict[str, Any]:
    chronicle = create_chronicle_client()
    case = chronicle.get_case(case_id)
    return {"case": object_to_jsonable(case)}


def post_case_wall_comment(case_id: str, comment: str) -> dict[str, Any]:
    chronicle = create_chronicle_client()
    parent = case_id
    if not parent.startswith("projects/"):
        parent = f"{chronicle.instance_id}/cases/{case_id}"

    base_url = chronicle.base_url() if callable(chronicle.base_url) else str(chronicle.base_url)
    url = f"{base_url}/{parent}/caseComments"
    response = chronicle.session.post(url, json={"comment": comment}, timeout=30)
    if not response.ok:
        raise RuntimeError(
            f"POST {url} failed: HTTP {response.status_code}: {response.text}"
        )
    if not response.content:
        return {"status": response.status_code}
    return object_to_jsonable(response.json())


def parse_alert(case: dict[str, Any]) -> dict[str, Any]:
    def value(field_name: str, default: str = "unknown") -> str:
        raw_value = case.get(field_name, default)
        if isinstance(raw_value, list):
            raw_value = next((item for item in raw_value if item not in (None, "")), default)
        if raw_value in (None, "", []):
            return default
        if isinstance(raw_value, dict):
            return json.dumps(raw_value, sort_keys=True)
        return str(raw_value)

    user_id = value("userid")
    user_email = value("user_email", default=user_id)
    display_name = value("display_name", default=user_id)
    external_session_id = value("externalSessionId")

    return {
        "user_id": user_id,
        "user_email": user_email,
        "display_name": display_name,
        "external_session_id": external_session_id,
        "original": {
            "ip": value("ip1"),
            "asn": value("e1_asn"),
            "city": value("e1_cities"),
            "user_agent": value("e1_ua"),
            "timestamp": value("first_e1_timestamp"),
        },
        "attacker": {
            "ip": value("ip2"),
            "asn": value("e2_asn"),
            "city": value("e2_cities"),
            "user_agent": value("e2_ua"),
            "timestamp": value("first_e2_timestamp"),
        },
    }


def query_virustotal(ip: str) -> dict[str, Any]:
    api_key = os.getenv("VT_API_KEY")
    if not api_key:
        return {"error": "VT_API_KEY is not set", "ip": ip}

    quoted_ip = urllib.parse.quote(ip, safe="")
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{quoted_ip}"
    response = requests.get(url, headers={"x-apikey": api_key}, timeout=30)
    if not response.ok:
        raise RuntimeError(
            f"GET {url} failed: HTTP {response.status_code}: {response.text}"
        )
    return response.json()


def normalize_vt(ip: str, vt_response: dict[str, Any]) -> dict[str, Any]:
    if "error" in vt_response:
        return {"ip": ip, "error": vt_response["error"]}

    attributes = vt_response.get("data", {}).get("attributes", {})
    return {
        "ip": ip,
        "asn": attributes.get("asn"),
        "as_owner": attributes.get("as_owner"),
        "network": attributes.get("network"),
        "country": attributes.get("country"),
        "tags": attributes.get("tags", []),
        "reputation": attributes.get("reputation"),
        "last_analysis_stats": attributes.get("last_analysis_stats", {}),
        "total_votes": attributes.get("total_votes", {}),
    }


def build_case_summary(
    context: dict[str, Any],
    original_vt: dict[str, Any],
    attacker_vt: dict[str, Any],
    containment_result: dict[str, Any],
    email_result: dict[str, Any],
    slack_result: dict[str, Any],
) -> str:
    return textwrap.dedent(
        f"""
        Detection Name: {DETECTION_NAME}
        Automation Status: response actions completed
        Generated At Epoch: {int(time.time())}
        User ID: {context["user_id"]}
        User Email: {context["user_email"]}
        Reused externalSessionId: {context["external_session_id"]}

        Original Session Context:
        - Timestamp: {context["original"]["timestamp"]}
        - IP: {context["original"]["ip"]}
        - ASN: {context["original"]["asn"]}
        - City: {context["original"]["city"]}
        - User Agent: {context["original"]["user_agent"]}
        - VirusTotal ASN Owner: {original_vt.get("as_owner", "unknown")}
        - VirusTotal Country: {original_vt.get("country", "unknown")}
        - VirusTotal Reputation: {original_vt.get("reputation", "unknown")}
        - VirusTotal Stats: {json.dumps(original_vt.get("last_analysis_stats", {}), sort_keys=True)}

        Suspected Attacker Session Context:
        - Timestamp: {context["attacker"]["timestamp"]}
        - IP: {context["attacker"]["ip"]}
        - ASN: {context["attacker"]["asn"]}
        - City: {context["attacker"]["city"]}
        - User Agent: {context["attacker"]["user_agent"]}
        - VirusTotal ASN Owner: {attacker_vt.get("as_owner", "unknown")}
        - VirusTotal Country: {attacker_vt.get("country", "unknown")}
        - VirusTotal Reputation: {attacker_vt.get("reputation", "unknown")}
        - VirusTotal Stats: {json.dumps(attacker_vt.get("last_analysis_stats", {}), sort_keys=True)}

        Why this fired:
        The same Okta externalSessionId was observed for the same user from a later
        session-start event with a different IP, ASN, and user agent.

        Automation Actions:
        - Okta sessions cleared: {json.dumps(containment_result, sort_keys=True)}
        - User email sent: {json.dumps(email_result, sort_keys=True)}
        - Slack message sent: {json.dumps(slack_result, sort_keys=True)}

        Recommended SOC Follow-up:
        Review Okta activity around both timestamps, validate the user's response,
        and escalate if the user denies the activity, the attacker IP is anonymized
        infrastructure, or sensitive apps/admin actions were accessed.
        """
    ).strip()


def clear_okta_user_sessions(user_id: str) -> dict[str, Any]:
    okta_domain = os.getenv("OKTA_DOMAIN", "").rstrip("/")
    okta_token = os.getenv("OKTA_API_TOKEN")
    if not okta_domain or not okta_token:
        raise RuntimeError("Set OKTA_DOMAIN and OKTA_API_TOKEN.")

    quoted_user = urllib.parse.quote(user_id, safe="")
    url = f"{okta_domain}/api/v1/users/{quoted_user}/sessions"
    response = requests.delete(
        url,
        headers={
            "Authorization": f"SSWS {okta_token}",
            "Accept": "application/json",
        },
        timeout=30,
    )
    if not response.ok:
        raise RuntimeError(
            f"DELETE {url} failed: HTTP {response.status_code}: {response.text}"
        )
    if not response.content:
        return {"status": response.status_code}
    try:
        return response.json()
    except requests.JSONDecodeError:
        return {"status": response.status_code, "text": response.text}


def send_email(context: dict[str, Any]) -> dict[str, Any]:
    smtp_host = os.getenv("SMTP_HOST")
    smtp_from = os.getenv("SMTP_FROM")
    if not smtp_host or not smtp_from:
        raise RuntimeError("Set SMTP_HOST and SMTP_FROM.")

    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_user = os.getenv("SMTP_USER")
    smtp_password = os.getenv("SMTP_PASSWORD")
    smtp_use_tls = os.getenv("SMTP_USE_TLS", "true").lower() == "true"

    message = EmailMessage()
    message["From"] = smtp_from
    message["To"] = context["user_email"]
    message["Subject"] = "Security check: unusual Okta session activity"
    message.set_content(
        textwrap.dedent(
            f"""
            Hi {context["display_name"]},

            We detected unusual Okta session activity for your account from a new
            network and browser context.

            Time: {context["attacker"]["timestamp"]}
            Location: {context["attacker"]["city"]}
            IP: {context["attacker"]["ip"]}
            Browser/User Agent: {context["attacker"]["user_agent"]}

            Did you perform this activity?

            Please reply YES if this was you, or NO if you do not recognize it.
            If you reply NO or do not respond, Security may revoke active sessions
            to protect your account.

            Security Operations
            """
        ).strip()
    )

    with smtplib.SMTP(smtp_host, smtp_port, timeout=30) as smtp:
        if smtp_use_tls:
            smtp.starttls(context=ssl.create_default_context())
        if smtp_user and smtp_password:
            smtp.login(smtp_user, smtp_password)
        smtp.send_message(message)

    return {"sent": True, "to": context["user_email"]}


def send_slack(context: dict[str, Any]) -> dict[str, Any]:
    webhook_url = os.getenv("SLACK_WEBHOOK_URL")
    if not webhook_url:
        raise RuntimeError("Set SLACK_WEBHOOK_URL.")

    text = (
        f"Hi {context['display_name']}, Security detected unusual Okta session activity "
        f"for your account.\n\n"
        f"*Time:* {context['attacker']['timestamp']}\n"
        f"*Location:* {context['attacker']['city']}\n"
        f"*IP:* {context['attacker']['ip']}\n\n"
        "Was this you? Please reply `YES` if this was you or `NO` if you do not recognize it."
    )
    response = requests.post(webhook_url, json={"text": text}, timeout=30)
    if not response.ok:
        raise RuntimeError(
            f"POST {webhook_url} failed: HTTP {response.status_code}: {response.text}"
        )
    if not response.content:
        return {"status": response.status_code}
    try:
        return response.json()
    except requests.JSONDecodeError:
        return {"status": response.status_code, "text": response.text}


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Respond to suspected Okta session cookie theft alerts."
    )
    parser.add_argument(
        "--secops-case-id",
        required=True,
        help="Google SecOps/Chronicle case ID to fetch with the SecOps SDK.",
    )
    args = parser.parse_args()

    secops_details = fetch_secops_case_details(args.secops_case_id)
    context = parse_alert(secops_details["case"])

    original_vt = normalize_vt(
        context["original"]["ip"],
        query_virustotal(context["original"]["ip"]),
    )
    attacker_vt = normalize_vt(
        context["attacker"]["ip"],
        query_virustotal(context["attacker"]["ip"]),
    )

    containment_result = clear_okta_user_sessions(context["user_id"])
    email_result = send_email(context)
    slack_result = send_slack(context)

    case_summary = build_case_summary(
        context,
        original_vt,
        attacker_vt,
        containment_result,
        email_result,
        slack_result,
    )
    post_case_wall_comment(args.secops_case_id, case_summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
