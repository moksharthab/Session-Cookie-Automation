# Okta Session Cookie Theft Response Automation

Python automation for responding to suspected Okta session cookie theft cases in Google SecOps/Chronicle.

The script fetches a SecOps case, extracts the relevant Okta session fields, enriches the original and suspected attacker IP addresses with VirusTotal, clears Okta user sessions, notifies the user by email and Slack, builds a SOC case summary, and posts that summary back to the SecOps case wall.

## Script

Primary simplified version:

```text
okta_session_cookie_response_no_dataclasses.py
```

## Requirements

Install the required Python packages:

```bash
pip install secops requests
```

Configure environment variables:

```bash
export SECOPS_CUSTOMER_ID="your-secops-customer-id"
export SECOPS_PROJECT_ID="your-gcp-project-id"
export SECOPS_REGION="us"

export VT_API_KEY="your-virustotal-api-key"

export OKTA_DOMAIN="https://your-org.okta.com"
export OKTA_API_TOKEN="your-okta-api-token"

export SMTP_HOST="smtp.example.com"
export SMTP_PORT="587"
export SMTP_FROM="security@example.com"
export SMTP_USER="smtp-user"
export SMTP_PASSWORD="smtp-password"
export SMTP_USE_TLS="true"

export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/..."
```

## Usage

Run the no-dataclass script:

```bash
python3 okta_session_cookie_response_no_dataclasses.py \
  --secops-case-id "CASE_ID"
```

The automation always performs these actions:

- Fetches the SecOps case
- Enriches both IP addresses with VirusTotal
- Clears Okta user sessions
- Sends user email
- Sends Slack message
- Posts the SOC summary to the SecOps case wall

## Function Call Flow

Current flow for `okta_session_cookie_response_no_dataclasses.py`:

```text
main()
|
|-- fetch_secops_case_details()
|   |
|   |-- create_chronicle_client()
|   |   |
|   |   |-- SecOpsClient()
|   |   |-- client.chronicle()
|   |
|   |-- chronicle.get_case()
|   |-- object_to_jsonable()
|
|-- parse_alert()
|   |
|   |-- value()
|   |-- returns plain dict:
|       |
|       |-- context["user_id"]
|       |-- context["user_email"]
|       |-- context["display_name"]
|       |-- context["external_session_id"]
|       |-- context["original"]
|       |-- context["attacker"]
|
|-- query_virustotal() for original IP
|   |
|   |-- requests.get()
|
|-- normalize_vt() for original IP
|
|-- query_virustotal() for attacker IP
|   |
|   |-- requests.get()
|
|-- normalize_vt() for attacker IP
|
|-- clear_okta_user_sessions()
|   |
|   |-- requests.delete()
|
|-- send_email()
|   |
|   |-- smtplib.SMTP()
|   |-- smtp.starttls()
|   |-- smtp.login()
|   |-- smtp.send_message()
|
|-- send_slack()
|   |
|   |-- requests.post()
|
|-- build_case_summary()
|
|-- post_case_wall_comment()
    |
    |-- create_chronicle_client()
    |   |
    |   |-- SecOpsClient()
    |   |-- client.chronicle()
    |
    |-- chronicle.session.post()
```

## Case Summary Output

The final SOC summary is posted to the SecOps case wall and includes:

- Detection name
- User ID and user email
- Reused `externalSessionId`
- Original IP, ASN, city, user agent, and timestamp
- Suspected attacker IP, ASN, city, user agent, and timestamp
- VirusTotal enrichment for both IPs
- Okta session clearing result
- Email notification result
- Slack notification result
- Recommended SOC follow-up
