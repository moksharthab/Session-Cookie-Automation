**Title**
`Automation Response: Suspected Okta Session Cookie Theft`

**1. Detection Context**
Briefly explain what the rule detects:

> This detection identifies possible Okta session cookie theft by finding the same `externalSessionId` reused by the same user from a different IP, ASN, and user agent within a 1-hour window.

**2. Automation Objective**
Use a simple flow:

```text
Detect → Create SOC Case → Enrich IPs → Analyze Context → Contain → Verify with User
```

**3. Response Workflow**
Make this a numbered list:

1. Receive alert payload from SIEM.
2. Create SOC case summary.
3. Query VirusTotal for original and suspicious IPs.
4. Use OpenAI to summarize VPN/proxy/Tor/hosting/malicious-infra likelihood.
5. Clear Okta user sessions using Okta API.
6. Send Slack and email notification to the user.

**4. Case Summary Fields**
Put this in a small table:

| Field | Purpose |
|---|---|
| User ID | Affected Okta user |
| externalSessionId | Reused session identifier |
| Original IP/ASN/City/UA | Expected user context |
| Suspicious IP/ASN/City/UA | Possible attacker context |
| Timestamps | Event sequence |
| Detection name | Suspected Okta Session Cookie Theft |

**5. API Integrations**
Keep this short:

- **Okta API:** Clears user sessions with `oauthTokens=true`.
- **VirusTotal API:** Enriches both IP addresses.
- **OpenAI API:** Produces SOC-ready IP infrastructure assessment.
- **Slack API:** Sends user verification message.
- **Gmail API:** Sends email confirmation request.

**6. Containment Action**
Highlight this clearly:

```text
DELETE /api/v1/users/{userId}/sessions?oauthTokens=true
```

Explain:

> This invalidates the active Okta session and related OAuth/OIDC tokens where applicable, reducing the usefulness of a stolen session cookie.

**7. User Notification**
Include the exact email/Slack message template.

**8. Demo Instructions**
Add:

```bash
python3 okta_session_theft_response.py \
  --alert-file sample_okta_session_theft_alert.json \
  --dry-run
```

Then explain that `--dry-run` shows the workflow without calling live APIs.

**9. Appendix**
Put the full Python script here, or better:

> Full script: `okta_session_theft_response.py`  
> Sample alert: `sample_okta_session_theft_alert.json`  
> Config template: `.env.example`
