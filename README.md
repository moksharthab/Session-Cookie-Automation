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
