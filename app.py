# standard imports
import base64, json, logging, sys, traceback
from datetime import datetime


# create logger
logger = logging.getLogger()
logger.setLevel(logging.INFO)


def get_activity_details(activity_info):
    """
    Function captures an Activity Name that is logged by Okta Syslog
    Parameters
    ----------
    activity_info: Activity Info captured by Okta system Log

    Returns
    ------
    activity: Name of the activity
    activity_id: Identifier for the activity
    """
    activities = {
        "user.session.start": ("Logon", 1),
        "user.session.end": ("Logoff", 2),
        "user.authentication": ("Authentication Ticket", 3),
        "app.oauth2": ("Service Ticket", 4),
        "policy.evaluate_sign_on": ("Other", 99),
    }

    for activity_key in activities:
        if activity_info and activity_key in activity_info:
            return activities[activity_key]

    return "Unknown", 0


def get_actor_details(user_details):
    """
    Function captures the identity of an actor using the credentials provided to it

    Returns
    ------
    actor: Actor object
    """
    return {"user": user_details}


def get_audit_category(event_type):
    """
    Function captures the event category name for an event logged by Okta
    get_audit_category function is dedicated for all the Audit Activity Events
    This function can be enhanced as more events are included
    Returns
    ------
    category_name: Name of the event category
    category_uid: Category unique identifier for the activity
    """
    audit_event_types = [
        "user.session.start",
        "user.session.access_admin_app",
        "user.session.end",
        "user.authentication",
        "app.oauth2",
        "policy.evaluate_sign_on",
    ]

    if event_type and any(
        audit_event in event_type for audit_event in audit_event_types
    ):
        return "Audit Activity events", 3

    return "Unknown", 0


def get_auth_protocol(data):
    """
    Function captures an authentication protocol reported by the event source.
    Parameters
    ----------
    auth_provider_detail: Contains the identity of an actor using the credentials provided to it

    Returns
    ------
    auth_protocol: Name of the activity
    auth_protocol: Identifier for the activity
    """
    auth_provider_detail = (
        data.get("detail", {})
        .get("authenticationContext", {})
        .get("authenticationProvider")
    )

    if auth_provider_detail and "FACTOR" in auth_provider_detail:
        return "Other / MFA", 99

    return "Unknown", 0


def get_clear_text_value(auth_protocol):
    """
    Function checks if credentials were passed in clear text.
    Parameters
    ----------
    auth_protocol: Contains the metadata about the authentication
    Returns
    ------
      Returns the boolean value
    """
    return auth_protocol not in ["FTP", "TELNET"]


def get_destination_endpoint(destination_endpoint):
    """
    Function finds the endpoint for which Authn was targeted
    Parameters
    ----------
    destination_endpoint: Contains the metadata about the endpoint for which AuthN was targeted

    Returns
    ------
    destination_details: Returns the destination endpoint as a dictionary
    """
    return {
        "hostname": destination_endpoint.get("requestUri", ""),
        "ip": "",
        "instance_uid": "",
        "interface_id": "",
        "svc_name": destination_endpoint.get("url", ""),
    }


def get_enrichment_data(client_data):
    """
    Function captures the Enrichment data for an event logged by Okta
    get_enrichment_data function is dedicated for all the enrichment of data
    This function can be enhanced based on data user wants to enrich. In this we will only return
    Client, Devices and Geographical context
    Returns
    ------
    enrichment: Array of the enriched data
    """
    return [
        {
            "name": "geographicalContext",
            "data": client_data.get("geographicalContext", ""),
            "value": client_data.get("ipAddress", ""),
            "type": "location",
        }
    ]


def get_event_class():
    """
    Function captures an event class

    Returns
    ------
    class_name: Name of the event class
    class_uid: Class unique identifier for the activity
    """
    return "Authentication Audit", 3002


def get_http_request(data):
    """
    Function captures an HTTP Request

    Returns
    ------
    http_request: HTTP Request object
    """
    return {
        "user_agent": data.get("detail", {})
        .get("client", {})
        .get("userAgent", {})
        .get("rawUserAgent", ""),
        "uid": data.get("detail", {})
        .get("debugContext", {})
        .get("debugData", {})
        .get("requestId", ""),
    }


def get_logon_type(login_transaction):
    """
    Function finds the type of the login based on the event source
    Parameters
    ----------
    login_transaction: Contains the metadata about the endpoint for which AuthN was targeted

    Returns
    ------
    logon_type: Returns the boolean value based on the event
    logon_type_id: Returns the logon id
    """
    logon_type = login_transaction.get("type", "")
    return logon_type, 99 if logon_type and "WEB" in logon_type else 0


def get_metadata(original_time, version):
    """
    Function captures the metadata about the event type for an event logged by Okta
    get_metadata function is dedicated for capturing the Metadata Object Type
    This function can be be enhanced as more events are included
    Returns
    ------
    metadata: Metadata Object is returned
    """
    return {
        "original_time": original_time,
        "product": {"vendor_name": "Okta", "name": "Okta System Log"},
        "version": version,
    }


def get_severity(severity):
    """
    Function to find the log severity
    Parameters
    ----------
    severity: Details about the event severity

    Returns
    ------
    severity: Returns the event severity
    severity_id: Returns event severity  id
    """
    severity_dict = {"INFO": 1, "DEBUG": 2, "WARN": 4, "ERROR": 6}
    return severity, severity_dict.get(severity, 0)


def get_src_endpoint(data):
    """
    Function to find the endpoint where authentication is requested
    Parameters
    ----------
    data: Details about the event

    Returns
    ------
    src_end_point: Returns the src endpoint
    """
    return {
        "hostname": data["debugContext"]["debugData"]["requestUri"],
        "ip ": data["client"]["ipAddress"],
        "interface_id": data["client"]["device"],
    }


def get_src_user(data):
    """
    Function to find the endpoint where authentication is requested
    Parameters
    ----------
    data: Get existing user data

    Returns
    ------
    src_user: Returns the user information
    """
    return {
        "account_uid": data["actor"]["id"],
        "email_addr": data["actor"]["alternateId"],
        "name": data["actor"]["displayName"],
        "type": data["actor"]["type"],
        "type_id": 1,
        "uuid": data["actor"]["id"],
        "uid": data["actor"]["id"],
    }


def get_status_details(data):
    """
    Function to find the endpoint where authentication is requested
    Parameters
    ----------
    data: Get existing user data

    Returns
    ------
    status_result: Returns the event status
    status_code: Returns the event status code
    status_detail: Details about authentication Request
    status_id: Normalized ID for the status
    """
    status_result = data.get("outcome", {}).get("result", "")
    status_code = "N/A"
    status_detail = "Unknown"
    status_id = 0

    event_type = data.get("eventType", "")
    success_event_mapping = {
        "user.session.start": "LOGON_USER_INITIATED",
        "user.session.access_admin_app": "ACCESS_ADMIN_APP",
        "user.session.end": "LOGOFF_USER_INITIATED",
        "app.oauth": "LOGOFF_USER_INITIATED",
    }

    if "SUCCESS" in status_result:
        status_detail = success_event_mapping.get(event_type, status_detail)
        status_id = 1
    elif "FAILURE" in status_result:
        status_detail = data.get("outcome", {}).get("reason", status_detail)
        status_id = 2
    elif "CHALLENGE" in status_result:
        status_detail = data.get("outcome", {}).get("reason", status_detail)
        status_id = 99

    return status_result, status_code, status_detail, status_id


def get_type_category(event_type):
    """
    Function captures the event type for an event logged by Okta
    get_audit_category function is dedicated for all the Audit Activity Types
    This function can be enhanced as more events are included
    Returns
    ------
    type_name: Name of the event Type
    type_uid: Type unique identifier for the activity
    """
    type_mapping = {
        "user.session.start": ("Authentication: Logon", 300201),
        "user.session.access_admin_app": (
            "Authentication: Logon - Elevated Privileges",
            300201,
        ),
        "user.session.end": ("Authentication: Logoff", 300202),
        "user.authentication": ("Authentication: Authentication Ticket", 300203),
        "app.oauth2": ("Authentication: Service Ticket", 300204),
        "policy.evaluate_sign_on": ("Authentication: Other", 300299),
    }
    type_name, type_uid = type_mapping.get(
        event_type, ("Authentication: Unknown", 300200)
    )
    return type_uid, type_name


def transform_data(data):
    detail = data["detail"]
    event_type = detail["eventType"]

    activity, activity_id = get_activity_details(event_type)
    actor = get_actor_details(get_src_user(detail))
    auth_protocol, auth_protocol_id = get_auth_protocol(data)
    category_name, category_uid = get_audit_category(event_type)
    class_name, class_uid = get_event_class()
    dst_endpoint = get_destination_endpoint(detail["debugContext"]["debugData"])
    enrichments = get_enrichment_data(detail["client"])
    http_request = get_http_request(data)
    is_cleartext = get_clear_text_value(auth_protocol)
    logon_type, logon_type_id = get_logon_type(detail["transaction"])
    metadata = get_metadata(data["time"], data["version"])
    severity, severity_id = get_severity(detail["severity"])
    src_endpoint = get_src_endpoint(detail)
    src_user = get_src_user(detail)
    status, status_code, status_detail, status_id = get_status_details(detail)
    type_uid, type_name = get_type_category(event_type)

    display_message = detail["displayMessage"]
    mfa = "auth_via_mfa" in event_type
    session_uid = detail["authenticationContext"]["externalSessionId"]
    date_time = datetime.strptime(data["time"], "%Y-%m-%dT%H:%M:%SZ")
    _time = int(date_time.timestamp())

    json_data = {
        "activity_id": activity_id,
        "category_uid": category_uid,
        "class_uid": class_uid,
        "dst_endpoint": dst_endpoint,
        "time": _time,
        "metadata": metadata,
        "severity_id": severity_id,
        "type_uid": type_uid,
        "user": src_user,
        "auth_protocol_id": auth_protocol_id,
        "logon_type_id": logon_type_id,
        "message": display_message,
        "is_remote": True,
        "status_id": status_id,
        "timezone_offset": -480,
        "activity_name": activity,
        "actor": actor,
        "auth_protocol": auth_protocol,
        "category_name": category_name,
        "class_name": class_name,
        "is_cleartext": is_cleartext,
        "data": "",
        "enrichments": enrichments,
        "http_request": http_request,
        "logon_type": logon_type,
        "mfa": mfa,
        "raw_data": json.dumps(data),
        "severity": severity,
        "src_endpoint": src_endpoint,
        "status": status,
        "status_code": status_code,
        "status_detail": status_detail,
        "type_name": type_name,
        "session": session_uid,
    }

    return json_data


def lambda_handler(event, context):
    """
    Purpose of this Lambda function is to provide a general guidance on converting Okta syslogs into OCSF format.
    For different syslog event categories lambda should be enhanced/modified as per the OCSF schema and Sys Log event attributes
    Parameters
    ----------
    event: event Object represents Okta SysLog event

        Event doc: https://developer.okta.com/docs/reference/api/system-log/#example-logevent-object

    Returns
    ------
    Output Format: Returning Okta Sys log event into an OCSF JSON format

        To Understand OCSF Data Format: https://schema.ocsf.io/classes/authentication?extensions=
    """
    output = []

    # Access Record Data from Syslog event
    try:
        logger.info(f"event: {event}")

        for record in event["records"]:
            data = base64.b64decode(record["data"])
            data = json.loads(data.decode("utf8"))

            result = transform_data(data)
            format = "%Y-%m-%dT%H:%M:%S.%fZ"
            date_input = data["detail"]["published"]

            datetime1 = datetime.strptime(date_input, format)
            year, month, day = (
                datetime1.strftime("%Y"),
                datetime1.strftime("%Y%m"),
                datetime1.strftime("%Y%m%d"),
            )

            output_record = {
                "recordId": record["recordId"],
                "result": "Ok",
                "data": base64.b64encode(
                    json.dumps(result, separators=(",", ":")).encode("utf-8") + b"\n"
                ).decode("utf-8"),
                "metadata": {
                    "partitionKeys": {
                        "source": "OktaEventSource",
                        "year": year,
                        "month": month,
                        "day": day,
                    }
                },
            }
            output.append(output_record)

        print(f"JSON Output base64 Encoded format: {output}")
        return {"records": output}

    except (TypeError, ValueError, KeyError) as exp:
        exception_type, exception_value, exception_traceback = sys.exc_info()
        traceback_string = traceback.format_exception(
            exception_type, exception_value, exception_traceback
        )
        err_msg = json.dumps(
            {
                "errorType": exception_type.__name__,
                "errorMessage": str(exception_value),
                "stackTrace": traceback_string,
            }
        )
        logger.error(err_msg)
