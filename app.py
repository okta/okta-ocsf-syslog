import base64
from datetime import datetime
import json


def lambda_handler(event, context):
    """
    Purpose of this Lambda function is to provide a general guidance on converting Okta syslogs into OCSF format.
    This Lambda function ONLY CONSIDERS : SUCCESSFUL AUTHENTICATION EVENT FROM OKTA SYS LOG
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
    for record in event['records']:
        data = base64.b64decode(record['data'])
        data = json.loads(data.decode('utf8'))
        # Invoke Transform Data to perform OCSF conversion
        result = tranform_data(data)
        # Add Dynamic Partioning for S3 buckets
        format = "%Y-%m-%dT%H:%M:%S.%fZ"
        date_input = data['detail']['published']

        datetime1 = datetime.strptime(date_input, format)
        partitionKeys = {}
        partitionKeys['source'] = 'OktaEventSource'
        partitionKeys['region'] = context.invoked_function_arn.split(":")[3]
        partitionKeys['AWS_account'] = context.invoked_function_arn.split(":")[4]
        partitionKeys['eventhour'] = datetime1.strftime("%Y%m%d%H")

        # Reformats the output in a base64 encoded format.OCSF JSON Output will be used by Firehose datastream and AWS Glue Schema
        output_record = {
            'recordId': record['recordId'],  # is this the problem? I used sequenceNumber, it is not right.
            'result': 'Ok',
            'data': base64.b64encode(json.dumps(result, separators=(',', ':')).encode('utf-8') + b'\n').decode(
                'utf-8'),
            'metadata': {'partitionKeys': partitionKeys}
        }
        output.append(output_record)
    print(f"JSON Output base64 Encoded format: {output}")
    return {'records': output}


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
    # Based on the OCSF schema definition, Successful Athentication is described as "unknown"
    # Activity Value will change based on a type of event you want to capture
    activity = 'Unknown'
    # Use Activity ID associated with an activity
    activity_id = 0
    # Check if User Authentication is part of the activity Info
    if 'user.authentication' in activity_info:
        activity = 'Logon'
        activity_id = 1
    return activity, activity_id


def get_auth_protocol(auth_provider_detail):
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
    auth_protocol = 'Unknown'
    auth_protocol_id = 0
    # Check if FACTOR is part of the activity Info
    # this can be extended to various scenarios and use cases
    if 'FACTOR' in auth_provider_detail:
        auth_protocol = 'Other / MFA'
        auth_protocol_id = 1
    return auth_protocol, auth_protocol_id


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
    # The event category name, for Successful Authentication , category name and category_uid are selected based on the OCSF schema
    category_name = 'Unknown'
    category_uid = 0
    if 'user.authentication' in event_type:
        category_name = 'Audit Activity events'
        category_uid = 3
    return category_name, category_uid


def get_event_class():
    """
    Function captures an event class

    Returns
    ------
    class_name: Name of the event class
    class_uid: Class unique identifier for the activity
    """
    class_name = 'Authentication Audit'
    class_uid = 3002
    return class_name, class_uid


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
    # check if protocol is either FTP or Telnet
    return auth_protocol != 'FTP' and auth_protocol != 'TELNET'


def get_destination_endpoint(destination_endpoint):
    """
    Function finds the endpoint for which Authn was targeted
    Parameters
    ----------
    destination_endpoint: Contains the metadata about the endpoint for which AuthN was targeted

    Returns
    ------
    detination_details: Returns the destination endpoint as a dictionary
    """
    # Create a JSON object in OCSF format
    detination_details = {'hostname': destination_endpoint['requestUri'],
                          'ip': '',
                          'instance_uid': '',
                          'interface_id': '',
                          'svc_name': destination_endpoint['url']}
    return detination_details


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
    # Capture the login transaction
    logon_type = login_transaction['type']
    # If WEB is not in logon_type return a normalized value
    logon_type_id = - 1 if 'WEB' in logon_type else 0

    return logon_type, logon_type_id


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
    # If the event severity is INFO assign value as 1
    severity_id = 1 if 'INFO' in severity else 0

    return severity, severity_id


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
    # Create JSON formatted string compatible with OCSF schema
    return {
        'hostname': data['debugContext']['debugData']['requestUri'],
        'ip ': data['client']['ipAddress'],
        'interface_id': data['client']['device']
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
    # Create JSON formatted string compatible with OCSF schema
    return {
        'type': data['actor']['type'],
        'name': data['actor']['displayName'],
        'email_addr': data['actor']['alternateId']
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
    status_result = data['outcome']['result']
    status_code = 'N/A'
    status_detail = ''
    status_id = -1
    if 'SUCCESS' in status_result:
        status_detail = 'LOGON_USER_INITIATED'
        status_id = 1
    return status_result, status_code, status_detail, status_id


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
    # Data that that will be enriched is location of a user
    # the OCSF schema
    enrichment = {'name': 'geographicalContext', 'data': client_data['geographicalContext'],
                  'value': client_data['ipAddress'], 'type': 'location'}

    return [enrichment]


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
    # The event category name, for Successful Authentication , category name and category_uid are selected based on
    # the OCSF schema
    type_uid = 0
    type_name = 'Unknown'
    if 'user.authentication' in event_type:
        type_name = 'Authentication Audit: Logon'
        type_uid = 300201
    return type_uid, type_name


def get_metadata(original_time, version):
    """
    Function captures the metadata about the event type for an event logged by Okta
    get_metadata function is dedicated for capturing the Metadata Object Type
    This function can be be enhanced as more events are included
    Returns
    ------
    metadata: Metadata Object is returned
    """
    # Create JSON formatted string compatible with OCSF schema
    return {
        'original_time': original_time,
        'product': {
            'vendor_name': 'Okta',
            'name': 'Okta System Log'
        },
        'version': version
    }


def tranform_data(data):
    # get activity details based on the eventType that is published
    activity, activity_id = get_activity_details(data['detail']['eventType'])
    # get the authentication protocol used to create the user session.
    auth_protocol, auth_protocol_id = get_auth_protocol(
        data['detail']['authenticationContext']['authenticationProvider'])
    # get the event category name,
    category_name, category_uid = get_audit_category(data['detail']['eventType'])
    # get the event class name
    class_name, class_uid = get_event_class()
    # check if whether the credentials were passed in clear text.
    is_cleartext = get_clear_text_value(auth_protocol)
    # get the destination endpoint for which the authentication was targeted.
    dst_endpoint = get_destination_endpoint(data['detail']['debugContext']['debugData'])
    # get user details and account type used for authentication
    dst_user = data['detail']['actor']['alternateId']
    # get additional additional information which is critical for the event but doesn't fall under OCSF schema
    enrichments = get_enrichment_data(data['detail']['client'])
    # get time of the event
    date_time = datetime.strptime(data['time'], '%Y-%m-%dT%H:%M:%SZ')
    _time = int(date_time.timestamp())
    # get type of the logon
    logon_type, logon_type_id = get_logon_type(data['detail']['transaction'])
    # get the description of the message
    display_message = data['detail']['displayMessage']
    # get the original event as reported
    ref_time = data['time']
    # get userID value
    profile = data['detail']['actor']['alternateId']
    # get the Session UID value
    session_uid = data['detail']['authenticationContext']['externalSessionId']
    # get the log severity of the event
    severity, severity_id = get_severity(data['detail']['severity'])
    # get the endpoint from which the authentication was requested.
    src_endpoint = get_src_endpoint(data['detail'])
    # get existing user from which an activity was initiated.
    src_user = get_src_user(data['detail'])
    # get event status details in OCSF format
    status, status_code, status_detail, status_id = get_status_details(data['detail'])
    # get event type details in OCSF format
    type_uid, type_name = get_type_category(data['detail']['eventType'])
    # get metadata about the event type in OCSF format
    metadata = get_metadata(data['time'], data['version'])
    # Assemeble the JSON string in OCSF format
    json_data = {
        'activity_name': activity,
        'activity_id': activity_id,
        'auth_protocol': auth_protocol,
        'auth_protocol_id': auth_protocol_id,
        'category_name': category_name,
        'category_uid': category_uid,
        'class_name': class_name,
        'class_uid': class_uid,
        'is_cleartext': is_cleartext,
        'dst_endpoint': dst_endpoint,
        'dst_user': dst_user,
        'enrichments': enrichments,
        'time': _time,
        'logon_type': logon_type,
        'logon_type_id': logon_type_id,
        'displayMessage': display_message,
        'ref_time': ref_time,
        'profile': profile,
        'session_uid': session_uid,
        'severity': severity,
        'severity_id': severity_id,
        'src_endpoint': src_endpoint,
        'user': src_user,
        'status': status,
        'status_code': status_code,
        'status_detail': status_detail,
        'status_id': status_id,
        'type_uid': type_uid,
        'type_name': type_name,
        'metadata': metadata
    }
    # Return the JSON String
    return json_data