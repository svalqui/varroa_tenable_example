import os
from datetime import datetime, timezone, timedelta

from keystoneauth1 import identity, session
from varroaclient import client

import config


def openstack_check_env_vars() -> bool:
    """
    Return true if there are OpenStack credentials in environment variables.

    The openstack session requires the following environment variables:
    - OS_AUTH_URL
    - OS_APPLICATION_CREDENTIAL_ID
    - OS_APPLICATION_CREDENTIAL_SECRET
    If any of these are missing, this function will return False. Therefore,
    this function should be called before calling create_openstack_session.
    """
    for env_var in [
        "OS_AUTH_URL",
        "OS_APPLICATION_CREDENTIAL_ID",
        "OS_APPLICATION_CREDENTIAL_SECRET",
    ]:
        if env_var not in os.environ:
            return False
    return True


def create_openstack_session() -> session.Session:
    """
    Return a session object for the OpenStack cloud.

    This function leverages the OpenStack keystone package to create
    a connection to the OpenStack cloud using the application credentials
    stored in the environment variables.
    """
    os_auth_url = os.getenv("OS_AUTH_URL")
    os_application_credential_id = os.getenv("OS_APPLICATION_CREDENTIAL_ID")
    os_application_credential_secret = os.getenv("OS_APPLICATION_CREDENTIAL_SECRET")

    auth = identity.v3.application_credential.ApplicationCredential(
        auth_url=os_auth_url,
        application_credential_id=os_application_credential_id,
        application_credential_secret=os_application_credential_secret,
    )
    return session.Session(auth=auth)


def _is_date_between(date_to_check, start_date, end_date):
    if not end_date or not start_date:
        return False
    return start_date <= date_to_check <= end_date


def get_instance_based_on_ip_history(ip_address: str, target_date: datetime) -> str:
    # Create OpenStack session
    sess = create_openstack_session()
    varroa_c = client.Client("1", session=sess)

    # Find the IP history for the specified IP address
    ip_history_list = varroa_c.ip_usage.list(ip=ip_address, all_projects=True)
    current_allocation = None
    resource_id = None
    project_id = None

    # Loop all results in the IP history
    # We are looking for the allocation that was active at the target date
    for ip_history in ip_history_list:
        ip_history_dict = ip_history.to_dict()
        start_date = ip_history.start
        end_date = ip_history.end

        # If the end_date is None, it is the current allocation
        if end_date is None:
            current_allocation = ip_history
            continue

        # Convert the dates to UTC and remove the timezone
        start_date = start_date.astimezone(timezone.utc).replace(tzinfo=None)
        end_date = end_date.astimezone(timezone.utc).replace(tzinfo=None)

        # Check if the target date is between the start and end date
        result = _is_date_between(target_date, start_date, end_date)
        if result:
            resource_id = ip_history_dict["resource_id"]
            project_id = ip_history_dict["project_id"]
            return resource_id, project_id

    # If no allocation was found, return the current allocation...
    # But only if the start date is before the target date
    if current_allocation:
        start_date = current_allocation.start
        start_date = start_date.astimezone(timezone.utc).replace(tzinfo=None)
        if start_date <= target_date:
            resource_id = current_allocation.to_dict()["resource_id"]
            project_id = ip_history_dict["project_id"]
            return resource_id, project_id

    # Return none by default, nothing was found
    return None, None


def check_security_risk_exists(finding: dict) -> bool:
    # Create OpenStack session
    sess = create_openstack_session()
    varroa_c = client.Client("1", session=sess)

    # Determine risk type ID
    risk_type = finding["risk_type"]
    risk_type_id = config.SECURITY_RISK_TYPE_LOOKUP.get(risk_type)
    if not risk_type_id:
        print(f"    [!] Unknown risk type: {risk_type}")
        return False

    # Check if the security risk already exists
    existing_security_risks = varroa_c.security_risks.list(project_id=finding["project_id"])
    # existing_security_risks = varroa_c.security_risks.list(all_projects=True)

    if not existing_security_risks:
        return False

    # Check for matching security risk
    for risk in existing_security_risks:
        if str(risk.type) == risk_type and risk.ipaddress == finding["ip_address"]:
            return True

    return False


def create_security_risk(finding: dict) -> bool:
    # Create OpenStack session
    sess = create_openstack_session()
    varroa_c = client.Client("1", session=sess)

    # Determine risk type ID
    risk_type = finding["risk_type"]
    risk_type_id = config.SECURITY_RISK_TYPE_LOOKUP.get(risk_type)
    if not risk_type_id:
        print(f"    [!] Unknown risk type: {risk_type}")
        return False

    # Set expires date to 7 days from now
    expires = datetime.now() + timedelta(days=7)
    expires = expires.replace(tzinfo=timezone.utc)
    expires = expires.strftime("%Y-%m-%dT%H:%M:%S%z")

    # Convert last found datetime to string
    last_found = finding["last_found"]
    last_found = last_found.astimezone(timezone.utc)
    last_found = last_found.strftime("%Y-%m-%dT%H:%M:%S%z")

    # Create the security risk
    security_risk = varroa_c.security_risks.create(
        time=last_found,
        expires=expires,
        type_id=risk_type_id,
        ipaddress=finding["ip_address"],
        port=finding["port"],
    )

    if not security_risk:
        return False

    return True
