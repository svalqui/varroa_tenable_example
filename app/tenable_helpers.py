import os
import ipaddress
from datetime import datetime

from tenable.io import TenableIO

import config


def tenable_check_env_vars() -> bool:
    """
    Return true if there are Tenable credentials in environment variables.

    The Tenable session requires the following environment variables:
    - TIO_ACCESS_KEY
    - TIO_SECRET_KEY
    If any of these are missing, this function will return False. Therefore,
    this function should be called before calling create_tenable_session.
    """
    for env_var in [
        "TIO_ACCESS_KEY",
        "TIO_SECRET_KEY",
    ]:
        if env_var not in os.environ:
            return False
    return True


def create_tenable_session() -> TenableIO:
    """
    Return a session object for the Tenable cloud.

    This function leverages the PyTenable package to create
    a connection to the Tenable cloud using the secret credentials
    stored in the environment variables.
    """
    tio_access_key = os.getenv("TIO_ACCESS_KEY")
    tio_secret_key = os.getenv("TIO_SECRET_KEY")

    # Hardcoded values for Tenable client
    # This helps with logging and tracking in Tenable Cloud
    tenable_vendor = ""
    tenable_product = ""
    tenable_version = ""

    tio = TenableIO(
        tio_access_key,
        tio_secret_key,
        vendor=tenable_vendor,
        product=tenable_product,
        build=tenable_version,
    )
    return tio


def get_findings_based_on_cidr_and_vulns():
    """
    Return a list of IP addresses that have a vulnerability finding based on plugin ID.

    This function queries the Tenable Cloud for all IP addresses in the specified CIDR
    range that have a specific vulnerability finding (e.g., password authentication enabled
    for SSH). Note that both the CIDR range and the plugin ID are specified in the config.py.
    """
    # Create Tenable session
    tio = create_tenable_session()

    # Convert target CIDR to IP network object
    cidr_obj = ipaddress.ip_network(config.TARGET_CIDR)

    # Plugin ID for password authentication enabled (info level )
    security_risk_type = config.SECURITY_RISK_TYPE_TARGET
    plugin_ids = config.SECURITY_RISK_TYPE_TENABLE_PLUGINS[security_risk_type]

    # Using PyTenable, export all vulnerabilities that:
    # - are of the specified plugin ID
    # - are in the specified CIDR range
    results = tio.exports.vulns(plugin_id=plugin_ids, cidr_range=config.TARGET_CIDR)

    # Process findings summary:
    # - Get only OPEN findings that have not been resolved
    # - Get only findings when the IP is in the CIDR range (this is a double check)
    findings = []
    for result in results:
        asset_uuid = result["asset"]["uuid"]
        port = result["port"]["port"]
        last_found = result["last_found"]
        state = result["state"]

        # Skip any findings if the state is not "OPEN"
        # Open means the vulnerability still exists
        if state != "OPEN":
            continue

        # Convert last_found to datetime object
        last_found = datetime.strptime(last_found, "%Y-%m-%dT%H:%M:%S.%fZ")

        # Get the asset in Tenable Cloud
        # We need the asset to get a full list of IP addresses associated with the asset
        # For example, when an instance has multiple interfaces
        asset = tio.assets.details(asset_uuid)

        # Loop through the interfaces to find the IP addresses
        ip_address = None
        for interface in asset["interfaces"]:
            for ip in interface["ipv4"]:
                # Check if the IP is in the CIDR range
                if ipaddress.ip_address(ip) in cidr_obj:
                    ip_address = ip
                    break

        # If the IP address is not in the CIDR range, skip this result
        if ip_address is None:
            continue

        # Create a finding dictionary to return for each result
        finding = {
            "asset_uuid": asset_uuid,
            "port": port,
            "last_found": last_found,
            "state": state,
            "ip_address": ip_address,
            "risk_type": security_risk_type,
        }
        findings.append(finding)

    return findings
