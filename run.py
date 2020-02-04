#!/usr/bin/env python3
"""Exports vCenter objects and imports them into Netbox via Python3"""

import atexit
from socket import gaierror
from datetime import date, datetime
from ipaddress import ip_network
import argparse
import requests
from pyVim.connect import SmartConnectNoSSL, Disconnect
from pyVmomi import vim
import settings
from logger import log


def main():
    """Main function to run if script is called directly"""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-c", "--cleanup", action="store_true",
        help="Remove all vCenter synced objects which support tagging. This "
             "is helpful if you want to start fresh or stop using this script."
        )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Enable verbose output. This overrides the log level in the "
             "settings file. Intended for debugging purposes only."
        )
    args = parser.parse_args()
    if args.verbose:
        log.setLevel("DEBUG")
        log.debug("Log level has been overriden by the --verbose argument.")
    for vc_host in settings.VC_HOSTS:
        try:
            start_time = datetime.now()
            nb = NetBoxHandler(vc_conn=vc_host)
            if args.cleanup:
                nb.remove_all()
                log.info(
                    "Completed removal of vCenter instance '%s' objects. Total "
                    "execution time %s.",
                    vc_host["HOST"], (datetime.now() - start_time)
                    )
            else:
                nb.verify_dependencies()
                nb.sync_objects(vc_obj_type="datacenters")
                nb.sync_objects(vc_obj_type="clusters")
                nb.sync_objects(vc_obj_type="hosts")
                nb.sync_objects(vc_obj_type="virtual_machines")
                nb.set_primary_ips()
                log.info(
                    "Completed sync with vCenter instance '%s'! Total "
                    "execution time %s.", vc_host["HOST"],
                    (datetime.now() - start_time)
                    )
        except (ConnectionError, requests.exceptions.ConnectionError,
                requests.exceptions.ReadTimeout) as err:
            log.warning(
                "Critical connection error occurred. Skipping sync with '%s'.",
                vc_host["HOST"]
                )
            log.debug("Connection error details: %s", err)
            continue


def compare_dicts(dict1, dict2, dict1_name="d1", dict2_name="d2", path=""):
    """
    Compares the key value pairs of two dictionaries and match boolean.

    dict1 keys and values are compared against dict2. dict2 may have keys and
    values that dict1 does not care evaluate.
    dict1_name and dict2_name allow you to overwrite dictionary name for logs.
    """
    # Setup paths to track key exploration. The path parameter is used to allow
    # recursive comparisions and track what's being compared.
    result = True
    for key in dict1.keys():
        dict1_path = "{}{}[{}]".format(dict1_name, path, key)
        dict2_path = "{}{}[{}]".format(dict2_name, path, key)
        if key not in dict2.keys():
            log.debug("%s not a valid key in %s.", dict1_path, dict2_path)
            result = False
        elif isinstance(dict1[key], dict) and isinstance(dict2[key], dict):
            log.debug(
                "%s and %s contain dictionary. Evaluating.", dict1_path,
                dict2_path
                )
            result = compare_dicts(
                dict1[key], dict2[key], dict1_name, dict2_name,
                path="[{}]".format(key)
                )
        elif isinstance(dict1[key], list) and isinstance(dict2[key], list):
            log.debug(
                "%s and %s key '%s' contains list. Validating dict1 items "
                "exist in dict2.", dict1_path, dict2_path, key
                )
            if not all([bool(item in dict2[key]) for item in dict1[key]]):
                log.debug(
                    "Mismatch: %s value is '%s' while %s value is '%s'.",
                    dict1_path, dict1[key], dict2_path, dict2[key]
                    )
                result = False
        # Hack for NetBox v2.6.7 requiring integers for some values
        elif key in ["status", "type"]:
            if dict1[key] != dict2[key]["value"]:
                log.debug(
                    "Mismatch: %s value is '%s' while %s value is '%s'.",
                    dict1_path, dict1[key], dict2_path, dict2[key]["value"]
                    )
                result = False
        elif dict1[key] != dict2[key]:
            log.debug(
                "Mismatch: %s value is '%s' while %s value is '%s'.",
                dict1_path, dict1[key], dict2_path, dict2[key]
                )
            result = False
        if result:
            log.debug("%s and %s values match.", dict1_path, dict2_path)
        else:
            log.debug("%s and %s values do not match.", dict1_path, dict2_path)
            return result
    log.debug("Final dictionary compare result: %s", result)
    return result


def format_ip(ip_addr):
    """
    Formats IPv4 addresses to IP with CIDR standard notation.

    ip_address expects IP and subnet mask, example: 192.168.0.0/255.255.255.0
    """
    ip = ip_addr.split("/")[0]
    cidr = ip_network(ip_addr, strict=False).prefixlen
    result = "{}/{}".format(ip, cidr)
    log.debug("Converted '%s' to CIDR notation '%s'.", ip_addr, result)
    return result

def format_slug(text):
    """
    Format string to comply to NetBox slug acceptable pattern and max length.

    NetBox slug pattern: ^[-a-zA-Z0-9_]+$
    NetBox slug max length: 50 characters
    """
    allowed_chars = (
        "abcdefghijklmnopqrstuvxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" # Alphabet
        "01234567890" # Numbers
        "_-" # Symbols
        )
    # Replace seperators with dash
    seperators = [" ", ",", "."]
    for sep in seperators:
        text = text.replace(sep, "-")
    # Strip unacceptable characters
    text = "".join([c for c in text if c in allowed_chars])
    # Enforce max length
    return truncate(text, max_len=50).lower()

def format_tag(tag):
    """
    Format string to comply to NetBox tag format and max length.

    NetBox tag max length: 100 characters
    """
    # If the tag presented is an IP address then no modifications are required
    try:
        ip_network(tag)
    except ValueError:
        # If an IP was not provided then assume fqdn
        tag = tag.split(".")[0]
        tag = truncate(tag, max_len=100)
    return tag

def format_vcenter_conn(conn):
    """
    Formats :param conn: into the expected connection string for vCenter.

    This supports the use of per-host credentials without breaking previous
    deployments during upgrade.

    :param conn: vCenter host connection details provided in settings.py
    :type conn: dict
    :returns: A dictionary containing the host details and credentials
    :rtype: dict
    """
    try:
        if bool(conn["USER"] != "" and conn["PASS"] != ""):
            log.debug(
                "Host specific vCenter credentials provided for '%s'.",
                conn["HOST"]
                )
        else:
            log.debug(
                "Host specific vCenter credentials are not defined for '%s'.",
                conn["HOST"]
                )
            conn["USER"], conn["PASS"] = settings.VC_USER, settings.VC_PASS
    except KeyError:
        log.debug(
            "Host specific vCenter credential key missing for '%s'. Falling "
            "back to global.", conn["HOST"]
            )
        conn["USER"], conn["PASS"] = settings.VC_USER, settings.VC_PASS
    return conn

def truncate(text="", max_len=50):
    """Ensure a string complies to the maximum length specified."""
    return text if len(text) < max_len else text[:max_len]

def verify_ip(ip_addr):
    """
    Verify input is expected format and checks against allowed networks.

    Allowed networks can be defined in the settings IPV4_ALLOWED and
    IPV6_ALLOWED variables.
    """
    result = False
    try:
        log.debug(
            "Validating IP '%s' is properly formatted and within allowed "
            "networks.",
            ip_addr
            )
        # Strict is set to false to allow host address checks
        version = ip_network(ip_addr, strict=False).version
        global_nets = settings.IPV4_ALLOWED if version == 4 \
                      else settings.IPV6_ALLOWED
        # Check whether the network is within the global allowed networks
        log.debug(
            "Checking whether IP address '%s' is within %s.", ip_addr,
            global_nets
            )
        net_matches = [
            ip_network(ip_addr, strict=False).overlaps(ip_network(net))
            for net in global_nets
            ]
        result = any(net_matches)
    except ValueError as err:
        log.debug("Validation of %s failed. Received error: %s", ip_addr, err)
    log.debug("IP '%s' validation returned a %s status.", ip_addr, result)
    return result

class vCenterHandler:
    """Handles vCenter connection state and object data collection"""
    def __init__(self, vc_conn):
        self.vc_session = None # Used to hold vCenter session state
        self.vc_host = vc_conn["HOST"]
        self.vc_port = vc_conn["PORT"]
        self.vc_user = vc_conn["USER"]
        self.vc_pass = vc_conn["PASS"]
        self.tags = ["Synced", "vCenter", format_tag(self.vc_host)]

    def authenticate(self):
        """Authenticate to vCenter"""
        log.info(
            "Attempting authentication to vCenter instance '%s'.",
            self.vc_host
            )
        try:
            vc_instance = SmartConnectNoSSL(
                host=self.vc_host,
                port=self.vc_port,
                user=self.vc_user,
                pwd=self.vc_pass,
                )
            atexit.register(Disconnect, vc_instance)
            self.vc_session = vc_instance.RetrieveContent()
            log.info(
                "Successfully authenticated to vCenter instance '%s'.",
                self.vc_host
                )
        except (gaierror, vim.fault.InvalidLogin, OSError) as err:
            if isinstance(err, OSError):
                err = "System unreachable."
            err_msg = (
                "Unable to connect to vCenter instance '{}' on port {}. "
                "Reason: {}".format(self.vc_host, self.vc_port, err)
                )
            log.critical(err_msg)
            raise ConnectionError(err_msg)

    def create_view(self, vc_obj_type):
        """
        Create a view scoped to the vCenter object type desired.

        This should be called before collecting data about vCenter object types.
        """
        # Mapping of object type keywords to view types
        vc_obj_views = {
            "datacenters": vim.Datacenter,
            "clusters": vim.ClusterComputeResource,
            "hosts": vim.HostSystem,
            "virtual_machines": vim.VirtualMachine,
            }
        # Ensure an active vCenter session exists
        if not self.vc_session:
            log.info("No existing vCenter session found.")
            self.authenticate()
        return self.vc_session.viewManager.CreateContainerView(
            self.vc_session.rootFolder, # View starting point
            [vc_obj_views[vc_obj_type]], # Object types to look for
            True # Should we recurively look into view
            )

    def get_objects(self, vc_obj_type):
        """
        Collects vCenter objects of type and returns NetBox formated objects.

        Returns dictionary of NetBox object types and corresponding list of
        Netbox objects. Object format must be compliant to NetBox API POST
        method (include all required fields).
        """
        log.info(
            "Collecting vCenter %s objects.",
            vc_obj_type[:-1].replace("_", " ") # Format virtual machines
            )
        # Mapping of vCenter object types to NetBox object types
        obj_type_map = {
            "datacenters": ["cluster_groups"],
            "clusters": ["clusters"],
            "hosts": [
                "manufacturers", "device_types", "devices", "interfaces",
                "ip_addresses"
                ],
            "virtual_machines": [
                "virtual_machines", "virtual_interfaces", "ip_addresses"
                ]
            }
        results = {}
        # Initalize keys expected to be returned
        for nb_obj_type in obj_type_map[vc_obj_type]:
            results.setdefault(nb_obj_type, [])
        # Create vCenter view for object collection
        container_view = self.create_view(vc_obj_type)
        for obj in container_view.view:
            try:
                obj_name = obj.name
                log.info(
                    "Collecting info about vCenter %s '%s' object.",
                    vc_obj_type, obj_name
                    )
                if vc_obj_type == "datacenters":
                    results["cluster_groups"].append(
                        {
                            "name": truncate(obj_name, max_len=50),
                            "slug": format_slug(obj_name),
                        })
                elif vc_obj_type == "clusters":
                    cluster_group = truncate(obj.parent.parent.name, max_len=50)
                    results["clusters"].append(
                        {
                            "name": truncate(obj_name, max_len=100),
                            "type": {"name": "VMware ESXi"},
                            "group": {"name": cluster_group},
                            "tags": self.tags
                        })
                elif vc_obj_type == "hosts":
                    obj_manuf_name = truncate(
                        obj.summary.hardware.vendor, max_len=50
                        )
                    # NetBox Manufacturers and Device Types are susceptible to
                    # duplication as they are parents to multiple objects
                    # To avoid unnecessary querying we check to make sure they
                    # haven't already been collected
                    duplicate = {"manufacturers": False, "device_types": False}
                    if obj_manuf_name in \
                    [res["name"] for res in results["manufacturers"]]:
                        duplicate["manufacturers"] = True
                        log.debug(
                            "Manufacturers object already exists. Skipping."
                            )
                    if not duplicate["manufacturers"]:
                        log.debug(
                            "Collecting info to create NetBox manufacturers "
                            "object."
                            )
                        results["manufacturers"].append(
                            {
                                "name": obj_manuf_name,
                                "slug": format_slug(obj_manuf_name)
                            })
                    obj_model = truncate(obj.summary.hardware.model, max_len=50)
                    if obj_model in \
                    [res["model"] for res in results["device_types"]]:
                        duplicate["device_types"] = True
                        log.debug(
                            "Device Types object already exists. Skipping."
                            )
                    if not duplicate["device_types"]:
                        log.debug(
                            "Collecting info to create NetBox device_types "
                            "object."
                            )
                        results["device_types"].append(
                            {
                                "manufacturer": {
                                    "name": obj_manuf_name
                                    },
                                "model": obj_model,
                                "slug": format_slug(obj_model),
                                "part_number": obj_model,
                                "tags": self.tags
                            })
                    log.debug(
                        "Collecting info to create NetBox devices object."
                        )
                    # Attempt to find serial number and asset tag
                    hw_idents = { # Scan throw identifiers to find S/N
                        identifier.identifierType.key:
                        identifier.identifierValue
                        for identifier in
                        obj.summary.hardware.otherIdentifyingInfo
                        }
                    # Serial Number
                    if "EnclosureSerialNumberTag" in hw_idents.keys():
                        serial_number = hw_idents["EnclosureSerialNumberTag"]
                        serial_number = truncate(serial_number, max_len=50)
                    elif "ServiceTag" in hw_idents.keys() \
                    and " " not in hw_idents["ServiceTag"]:
                        serial_number = hw_idents["ServiceTag"]
                        serial_number = truncate(serial_number, max_len=50)
                    else:
                        serial_number = None
                    # Asset Tag
                    if "AssetTag" in hw_idents.keys():
                        banned_tags = ["Default string", "Unknown", " ", ""]
                        asset_tag = truncate(hw_idents["AssetTag"], max_len=50)
                        for btag in banned_tags:
                            if btag.lower() in hw_idents["AssetTag"].lower():
                                log.debug("Banned asset tag string. Nulling.")
                                asset_tag = None
                                break
                    else:
                        asset_tag = None
                    cluster = truncate(obj.parent.name, max_len=100)
                    results["devices"].append(
                        {
                            "name": truncate(obj_name, max_len=64),
                            "device_type": {"model": obj_model},
                            "device_role": {"name": "Server"},
                            "platform": {"name": "VMware ESXi"},
                            "site": {"name": "vCenter"},
                            "serial": serial_number,
                            "asset_tag": asset_tag,
                            "cluster": {"name": cluster},
                            "status": ( # 0 = Offline / 1 = Active
                                1 if obj.summary.runtime.connectionState == \
                                "connected"
                                else 0
                                ),
                            "tags": self.tags
                        })
                    # Iterable object types
                    # Physical Interfaces
                    log.debug(
                        "Collecting info to create NetBox interfaces object."
                        )
                    for pnic in obj.config.network.pnic:
                        nic_name = truncate(pnic.device, max_len=64)
                        log.debug(
                            "Collecting info for physical interface '%s'.",
                            nic_name
                            )
                        # Try multiple methods of finding link speed
                        link_speed = pnic.spec.linkSpeed
                        if link_speed is None:
                            try:
                                link_speed = "{}Mbps ".format(
                                    pnic.validLinkSpecification[0].speedMb
                                    )
                            except IndexError:
                                log.debug(
                                    "No link speed detected for physical "
                                    "interface '%s'.", nic_name
                                    )
                        else:
                            link_speed = "{}Mbps ".format(
                                pnic.spec.linkSpeed.speedMb
                                )
                        results["interfaces"].append(
                            {
                                "device": {
                                    "name": truncate(obj_name, max_len=64)
                                    },
                                # Interface speed is placed in the description
                                # as it is irrelevant to making connections and
                                # an error prone mapping process
                                "type": 32767, # 32767 = Other
                                "name": nic_name,
                                # Capitalized to match NetBox format
                                "mac_address": pnic.mac.upper(),
                                "description": "{}Physical Interface".format(
                                    link_speed
                                    ),
                                "enabled": bool(link_speed),
                                "tags": self.tags
                            })
                    # Virtual Interfaces
                    for vnic in obj.config.network.vnic:
                        nic_name = truncate(vnic.device, max_len=64)
                        log.debug(
                            "Collecting info for virtual interface '%s'.",
                            nic_name
                            )
                        results["interfaces"].append(
                            {
                                "device": {
                                    "name": truncate(obj_name, max_len=64)
                                    },
                                "type": 0, # 0 = Virtual
                                "name": nic_name,
                                "mac_address": vnic.spec.mac.upper(),
                                "mtu": vnic.spec.mtu,
                                "tags": self.tags
                            })
                        # IP Addresses
                        ip_addr = vnic.spec.ip.ipAddress
                        log.debug(
                            "Collecting info for IP Address '%s'.",
                            ip_addr
                            )
                        results["ip_addresses"].append(
                            {
                                "address": "{}/{}".format(
                                    ip_addr, vnic.spec.ip.subnetMask
                                    ),
                                "vrf": None, # Collected from prefix
                                "tenant": None, # Collected from prefix
                                "interface": {
                                    "device": {
                                        "name": truncate(obj_name, max_len=64)
                                        },
                                    "name": nic_name,
                                    },
                                "tags": self.tags
                            })
                elif vc_obj_type == "virtual_machines":
                    log.info(
                        "Collecting info about vCenter %s '%s' object.",
                        vc_obj_type, obj_name
                        )
                    # Virtual Machines
                    log.debug(
                        "Collecting info for virtual machine '%s'", obj_name
                        )
                    # Platform
                    vm_family = obj.guest.guestFamily
                    platform = None
                    cluster = truncate(
                        obj.runtime.host.parent.name, max_len=100
                        )
                    if vm_family is not None:
                        if "linux" in vm_family:
                            platform = {"name": "Linux"}
                        elif "windows" in vm_family:
                            platform = {"name": "Windows"}
                    results["virtual_machines"].append(
                        {
                            "name": truncate(obj_name, max_len=64),
                            "status": 1 if obj.runtime.powerState == "poweredOn"
                                      else 0,
                            "cluster": {"name": cluster},
                            "role": {"name": "Server"},
                            "platform": platform,
                            "memory": obj.config.hardware.memoryMB,
                            "disk": int(sum([
                                comp.capacityInKB for comp in
                                obj.config.hardware.device
                                if isinstance(comp, vim.vm.device.VirtualDisk)
                                ]) / 1024 / 1024), # Kilobytes to Gigabytes
                            "vcpus": obj.config.hardware.numCPU,
                            "tags": self.tags
                        })
                    # If VMware Tools is not detected then we cannot reliably
                    # collect interfaces and IP addresses
                    if vm_family:
                        for index, nic in enumerate(obj.guest.net):
                            # Interfaces
                            nic_name = "vNIC{}".format(index)
                            log.debug(
                                "Collecting info for virtual interface '%s'.",
                                nic_name
                                )
                            results["virtual_interfaces"].append(
                                {
                                    "virtual_machine": {
                                        "name": truncate(obj_name, max_len=64)
                                        },
                                    "type": 0, # 0 = Virtual
                                    "name": nic_name,
                                    "mac_address": nic.macAddress.upper(),
                                    "enabled": nic.connected,
                                    "tags": self.tags
                                })
                            # IP Addresses
                            if nic.ipConfig is not None:
                                for ip in nic.ipConfig.ipAddress:
                                    ip_addr = ip.ipAddress
                                    log.debug(
                                        "Collecting info for IP Address '%s'.",
                                        ip_addr
                                        )
                                    results["ip_addresses"].append(
                                        {
                                            "address": "{}/{}".format(
                                                ip_addr, ip.prefixLength
                                                ),
                                            # VRF and Tenant are initialized
                                            # to be later collected through a
                                            # prefix search
                                            "vrf": None,
                                            "tenant": None,
                                            "interface": {
                                                "virtual_machine": {
                                                    "name": truncate(
                                                        obj_name, max_len=64
                                                        )
                                                    },
                                                "name": nic_name,
                                                },
                                            "tags": self.tags
                                        })
            except AttributeError:
                log.warning(
                    "Unable to collect necessary data for vCenter %s '%s'"
                    "object. Skipping.", vc_obj_type, obj
                    )
                continue
        container_view.Destroy()
        log.debug(
            "Collected %s vCenter %s object%s.", len(results),
            vc_obj_type[:-1].replace("_", " "),
            "s" if len(results) != 1 else "",
            )
        return results

class NetBoxHandler:
    """Handles NetBox connection state and interaction with API"""
    def __init__(self, vc_conn):
        self.header = {"Authorization": "Token {}".format(settings.NB_API_KEY)}
        self.nb_api_url = "http{}://{}{}/api/".format(
            ("s" if not settings.NB_DISABLE_TLS else ""), settings.NB_FQDN,
            (":{}".format(settings.NB_PORT) if settings.NB_PORT != 443 else "")
            )
        self.nb_session = None
        # NetBox object type relationships when working in the API
        self.obj_map = {
            "cluster_groups": {
                "api_app": "virtualization",
                "api_model": "cluster-groups",
                "key": "name",
                "prune": False,
                },
            "cluster_types": {
                "api_app": "virtualization",
                "api_model": "cluster-types",
                "key": "name",
                "prune": False,
                },
            "clusters": {
                "api_app": "virtualization",
                "api_model": "clusters",
                "key": "name",
                "prune": True,
                "prune_pref": 2
                },
            "device_roles": {
                "api_app": "dcim",
                "api_model": "device-roles",
                "key": "name",
                "prune": False,
                },
            "device_types": {
                "api_app": "dcim",
                "api_model": "device-types",
                "key": "model",
                "prune": True,
                "prune_pref": 3
                },
            "devices": {
                "api_app": "dcim",
                "api_model": "devices",
                "key": "name",
                "prune": True,
                "prune_pref": 4
                },
            "interfaces": {
                "api_app": "dcim",
                "api_model": "interfaces",
                "key": "name",
                "prune": True,
                "prune_pref": 5
                },
            "ip_addresses": {
                "api_app": "ipam",
                "api_model": "ip-addresses",
                "key": "address",
                "prune": True,
                "prune_pref": 8
                },
            "manufacturers": {
                "api_app": "dcim",
                "api_model": "manufacturers",
                "key": "name",
                "prune": False,
                },
            "platforms": {
                "api_app": "dcim",
                "api_model": "platforms",
                "key": "name",
                "prune": False,
                },
            "prefixes": {
                "api_app": "ipam",
                "api_model": "prefixes",
                "key": "prefix",
                "prune": False,
                },
            "sites": {
                "api_app": "dcim",
                "api_model": "sites",
                "key": "name",
                "prune": True,
                "prune_pref": 1
                },
            "tags": {
                "api_app": "extras",
                "api_model": "tags",
                "key": "name",
                "prune": False,
                },
            "virtual_machines": {
                "api_app": "virtualization",
                "api_model": "virtual-machines",
                "key": "name",
                "prune": True,
                "prune_pref": 6
                },
            "virtual_interfaces": {
                "api_app": "virtualization",
                "api_model": "interfaces",
                "key": "name",
                "prune": True,
                "prune_pref": 7
                },
            }
        # Create an instance of the vCenter host for use in tagging functions
        # Strip to hostname if a fqdn was provided
        self.vc_tag = format_tag(vc_conn["HOST"])
        self.vc = vCenterHandler(format_vcenter_conn(vc_conn))

    def get_primary_ip(self, nb_obj_type, nb_id):
        """Collects the primary IP of a NetBox device or virtual machine."""
        query_key = str(
            "device_id" if nb_obj_type == "devices" else "virtual_machine_id"
            )
        req = self.request(
            req_type="get", nb_obj_type="ip_addresses",
            query="?{}={}".format(query_key, nb_id)
            )
        log.debug("Found %s child IP addresses.", req["count"])
        if req["count"] > 0:
            result = {
                "address": req["results"][0]["address"],
                "id": req["results"][0]["id"]
                }
            log.debug(
                "Selected %s (ID: %s) as primary IP.", result["address"],
                result["id"]
                )
        else:
            result = None
        return result

    def request(self, req_type, nb_obj_type, data=None, query=None, nb_id=None):
        """
        HTTP requests and exception handler for NetBox

        req_type: HTTP Method
        nb_obj_type: NetBox object type, must match keys in self.obj_map
        data: Dictionary to be passed as request body.
        query: String used to filter results when using GET method
        nb_id: Integer used when working with a single NetBox object
        """
        # If an existing session is not already found then create it
        # The goal here is session re-use without TCP handshake on every request
        if not self.nb_session:
            self.nb_session = requests.Session()
            self.nb_session.headers.update(self.header)
        result = None
        # Generate URL
        url = "{}{}/{}/{}{}".format(
            self.nb_api_url,
            self.obj_map[nb_obj_type]["api_app"], # App that model falls under
            self.obj_map[nb_obj_type]["api_model"], # Data model
            query if query else "",
            "{}/".format(nb_id) if nb_id else ""
            )
        log.debug(
            "Sending %s to '%s' with data '%s'.", req_type.upper(), url, data
            )
        req = getattr(self.nb_session, req_type)(
            url, json=data, timeout=10, verify=(not settings.NB_INSECURE_TLS)
            )
        # Parse status
        log.debug("Received HTTP Status %s.", req.status_code)
        if req.status_code == 200:
            log.debug(
                "NetBox %s request OK; returned %s status.", req_type.upper(),
                req.status_code
                )
            result = req.json()
            if req_type == "get":
                # NetBox returns 50 results by default, this ensures all results
                # are bundled together
                while req.json()["next"] is not None:
                    url = req.json()["next"]
                    log.debug(
                        "NetBox returned more than 50 objects. Sending %s to "
                        "%s for additional objects.", req_type.upper(), url
                        )
                    req = getattr(self.nb_session, req_type)(url, timeout=10)
                    result["results"] += req.json()["results"]
        elif req.status_code in [201, 204]:
            log.info(
                "NetBox successfully %s %s object.",
                "created" if req.status_code == 201 else "deleted",
                nb_obj_type,
                )
        elif req.status_code == 400:
            if req_type == "post":
                log.warning(
                    "NetBox failed to create %s object. A duplicate record may "
                    "exist or the data sent is not acceptable.", nb_obj_type
                    )
                log.debug(
                    "NetBox %s status reason: %s", req.status_code, req.text
                    )
            elif req_type == "put":
                log.warning(
                    "NetBox failed to modify %s object with status %s. The "
                    "data sent may not be acceptable.", nb_obj_type,
                    req.status_code
                    )
                log.debug(
                    "NetBox %s status reason: %s", req.status_code, req.text
                    )
            else:
                raise SystemExit(
                    log.critical(
                        "Well this in unexpected. Please report this. "
                        "%s request received %s status with body '%s' and "
                        "response '%s'.",
                        req_type.upper(), req.status_code, data, req.json()
                        )
                    )
            log.debug("Unaccepted request data: %s", data)
        elif req.status_code == 409 and req_type == "delete":
            log.warning(
                "Received %s status when attemping to delete NetBox object "
                "(ID: %s). If you have more than 1 vCenter host configured "
                "this may be deleted on the final pass. Otherwise check the "
                "object dependencies.",
                req.status_code, nb_id
                )
            log.debug("NetBox %s status body: %s", req.status_code, req.json())
        else:
            raise SystemExit(
                log.critical(
                    "Well this in unexpected. Please report this. "
                    "%s request received %s status with body '%s' and response "
                    "'%s'.",
                    req_type.upper(), req.status_code, data, req.text
                    )
                )
        return result

    def obj_exists(self, nb_obj_type, vc_data):
        """
        Checks whether a NetBox object exists and matches the vCenter object.

        If object does not exist or does not match the vCenter object it will
        be created or updated.

        nb_obj_type: String NetBox object type to query for and compare against
        vc_data: Dictionary of vCenter object key value pairs pre-formatted for
        NetBox
        """
        # NetBox Device Types objects do not have names to query; we catch
        # and use the model instead
        query_key = self.obj_map[nb_obj_type]["key"]
        # Create a query specific to the device parent/child relationship when
        # working with interfaces
        if nb_obj_type == "interfaces":
            query = "?device={}&{}={}".format(
                vc_data["device"]["name"], query_key, vc_data[query_key]
                )
        elif nb_obj_type == "virtual_interfaces":
            query = "?virtual_machine={}&{}={}".format(
                vc_data["virtual_machine"]["name"], query_key,
                vc_data[query_key]
                )
        else:
            query = "?{}={}".format(query_key, vc_data[query_key])
        req = self.request(
            req_type="get", nb_obj_type=nb_obj_type,
            query=query
            )
        # A single matching object is found so we compare its values to the new
        # object
        if req["count"] == 1:
            log.debug(
                "NetBox %s object '%s' already exists. Comparing values.",
                nb_obj_type, vc_data[query_key]
                )
            nb_data = req["results"][0]
            # Objects that have been previously tagged as orphaned but then
            # reappear in vCenter need to be stripped of their orphaned status
            if "tags" in vc_data and "Orphaned" in nb_data["tags"]:
                log.info(
                    "NetBox %s object '%s' is currently marked as orphaned "
                    "but has reappeared in vCenter. Updating NetBox.",
                    nb_obj_type, vc_data[query_key]
                    )
                self.request(
                    req_type="put", nb_obj_type=nb_obj_type, data=vc_data,
                    nb_id=nb_data["id"]
                    )
            elif compare_dicts(
                    vc_data, nb_data, dict1_name="vc_data",
                    dict2_name="nb_data"):
                log.info(
                    "NetBox %s object '%s' match current values. Moving on.",
                    nb_obj_type, vc_data[query_key]
                    )
            else:
                log.info(
                    "NetBox %s object '%s' do not match current values.",
                    nb_obj_type, vc_data[query_key]
                    )
                # Issue #1: Ensure existing and new tags are merged together
                # This allows users to add alternative tags or sync from
                # multiple vCenter instances
                if "tags" in vc_data:
                    log.debug("Merging tags between vCenter and NetBox object.")
                    vc_data["tags"] = list(
                        set(vc_data["tags"] + nb_data["tags"])
                        )
                self.request(
                    req_type="put", nb_obj_type=nb_obj_type, data=vc_data,
                    nb_id=nb_data["id"]
                    )
        elif req["count"] > 1:
            log.warning(
                "Search for NetBox %s object '%s' returned %s results but "
                "should have only returned 1. Please manually review and "
                "report this if the data is accurate. Skipping for safety.",
                nb_obj_type, vc_data[query_key], req["count"]
                )
        else:
            log.info(
                "Netbox %s '%s' object not found. Requesting creation.",
                nb_obj_type,
                vc_data[query_key],
                )
            self.request(
                req_type="post", nb_obj_type=nb_obj_type, data=vc_data
                )

    def set_primary_ips(self):
        """Sets the Primary IP of vCenter hosts and Virtual Machines."""
        for nb_obj_type in ("devices", "virtual_machines"):
            log.info(
                "Collecting NetBox %s objects to set Primary IPs.",
                nb_obj_type[:-1].replace("_", " ")
                )
            obj_key = self.obj_map[nb_obj_type]["key"]
            # Collect all parent objects that support Primary IPs
            parents = self.request(
                req_type="get", nb_obj_type=nb_obj_type,
                query="?tag={}".format(format_slug(self.vc_tag))
                )
            log.info("Collected %s NetBox objects.", parents["count"])
            for nb_obj in parents["results"]:
                update_object = False
                parent_id = nb_obj["id"]
                nb_obj_name = nb_obj[obj_key]
                new_pri_ip = self.get_primary_ip(nb_obj_type, parent_id)
                # Skip the rest if we don't have a usable IP
                if new_pri_ip is None:
                    log.info(
                        "No usable IPs were found for NetBox '%s' object. "
                        "Moving on.",
                        nb_obj_name
                        )
                    continue
                if nb_obj["primary_ip"] is None:
                    log.info(
                        "No existing Primary IP found for NetBox '%s' object.",
                        nb_obj_name
                        )
                    update_object = True
                else:
                    log.info(
                        "Primary IP already set for NetBox '%s' object. "
                        "Comparing.",
                        nb_obj_name
                        )
                    old_pri_ip = nb_obj["primary_ip"]["id"]
                    if old_pri_ip != new_pri_ip["id"]:
                        log.info(
                            "Existing Primary IP does not match latest check. "
                            "Requesting update."
                            )
                        update_object = True
                    else:
                        log.info(
                            "Existing Primary IP matches latest check. Moving "
                            "on."
                            )
                if update_object:
                    log.info(
                        "Setting NetBox '%s' object primary IP to %s.",
                        nb_obj_name, new_pri_ip["address"]
                        )
                    ip_version = str(
                        "primary_ip{}".format(
                            ip_network(
                                new_pri_ip["address"], strict=False
                                ).version
                        ))
                    data = {ip_version: new_pri_ip["id"]}
                    self.request(
                        req_type="patch", nb_obj_type=nb_obj_type,
                        nb_id=parent_id, data=data
                        )

    def sync_objects(self, vc_obj_type):
        """
        Collects objects from vCenter and syncs them to NetBox.

        Some object types do not support tags so they will be a one-way sync
        meaning orphaned objects will not be removed from NetBox.
        """
        # Collect data from vCenter
        log.info(
            "Initiated sync of vCenter %s objects to NetBox.",
            vc_obj_type[:-1]
            )
        vc_objects = self.vc.get_objects(vc_obj_type=vc_obj_type)
        # Determine each NetBox object type collected from vCenter
        nb_obj_types = list(vc_objects.keys())
        for nb_obj_type in nb_obj_types:
            log.info(
                "Starting sync of %s vCenter %s object%s to NetBox %s "
                "object%s.",
                len(vc_objects[nb_obj_type]),
                vc_obj_type,
                "s" if len(vc_objects[nb_obj_type]) != 1 else "",
                nb_obj_type,
                "s" if len(vc_objects[nb_obj_type]) != 1 else "",
                )
            for obj in vc_objects[nb_obj_type]:
                # Check to ensure IP addresses pass all checks before syncing
                # to NetBox
                if nb_obj_type == "ip_addresses":
                    ip_addr = obj["address"]
                    if verify_ip(ip_addr):
                        log.debug(
                            "IP %s has passed necessary pre-checks.",
                            ip_addr
                            )
                        # Update IP address to CIDR notation for comparsion
                        # with existing NetBox objects
                        obj["address"] = format_ip(ip_addr)
                        # Search for parent prefix to assign VRF and tenancy
                        prefix = self.search_prefix(obj["address"])
                        # Update placeholder values with matched values
                        obj["vrf"] = prefix["vrf"]
                        obj["tenant"] = prefix["tenant"]
                    else:
                        log.debug(
                            "IP %s has failed necessary pre-checks. Skipping "
                            "sync to NetBox.", ip_addr,
                            )
                        continue
                self.obj_exists(nb_obj_type=nb_obj_type, vc_data=obj)
            log.info(
                "Finished sync of %s vCenter %s object%s to NetBox %s "
                "object%s.",
                len(vc_objects[nb_obj_type]),
                vc_obj_type,
                "s" if len(vc_objects[nb_obj_type]) != 1 else "",
                nb_obj_type,
                "s" if len(vc_objects[nb_obj_type]) != 1 else "",
                )
        # Send vCenter objects to the pruner
        if settings.NB_PRUNE_ENABLED:
            self.prune_objects(vc_objects, vc_obj_type)

    def prune_objects(self, vc_objects, vc_obj_type):
        """
        Collects NetBox objects and checks if they still exist in vCenter.

        If NetBox objects are not found in the supplied vc_objects data then
        they will go through a pruning process.

        vc_objects: Dictionary of VC object types and list of their objects
        vc_obj_type: The parent object type called during the synce. This is
        used to determine whether special filtering needs to be applied.
        """
        # Determine qualifying object types based on object map
        nb_obj_types = [t for t in vc_objects if self.obj_map[t]["prune"]]
        # Sort qualify NetBox object types by prune priority. This ensures
        # we do not have issues with deleting due to orphaned dependencies.
        nb_obj_types = sorted(
            nb_obj_types, key=lambda t: self.obj_map[t]["prune_pref"],
            reverse=True
            )
        for nb_obj_type in nb_obj_types:
            log.info(
                "Comparing existing NetBox %s objects to current vCenter "
                "objects for pruning eligibility.", nb_obj_type
                )
            nb_objects = self.request(
                req_type="get", nb_obj_type=nb_obj_type,
                # Tags need to always be searched by slug
                query="?tag={}".format(format_slug(self.vc_tag))
                )["results"]
            # Certain vCenter object types map to multiple NetBox types. We
            # define the relationships to compare against for these situations.
            if vc_obj_type == "hosts" and nb_obj_type == "interfaces":
                nb_objects = [
                    obj for obj in nb_objects
                    if obj["device"] is not None
                    ]
            elif vc_obj_type == "hosts" and nb_obj_type == "ip_addresses":
                nb_objects = [
                    obj for obj in nb_objects
                    if obj["interface"]["device"] is not None
                    ]
            # Issue 33: As of NetBox v2.6.11 it is not possible to filter
            # virtual interfaces by tag. Therefore we filter post collection.
            elif vc_obj_type == "virtual_machines" and \
                    nb_obj_type == "virtual_interfaces":
                nb_objects = [
                    obj for obj in nb_objects
                    if self.vc_tag in obj["tags"]
                    ]
                log.debug(
                    "Found %s virtual interfaces with tag '%s'.",
                    len(nb_objects), self.vc_tag
                    )
            elif vc_obj_type == "virtual_machines" and \
                    nb_obj_type == "ip_addresses":
                nb_objects = [
                    obj for obj in nb_objects
                    if obj["interface"]["virtual_machine"] is not None
                    ]
            # From the vCenter objects provided collect only the names/models of
            # each object from the current type we're comparing against
            query_key = self.obj_map[nb_obj_type]["key"]
            vc_obj_values = [obj[query_key] for obj in vc_objects[nb_obj_type]]
            orphans = [
                obj for obj in nb_objects if obj[query_key] not in vc_obj_values
                ]
            log.info(
                "Comparison completed. %s %s orphaned NetBox object%s did not "
                "match.",
                len(orphans), nb_obj_type, "s" if len(orphans) != 1 else ""
                )
            log.debug("The following objects did not match: %s", orphans)
            # Pruned items are checked against the prune timer
            # All pruned items are first tagged so it is clear why they were
            # deleted, and then those items which are greater than the max age
            # will be deleted permanently
            for orphan in orphans:
                log.info(
                    "Processing orphaned NetBox %s '%s' object.",
                    nb_obj_type, orphan[query_key]
                    )
                if "Orphaned" not in orphan["tags"]:
                    log.info(
                        "No tag found. Adding 'Orphaned' tag to %s '%s' "
                        "object.",
                        nb_obj_type, orphan[query_key]
                        )
                    tags = {
                        "tags": ["Synced", "vCenter", self.vc_tag, "Orphaned"]
                        }
                    self.request(
                        req_type="patch", nb_obj_type=nb_obj_type,
                        nb_id=orphan["id"],
                        data=tags
                        )
                # Check if the orphan has gone past the max prune timer and
                # needs to be deleted
                # Dates are in YY, MM, DD format
                current_date = date.today()
                # Some objects do not have a last_updated field so we must
                # handle that gracefully and send for deletion
                del_obj = False
                try:
                    modified_date = date(
                        int(orphan["last_updated"][:4]), # Year
                        int(orphan["last_updated"][5:7]), # Month
                        int(orphan["last_updated"][8:10]) # Day
                        )
                    # Calculated timedelta then converts it to the days integer
                    days_orphaned = (current_date - modified_date).days
                    if days_orphaned >= settings.NB_PRUNE_DELAY_DAYS:
                        log.info(
                            "The %s '%s' object has exceeded the %s day max "
                            "for orphaned objects. Sending it for deletion.",
                            nb_obj_type, orphan[query_key],
                            settings.NB_PRUNE_DELAY_DAYS
                            )
                        del_obj = True
                    else:
                        log.info(
                            "The %s '%s' object has been orphaned for %s of %s "
                            "max days. Proceeding to next object.",
                            nb_obj_type, orphan[query_key], days_orphaned,
                            settings.NB_PRUNE_DELAY_DAYS
                            )
                except KeyError as err:
                    log.debug(
                        "The %s '%s' object does not have a %s "
                        "field. Sending it for deletion.",
                        nb_obj_type, orphan[query_key], err
                        )
                    del_obj = True
                if del_obj:
                    self.request(
                        req_type="delete", nb_obj_type=nb_obj_type,
                        nb_id=orphan["id"],
                        )

    def search_prefix(self, ip_addr):
        """
        Queries Netbox for the parent prefix of any supplied IP address.

        Returns dictionary of VRF and tenant values.
        """
        result = {"tenant": None, "vrf": None}
        query = "?contains={}".format(ip_addr)
        try:
            prefix_obj = self.request(
                req_type="get", nb_obj_type="prefixes", query=query
                )["results"][-1] # -1 used to choose the most specific result
            prefix = prefix_obj["prefix"]
            for key in result:
                # Ensure the data returned was not null.
                try:
                    result[key] = {"name": prefix_obj[key]["name"]}
                except TypeError:
                    log.debug(
                        "No %s key was found in the parent prefix. Nulling.",
                        key
                        )
                    result[key] = None
            log.debug(
                "IP address %s is a child of prefix %s with the following "
                "attributes: %s", ip_addr, prefix, result
                )
        except IndexError:
            log.debug("No parent prefix was found for IP %s.", ip_addr)
        return result

    def verify_dependencies(self):
        """
        Validates that all prerequisite NetBox objects exist and creates them.
        """
        dependencies = {
            "manufacturers": [
                {"name": "VMware", "slug": "vmware"},
                ],
            "platforms": [
                {"name": "VMware ESXi", "slug": "vmware-esxi"},
                {"name": "Windows", "slug": "windows"},
                {"name": "Linux", "slug": "linux"},
                ],
            "sites": [{
                "name": "vCenter",
                "slug": "vcenter",
                "comments": "A default virtual site created to house objects "
                            "that have been synced from vCenter.",
                "tags": ["Synced", "vCenter"]
                }],
            "cluster_types": [
                {"name": "VMware ESXi", "slug": "vmware-esxi"}
                ],
            "device_roles": [
                {
                    "name": "Server",
                    "slug": "server",
                    "color": "9e9e9e",
                    "vm_role": True
                }],
            "tags": [
                {
                    "name": "Orphaned",
                    "slug": "orphaned",
                    "color": "607d8b",
                    "comments": "This applies to objects that have become "
                                "orphaned. The source system which has "
                                "previously provided the object no longer "
                                "states it exists.{}".format(
                                    " An object with the 'Orphaned' tag will "
                                    "remain in this state until it ages out "
                                    "and is automatically removed."
                                    ) if settings.NB_PRUNE_ENABLED else ""
                },
                {
                    "name": self.vc_tag,
                    "slug": format_slug(self.vc_tag),
                    "comments": "Objects synced from vCenter host "
                                "{}. Be careful not to modify the name or "
                                "slug.".format(self.vc_tag)
                }]
            }
        # For each dependency of each type verify object exists
        log.info("Verifying all prerequisite objects exist in NetBox.")
        for dep_type in dependencies:
            log.debug(
                "Checking NetBox has necessary %s objects.", dep_type[:-1]
                )
            for dep in dependencies[dep_type]:
                self.obj_exists(nb_obj_type=dep_type, vc_data=dep)
        log.info("Finished verifying prerequisites.")

    def remove_all(self):
        """
        Searches NetBox for all synced objects and then removes them.

        This is intended to be used in the case you wish to start fresh or stop
        using the script.
        """
        log.info("Preparing for removal of all NetBox synced vCenter objects.")
        nb_obj_types = [
            t for t in self.obj_map if self.obj_map[t]["prune"]
            ]
        # Honor preference, highest to lowest
        nb_obj_types = sorted(
            nb_obj_types, key=lambda t: self.obj_map[t]["prune_pref"],
            reverse=True
            )
        for nb_obj_type in nb_obj_types:
            log.info(
                "Collecting all current NetBox %s objects to prepare for "
                "deletion.", nb_obj_type
                )
            query = "?tag={}".format(
                # vCenter site is a global dependency so we change the query
                "vcenter" if nb_obj_type == "sites"
                else format_slug(self.vc_tag)
                )
            nb_objects = self.request(
                req_type="get", nb_obj_type=nb_obj_type,
                query=query
                )["results"]
            query_key = self.obj_map[nb_obj_type]["key"]
            # NetBox virtual interfaces do not currently support filtering
            # by tags. Therefore we collect all virtual interfaces and
            # filter them post collection.
            if nb_obj_type == "virtual_interfaces":
                log.debug("Collected %s virtual interfaces pre-filtering.")
                nb_objects = [
                    obj for obj in nb_objects if self.vc_tag in obj["tags"]
                    ]
                log.debug(
                    "Filtered to %s virtual interfaces with '%s' tag.",
                    len(nb_objects), self.vc_tag
                    )
            log.info(
                "Deleting %s NetBox %s objects.", len(nb_objects), nb_obj_type
                )
            for obj in nb_objects:
                log.info(
                    "Deleting NetBox %s '%s' object.", nb_obj_type,
                    obj[query_key]
                    )
                self.request(
                    req_type="delete", nb_obj_type=nb_obj_type,
                    nb_id=obj["id"],
                    )


if __name__ == "__main__":
    main()
