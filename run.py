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
            nb = NetBoxHandler(vc_host["HOST"], vc_host["PORT"])
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
    """Compares the key value pairs of two dictionaries and returns whether
    the values match or not."""
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
            compare_dicts(
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
        if not result:
            log.debug(
                "%s and %s values do not match.", dict1_path, dict2_path
                )
        else:
            log.debug("%s and %s values match.", dict1_path, dict2_path)
    return result

def format_ip(ip_addr):
    """Formats IPv4 addresses to IP with CIDR standard notation. This is used
    to ensure equal comparsion against exists NetBox IP Address objects."""
    ip = ip_addr.split("/")[0]
    cidr = ip_network(ip_addr, strict=False).prefixlen
    result = "{}/{}".format(ip, cidr)
    log.debug("Converted '%s' to CIDR notation '%s'.", ip_addr, result)
    return result

def verify_ip(ip_addr):
    """Verify IP address received is valid and within the allowed networks
    networks provided in the settings file."""
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
    """Handles vCenter connection state and export of objects"""
    def __init__(self, vc_host, vc_port):
        self.vc_session = None # Used to hold vCenter session state
        self.vc_host = vc_host
        self.vc_port = vc_port
        self.tags = ["Synced", "vCenter", vc_host.split(".")[0]]

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
                user=settings.VC_USER,
                pwd=settings.VC_PASS,
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
        """Create a view scoped to the vCenter object type desired.
        This should be called by gets for vCenter object types.
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
        """Collects all objects of a type from vCenter and then builds objects
        in the format NetBox expects.
        NetBox object format should be compliant pass to POST method against the
        API."""
        results = {}
        log.info("Collecting vCenter %s objects.", vc_obj_type[:-1])
        if vc_obj_type == "datacenters":
            # Initalize keys expected to be returned
            results.setdefault("cluster_groups", [])
            container_view = self.create_view(vc_obj_type)
            for obj in container_view.view:
                obj_name = obj.name
                log.info(
                    "Collecting info about vCenter %s '%s' object.",
                    vc_obj_type, obj_name
                    )
                results["cluster_groups"].append(
                    {
                        "name": obj_name,
                        "slug": obj_name.replace(" ", "-").lower(),
                    })
        elif vc_obj_type == "clusters":
            # Initalize keys expected to be returned
            results.setdefault("clusters", [])
            container_view = self.create_view(vc_obj_type)
            for obj in container_view.view:
                try:
                    obj_name = obj.name
                    log.info(
                        "Collecting info about vCenter %s '%s' object.",
                        vc_obj_type, obj_name
                        )
                    results["clusters"].append(
                        {
                            "name": obj_name,
                            "type": {"name": "VMware ESXi"},
                            "group": {"name": obj.parent.parent.name},
                            "tags": self.tags
                        })
                except AttributeError:
                    log.warning(
                        "Unable to collect necessary data for vCenter %s '%s'"
                        "object. Skipping.", vc_obj_type, obj
                        )
                    continue
        elif vc_obj_type == "hosts":
            # Initialize all the NetBox object types we're going to collect
            nb_objects = [
                "manufacturers", "device_types", "devices", "interfaces",
                "ip_addresses"
                ]
            for nb_obj in nb_objects:
                results.setdefault(nb_obj, [])
            container_view = self.create_view(vc_obj_type)
            for obj in container_view.view:
                try:
                    obj_name = obj.name
                    log.info(
                        "Collecting info about vCenter %s '%s' object.",
                        vc_obj_type, obj_name
                        )
                    obj_manuf_name = obj.summary.hardware.vendor
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
                                "slug": obj_manuf_name.\
                                        replace(" ", "-").lower(),
                            })
                    obj_model = obj.summary.hardware.model
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
                                "slug": obj_model.\
                                        replace(" ", "-").lower(),
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
                    elif "ServiceTag" in hw_idents.keys() \
                    and " " not in hw_idents["ServiceTag"]:
                        serial_number = hw_idents["ServiceTag"]
                    else:
                        serial_number = None
                    # Asset Tag
                    if "AssetTag" in hw_idents.keys():
                        banned_tags = ["Default string", "Unknown", " "]
                        asset_tag = hw_idents["AssetTag"]
                        for btag in banned_tags:
                            if btag in hw_idents["AssetTag"]:
                                log.debug("Banned asset tag string. Nulling.")
                                asset_tag = None
                                break
                    else:
                        asset_tag = None
                    results["devices"].append(
                        {
                            "name": obj_name,
                            "device_type": {"model": obj_model},
                            "device_role": {"name": "Server"},
                            "platform": {"name": "VMware ESXi"},
                            "site": {"name": "vCenter"},
                            "serial": serial_number,
                            "asset_tag": asset_tag,
                            "cluster": {"name": obj.parent.name},
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
                        nic_name = pnic.device
                        log.debug(
                            "Collecting info for physical interface '%s'.",
                            nic_name
                            )
                        pnic_up = pnic.spec.linkSpeed
                        results["interfaces"].append(
                            {
                                "device": {"name": obj_name},
                                # Interface speed is placed in the description
                                # as it is irrelevant to making connections and
                                # an error prone mapping process
                                "type": 32767, # 32767 = Other
                                "name": nic_name,
                                # Capitalized to match NetBox format
                                "mac_address": pnic.mac.upper(),
                                "description": ( # I'm sorry :'(
                                    "{}Mbps Physical Interface".format(
                                        pnic.spec.linkSpeed.speedMb
                                        ) if pnic_up
                                    else "{}Mbps Physical Interface".format(
                                        pnic.validLinkSpecification[0].speedMb
                                        )
                                    ),
                                "enabled": bool(pnic_up),
                                "tags": self.tags
                            })
                    # Virtual Interfaces
                    for vnic in obj.config.network.vnic:
                        nic_name = vnic.device
                        log.debug(
                            "Collecting info for virtual interface '%s'.",
                            nic_name
                            )
                        results["interfaces"].append(
                            {
                                "device": {"name": obj_name},
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
                                        "name": obj_name
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
        elif vc_obj_type == "virtual_machines":
            # Initialize all the NetBox object types we're going to collect
            nb_objects = [
                "virtual_machines", "virtual_interfaces", "ip_addresses",
                ]
            for nb_obj in nb_objects:
                results.setdefault(nb_obj, [])
            container_view = self.create_view(vc_obj_type)
            for obj in container_view.view:
                try:
                    obj_name = obj.name
                    log.info(
                        "Collecting info about vCenter %s '%s' object.",
                        vc_obj_type, obj_name
                        )
                    # Virtual Machines
                    vm_name = obj.name
                    log.debug(
                        "Collecting info for virtual machine '%s'", vm_name
                        )
                    # Platform
                    vm_family = obj.guest.guestFamily
                    platform = None
                    if vm_family is not None:
                        if "linux" in vm_family:
                            platform = {"name": "Linux"}
                        elif "windows" in vm_family:
                            platform = {"name": "Windows"}
                    results["virtual_machines"].append(
                        {
                            "name": vm_name,
                            "status": 1 if obj.runtime.powerState == "poweredOn"
                                      else 0,
                            "cluster": {"name": obj.runtime.host.parent.name},
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
                                    "virtual_machine": {"name": obj.name},
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
                                                    "name": obj_name
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
        else:
            raise ValueError(
                "vCenter object type {} is not valid.".format(vc_obj_type)
                )
        container_view.Destroy()
        log.debug(
            "Collected %s vCenter %s object%s.", len(results),
            vc_obj_type[:-1],
            "s" if len(results) != 1 else "", # Grammar matters :)
            )
        return results

class NetBoxHandler:
    """Handles NetBox connection state and object sync operations"""
    def __init__(self, vc_host, vc_port):
        self.header = {"Authorization": "Token {}".format(settings.NB_API_KEY)}
        self.nb_api_url = "http{}://{}{}/api/".format(
            ("s" if not settings.NB_DISABLE_TLS else ""), settings.NB_FQDN,
            (":{}".format(settings.NB_PORT) if settings.NB_PORT != 443 else "")
            )
        self.nb_session = None
        # Object type relationships when working in the API and browsing the
        # object data structures
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
        # Replace periods with underscores otherwise NetBox cannot search it
        self.vc_tag = vc_host.split(".")[0]
        self.vc = vCenterHandler(vc_host=vc_host, vc_port=vc_port)

    def request(self, req_type, nb_obj_type, data=None, query=None, nb_id=None):
        """HTTP requests and exception handler for NetBox"""
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
        log.debug("Sending %s to %s", req_type.upper(), url)
        req = getattr(self.nb_session, req_type)(url, json=data, timeout=10)
        # Parse status
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
                    "NetBox %s status reason: %s", req.status_code, req.json()
                    )
            elif req_type == "put":
                log.warning(
                    "NetBox failed to modify %s object with status %s. The "
                    "data sent may not be acceptable.", nb_obj_type,
                    req.status_code
                    )
                log.debug(
                    "NetBox %s status reason: %s", req.status_code, req.json()
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
                    req_type.upper(), req.status_code, data, req.json()
                    )
                )
        return result

    def obj_exists(self, nb_obj_type, vc_data):
        """Checks if a NetBox object exists and has matching key value pairs.
        If not, the record wil be created or updated."""
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
            if compare_dicts(
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
                if vc_data["tags"]:
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

    def sync_objects(self, vc_obj_type):
        """Collects objects from vCenter and syncs them to NetBox.
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
        """Collects the current objects from NetBox then compares them to the
        latest vCenter objects.
        If there are objects that do not match they go through a pruning
        process.

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
                query="?tag={}".format(self.vc_tag)
                )["results"]
            # Certain NetBox object types overlap between vCenter object types
            # When pruning, we must differentiate so as not to compare against
            # the wrong objects
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
            elif vc_obj_type == "virtual_machines" and \
                    nb_obj_type == "interfaces":
                nb_objects = [
                    obj for obj in nb_objects
                    if obj["virtual_machine"] is not None
                    ]
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
                modified_date = date(
                    int(orphan["last_updated"][:4]), # Year
                    int(orphan["last_updated"][5:7]), # Month
                    int(orphan["last_updated"][8:10]) # Day
                    )
                # Calculated timedelta then converts it to the days integer
                days_orphaned = (current_date - modified_date).days
                if days_orphaned >= settings.NB_PRUNE_DELAY_DAYS:
                    log.info(
                        "The %s '%s' object has exceeded the %s day max for "
                        "orphaned objects. Sending it for deletion.",
                        nb_obj_type, orphan[query_key],
                        settings.NB_PRUNE_DELAY_DAYS
                        )
                    self.request(
                        req_type="delete", nb_obj_type=nb_obj_type,
                        nb_id=orphan["id"],
                        )
                else:
                    log.info(
                        "The %s '%s' object has been orphaned for %s of %s max "
                        "days. Proceeding to next object.",
                        nb_obj_type, orphan[query_key], days_orphaned,
                        settings.NB_PRUNE_DELAY_DAYS
                        )

    def search_prefix(self, ip_addr):
        """Searches for the parent prefix of any supplied IP address.
        Returns dictionary of VRF and tenant values."""
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
        """Validates that all prerequisite objects exist in NetBox"""
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
                {"name": self.vc_tag, "slug": self.vc_tag.lower()}
                ]
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
        """Searches NetBox for all synced objects and then removes them.
        This is intended to be used in the case you wish to start fresh or stop
        using the script."""
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
                "vcenter" if nb_obj_type == "sites" else self.vc_tag
                )
            nb_objects = self.request(
                req_type="get", nb_obj_type=nb_obj_type,
                query=query
                )["results"]
            query_key = self.obj_map[nb_obj_type]["key"]
            log.info(
                "Deleting %s NetBox %s objects.", len(nb_objects), nb_obj_type
                )
            for obj in nb_objects:
                # NetBox virtual interfaces do not currently support filtering
                # by tags. Therefore we accidentally collect all virtual
                # virtual interfaces in our query so we need to make suer we
                # only delete the relevant ones by checking tags
                if nb_obj_type == "virtual_interfaces" \
                and self.vc_tag not in obj["tags"]:
                    log.debug(
                        "NetBox %s '%s' object does not contain '%s' tag. "
                        "Skipping deletion.", nb_obj_type, obj[query_key],
                        self.vc_tag
                    )
                    continue
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
