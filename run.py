#!/usr/bin/env python3
"""Exports vCenter objects and imports them into Netbox via Python3"""

import atexit
from socket import gaierror
from datetime import date, datetime
import requests
from pyVim.connect import SmartConnectNoSSL, Disconnect
from pyVmomi import vim
import settings
from logger import log


def main():
    """Main function to run if script is called directly"""
    start_time = datetime.now()
    # vc = vCenterHandler()
    # vc.view_explorer()
    nb = NetBoxHandler()
    nb.verify_dependencies()
    # nb.sync_objects(vc_obj_type="datacenters")
    # nb.sync_objects(vc_obj_type="clusters")
    nb.sync_objects(vc_obj_type="hosts")
    # nb.sync_objects(vc_obj_type="virtual_machines")
    log.info(
        "Completed! Total execution time %s.",
        (datetime.now() - start_time)
        )

class vCenterHandler:
    """Handles vCenter connection state and export of objects"""
    def __init__(self):
        self.vc_content = None # Used to hold vCenter session state

    def authenticate(self):
        """Authenticate to vCenter"""
        log.info(
            "Attempting authentication to vCenter instance '%s'.",
            settings.VC_HOST
            )
        try:
            vc_instance = SmartConnectNoSSL(
                host=settings.VC_HOST,
                port=settings.VC_PORT,
                user=settings.VC_USER,
                pwd=settings.VC_PASS,
                )
            atexit.register(Disconnect, vc_instance)
            self.vc_content = vc_instance.RetrieveContent()
            log.info(
                "Successfully authenticated to vCenter instance '%s'.",
                settings.VC_HOST
                )
        except (gaierror, vim.fault.InvalidLogin) as err:
            raise SystemExit(
                log.critical(
                    "Unable to connect to vCenter instance '%s' on port %s. "
                    "Reason: %s",
                    settings.VC_HOST, settings.VC_PORT, err
                ))

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
        if not self.vc_content:
            log.info("No existing vCenter session found.")
            self.authenticate()
        return self.vc_content.viewManager.CreateContainerView(
            self.vc_content.rootFolder, # View starting point
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
                        "name": obj_name, "slug": obj_name.lower()
                    })
        elif vc_obj_type == "clusters":
            # Initalize keys expected to be returned
            results.setdefault("clusters", [])
            container_view = self.create_view(vc_obj_type)
            for obj in container_view.view:
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
                        "tags": ["Synced", "vCenter"]
                    })
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
                        "Collecting info to create NetBox manufacturers object."
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
                        "Collecting info to create NetBox device_types object."
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
                            "tags": ["Synced", "vCenter"]
                        })
                log.debug("Collecting info to create NetBox devices object.")
                results["devices"].append(
                    {
                        "name": obj_name,
                        "device_type": {"model": obj_model},
                        "device_role": {"name": "Server"},
                        "platform": {"name": "VMware ESXi"},
                        "serial": [ # Scan throw identifiers to find S/N
                            identifier.identifierValue for identifier
                            in obj.summary.hardware.otherIdentifyingInfo
                            if identifier.identifierType.key == \
                            "EnclosureSerialNumberTag"
                            ][0],
                        "asset_tag": [
                            (identifier.identifierValue
                             if identifier.identifierValue != "Default string"
                             else ""
                            ) for identifier in
                            obj.summary.hardware.otherIdentifyingInfo
                            if identifier.identifierType.key == "AssetTag"
                            ][0],
                        "cluster": obj.parent.name,
                        "status": ( # 0 = Offline / 1 = Active
                            1 if obj.summary.runtime.connectionState == \
                            "connected"
                            else 0
                            ),
                        "tags": ["Synced", "vCenter"]
                    })
                # Iterable object types
                # Physical Interfaces
                log.debug("Collecting info to create NetBox interfaces object.")
                for pnic in obj.config.network.pnic:
                    log.debug(
                        "Collecting info for physical interface '%s'.", obj_name
                        )
                    pnic_up = pnic.spec.linkSpeed
                    results["interfaces"].append(
                        {
                            "device": obj_name,
                            # Interface speed is placed in the description as it
                            # is irrelevant to making connections and an error
                            # prone mapping process
                            "type": {"label": "Other"},
                            "name": pnic.device,
                            "mac_address": pnic.mac,
                            "description": ( # I'm sorry :'(
                                "{}Mbps Physical Interface".format(
                                    pnic.spec.linkSpeed.speedMb
                                    ) if pnic_up
                                else "{}Mbps Physical Interface".format(
                                    pnic.validLinkSpecification[0].speedMb
                                    )
                                ),
                            "enabled": bool(pnic_up),
                            "tags": ["Synced", "vCenter"]
                        })
                # Virtual Interfaces
                for vnic in obj.config.network.vnic:
                    nic_name = vnic.device
                    log.debug(
                        "Collecting info for virtual interface '%s'.", obj_name
                        )
                    results["interfaces"].append(
                        {
                            "device": obj_name,
                            "type": {"label": "Virtual"},
                            "name": nic_name,
                            "mac_address": vnic.spec.mac,
                            "mtu": vnic.spec.mtu,
                            "tags": ["Synced", "vCenter"]
                        })
                    # IP Addresses
                    ip_addr = vnic.spec.ip.ipAddress
                    log.debug(
                        "Collecting info for IP Address '%s'.",
                        ip_addr
                        )
                    results["interfaces"].append(
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
                            "tags": ["Synced", "vCenter"]
                        })
        elif vc_obj_type == "virtual_machines":
            # Initialize all the NetBox object types we're going to collect
            nb_objects = [
                "virtual_machines", "interfaces", "ip_addresses"]
            for nb_obj in nb_objects:
                results.setdefault(nb_obj, [])
            container_view = self.create_view(vc_obj_type)
            for obj in container_view.view:
                obj_name = obj.name
                log.info(
                    "Collecting info about vCenter %s '%s' object.",
                    vc_obj_type, obj_name
                    )
                # Virtual Machines
                vm_name = obj.name
                log.debug("Collecting info for virtual machine '%s'", vm_name)
                vm_family = obj.guest.guestFamily
                results["virtual_machines"].append(
                    {
                        "name": vm_name,
                        "status": 1 if obj.runtime.powerState == "poweredOn"
                                  else 0,
                        "cluster": {"name": obj[0].runtime.host.parent.name},
                        "role": {"name": "Server"},
                        # "tenant": {"name": ""},
                        "platform": {
                            "name": "Linux" if "linux" in vm_family
                                    else "Windows" if "windows" in vm_family
                                    else None}
                                    if vm_family else {"name": None},
                        "memory": obj.config.hardware.memoryMB,
                        "disk": sum([
                            comp.capacityInKB for comp in obj.config.hardware.device
                            if isinstance(comp, vim.vm.device.VirtualDisk)
                            ]) / 1024 / 1024, # Kilobytes to Gigabytes
                        "vcpus": obj.config.hardware.numCPU,
                        "tags": ["Synced", "vCenter"]
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
                        results["interfaces"].append(
                            {
                                "device": obj.name,
                                "type": {"label": "Virtual"},
                                "name": nic_name,
                                "mac_address": nic.macAddress,
                                "connection_status": nic.connected,
                                "tags": ["Synced", "vCenter"]
                            })
                        # IP Addresses
                        log.debug(
                            "Collecting info for IP Address '%s'.",
                            ip_addr
                            )
                        results["ip_addresses"].append(
                            {
                            })
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

    def view_explorer(self):
        """Interactive view explorer for exploring models"""
        log.warning("View Explorer mode activated! Use with caution!")
        vc_obj_type = input("Object Type to Explore: ")
        container_view = self.create_view(vc_obj_type)
        log.debug("Created view for object type '%s'.", vc_obj_type)
        objects = [obj for obj in container_view.view]
        log.debug(
            "Collected %s objects of object type %s.", len(objects), vc_obj_type
            )
        log.warning(
            "Entering interactive mode. Current data stored in 'objects' "
            "variable."
            )
        import pdb
        pdb.set_trace()
        container_view.Destroy()

class NetBoxHandler:
    """Handles NetBox connection state and object sync operations"""
    def __init__(self):
        self.header = {"Authorization": "Token {}".format(settings.NB_API_KEY)}
        self.nb_api_url = "http{}://{}{}/api/".format(
            ("s" if not settings.NB_DISABLE_TLS else ""), settings.NB_FQDN,
            (":{}".format(settings.NB_PORT) if settings.NB_PORT != 443 else "")
            )
        self.nb_session = None
        self.vc = vCenterHandler()

    def request(self, req_type, nb_obj_type, data=None, query=None, nb_id=None):
        """HTTP requests and exception handler for NetBox"""
        # Object family relationships in the API used for url crafting
        obj_families = {
            "cluster_groups": "virtualization",
            "cluster_types": "virtualization",
            "clusters": "virtualization",
            "manufacturers": "dcim",
            "platforms": "dcim",
            "device_types": "dcim",
            "devices": "dcim",
            "interfaces": "dcim",
            "ip_addresses": "ipam",
            "virtual_machines": "virtualization",
            "tags": "extras",
            }
        # If an existing session is not already found then create it
        # The goal here is session re-use without TCP handshake on every request
        if not self.nb_session:
            self.nb_session = requests.Session()
            self.nb_session.headers.update(self.header)
        result = None
        # Generate URL
        url = "{}{}/{}/{}{}".format(
            self.nb_api_url,
            obj_families[nb_obj_type],
            nb_obj_type.replace("_", "-"), # Converts to url format
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
                "NetBox successfully %s %s '%s' object.",
                "created" if req.status_code == 201 else "deleted",
                nb_obj_type[:-1],
                data["model"] if nb_obj_type == "device_types" else data["name"]
                )
        elif req.status_code == 400:
            if req_type == "post":
                log.warning(
                    "NetBox failed to create %s object. A duplicate record may "
                    "exist or the data sent is not acceptable.", nb_obj_type
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

    def obj_exists(self, nb_obj_type, data):
        """Checks if a NetBox object exists and has matching key value pairs.
        If not, the record wil be created or updated."""
        # NetBox Device Types objects do not have names to query; we catch
        # and use the model instead
        query_key = "model" if nb_obj_type == "device_types" else "name"
        req = self.request(
            req_type="get", nb_obj_type=nb_obj_type,
            query="?{}={}".format(query_key, data[query_key])
            )
        # A single matching object is found so we compare its values to the new
        # object
        if req["count"] == 1:
            log.debug(
                "NetBox %s object '%s' already exists. Comparing values.",
                nb_obj_type, data[query_key]
                )
            for key in data:
                old_value = req["results"][0][key]
                # For NetBox relational objects, NetBox returns nested
                # dictionaries; we parse them using list comprehension and
                # verify the nested key value pairs match
                objects_matched = True
                if isinstance(data[key], dict):
                    objects_matched = all([
                        data[key][sub_key] == old_value[sub_key]
                        for sub_key in data[key]
                        ])
                # Tag orders are not guaranteed so we must parse them
                # individually
                if key == "tags":
                    # Tags are not matching, cleans up 'Orphaned' if it's
                    # seen again on vCenter
                    if len(data[key]) != len(old_value):
                        objects_matched = False
                    for tag in data[key]:
                        if tag not in old_value:
                            objects_matched = False
                # Handling results
                if data[key] == old_value and objects_matched:
                    log.debug("New and old '%s' values match. Moving on.", key)
                if not objects_matched:
                    log.info(
                        "New and old object values do not match. Updating "
                        "NetBox with the latest object data."
                        )
                    log.debug(
                        "Old %s value is '%s' and new value is '%s'.",
                        key, old_value, data[key]
                        )
                    self.request(
                        req_type="put", nb_obj_type=nb_obj_type,
                        nb_id=req["results"][0]["id"],
                        data=data
                        )
                    break
        else:
            log.info(
                "Object '%s' in %s not found.",
                data[query_key],
                nb_obj_type
                )
            self.request(req_type="post", nb_obj_type=nb_obj_type, data=data)

    def sync_objects(self, vc_obj_type):
        """Collects objects from vCenter and syncs them to NetBox.
        Some object types do not support tags so they will be a one-way sync
        meaning orphaned objects will not be removed from NetBox.
        """
        # NetBox objects which support pruning
        prunable_obj_types = [
            "clusters", "device_types", "devices", "virtual_machines", "interfaces", "ip_addresses"
            ]
        # Collect data from vCenter
        log.info(
            "Initiated sync of vCenter %s objects to NetBox.",
            vc_obj_type[:-1]
            )
        vc_objects = self.vc.get_objects(vc_obj_type=vc_obj_type)
        # Determine each NetBox object type collected from vCenter
        nb_obj_types = [obj for obj in vc_objects]
        for nb_obj_type in nb_obj_types:
            log.info(
                "Starting sync of %s vCenter %s object%s to NetBox %s "
                "object%s.",
                len(vc_objects[nb_obj_type]),
                vc_obj_type[:-1],
                "s" if len(vc_objects[nb_obj_type]) != 1 else "",
                nb_obj_type[:-1],
                "s" if len(vc_objects[nb_obj_type]) != 1 else "",
                )
            for obj in vc_objects[nb_obj_type]:
                self.obj_exists(nb_obj_type=nb_obj_type, data=obj)
            log.info(
                "Finished sync of %s vCenter %s object%s to NetBox %s "
                "object%s.",
                len(vc_objects[nb_obj_type]),
                vc_obj_type[:-1],
                "s" if len(vc_objects[nb_obj_type]) != 1 else "",
                nb_obj_type[:-1],
                "s" if len(vc_objects[nb_obj_type]) != 1 else "",
                )
            # If pruning is globally enabled and the objects are prunable
            if settings.NB_PRUNE_ENABLED and nb_obj_type in prunable_obj_types:
                self.prune_objects(nb_obj_type, vc_objects)

    def prune_objects(self, nb_obj_type, vc_objects):
        """Collects the current objects from NetBox then compares them to the
        latest vCenter objects.
        If there are objects that do not match they go through a pruning
        process."""
        nb_objects = self.request(
            req_type="get", nb_obj_type=nb_obj_type, query="?tag=vcenter"
            )["results"]
        log.info(
            "Comparing existing NetBox %s objects to current vCenter objects.",
            nb_obj_type[:-1]
            )
        # From the vCenter objects provided collect only the names/models of
        # each object from the current type we're comparing against
        query_key = "model" if nb_obj_type == "device_types" else "name"
        vc_obj_values = [obj[query_key] for obj in vc_objects[nb_obj_type]]
        orphans = [
            obj for obj in nb_objects if obj[query_key] not in vc_obj_values
            ]
        log.info(
            "Comparsion completed. %s object%s were unmatched.", len(orphans),
            "s" if len(orphans) != 1 else ""
            )
        log.debug("The following objects did not match: %s", orphans)
        # Pruned items are checked against the prune timer
        # All pruned items are first tagged so it is clear why they were
        # deleted, and then those items which are greater than the max age
        # will be deleted permanently
        for orphan in orphans:
            log.info(
                "Processing %s '%s' object", nb_obj_type[:-1], orphan[query_key]
                )
            if "Orphaned" not in orphan["tags"]:
                log.info(
                    "No tag found. Adding 'Orphaned' tag to %s '%s' object",
                    nb_obj_type[:-1], orphan[query_key]
                    )
                self.request(
                    req_type="patch", nb_obj_type=nb_obj_type,
                    nb_id=orphan["id"],
                    data={"tags": ["Synced", "vCenter", "Orphaned"]}
                    )
            # Check if the orphan has gone past the max prune timer and needs
            # to be deleted
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
                    nb_obj_type[:-1], orphan[query_key],
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
                    nb_obj_type[:-1], orphan[query_key], days_orphaned,
                    settings.NB_PRUNE_DELAY_DAYS
                    )

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
            "tags": [{
                "name": "Orphaned",
                "slug": "orphaned",
                "color": "607d8b",
                "comments": "This applies to objects that have become "
                            "orphaned. The source system which has previously "
                            "provided the object no longer states it "
                            "exists.{}".format(
                                " An object with the 'Orphaned' tag will "
                                "remain in this state until it ages out and is "
                                "automatically removed."
                                ) if settings.NB_PRUNE_ENABLED else ""

                }]
            }
        # For each dependency of each type verify object exists
        log.info("Verifying all prerequisite objects exist in NetBox.")
        for dep_type in dependencies:
            log.debug(
                "Checking NetBox has necessary %s objects.", dep_type[:-1]
                )
            for dep in dependencies[dep_type]:
                self.obj_exists(nb_obj_type=dep_type, data=dep)
        log.info("Finished verifying prerequisites.")


if __name__ == "__main__":
    main()
