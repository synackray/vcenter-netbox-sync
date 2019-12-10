#!/usr/bin/env python3
"""Exports vCenter objects and imports them into Netbox via Python3"""

import atexit
from socket import gaierror
import requests
from pyVim.connect import SmartConnectNoSSL, Disconnect
from pyVmomi import vim
import settings
from logger import log


def main():
    """Main function to run if script is called directly"""
    nb = NetBoxHandler()
    nb.verify_dependencies()
    nb.sync_objects(vc_obj_type="datacenters", nb_obj_type="cluster_groups")
    nb.sync_objects(
        vc_obj_type="clusters", nb_obj_type="clusters", compare=True
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
        """Collects all objects of a type from vCenter"""
        results = {}
        log.info("Collecting vCenter %s objects.", vc_obj_type[:-1])
        if vc_obj_type == "datacenters":
            # Initalize keys expected to be returned
            results["cluster_groups"] = []
            container_view = self.create_view("datacenters")
            for obj in container_view.view:
                results["cluster_groups"].append(
                    {
                        "name": obj.name, "slug": obj.name.lower()
                    })
        elif vc_obj_type == "clusters":
            # Initalize keys expected to be returned
            results["clusters"] = []
            container_view = self.create_view("clusters")
            for obj in container_view.view:
                results["clusters"].append(
                    {
                        "name": obj.name,
                        "type": {"name": "VMware ESXi"},
                        "group": {"name": obj.parent.parent.name},
                        "tags": ["Synced", "vCenter"]
                    })
        elif vc_obj_type == "hosts":
            pass
        elif vc_obj_type == "virtual_machines":
            pass
        else:
            raise ValueError(
                "vCenter object type {} is not valid.".format(vc_obj_type)
                )
        container_view.Destroy()
        log.debug(
            "Collected %s vCenter %s object%s.", len(results),
            vc_obj_type[:-1],
            "s" if len(results) == 1 else "", # Grammar matters
            )
        return results


    def get_vms(self):
        """Collect all Virtual Machines from vCenter"""
        log.info("Collecting vCenter virtual machine objects.")
        container_view = self.create_view("virtual_machines")
        vms = [vm for vm in container_view.view]
        log.debug(
            "%s VMs. The first VM is '%s'.", len(vms),
            vms[0].name
            )
        container_view.Destroy()

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

    def request(self, req_type, nb_obj_type, data=None, query=None, tag=None,
                nb_id=None):
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
            "?name={}".format(query) if query else "",
            "?tag={}".format(tag) if tag else "",
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
            # NetBox returns 50 results by default, this ensures all results
            # are bundled together
            while req.json()["next"] != None:
                url = req.json()["next"]
                log.debug(
                    "NetBox returned more than 50 objects. Sending %s to %s "
                    "for additional objects.", req_type.upper(), url
                    )
                req = getattr(self.nb_session, req_type)(url, timeout=10)
                result["results"] += req.json()["results"]
        elif req.status_code in [201, 204]:
            log.info(
                "NetBox successfully %s %s object.",
                 "created" if req.status_code == 201 else "deleted",
                data["name"],
                nb_obj_type
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
                        "%s request received %s status with body '%s'.",
                        req_type.upper(), req.status_code, data
                        )
                    )
            log.debug("Unaccepted request data: %s", data)
        else:
            raise SystemExit(
                log.critical(
                    "Well this in unexpected. Please report this. "
                    "%s request received %s status with body '%s'.",
                    req_type.upper(), req.status_code, data
                    )
                )
        return result

    def obj_exists(self, nb_obj_type, data):
        """Checks if a NetBox object exists and has matching key value pairs.
        If not, the record wil be created or updated."""
        req = self.request(
            req_type="get", nb_obj_type=nb_obj_type,
            query=data["name"]
            )
        # A single matching object is found so we compare its values to the new
        # object
        if req["count"] == 1:
            log.debug(
                "NetBox %s object '%s' already exists. Comparing values.",
                nb_obj_type,
                data["name"]
                )
            for key in data:
                new_value = req["results"][0][key]
                # For NetBox relational objects, NetBox returns nested
                # dictionaries; we parse them using list comprehension and
                # verify the nested key value pairs match
                if isinstance(data[key], dict):
                    nested_match = all([
                        data[key][sub_key] == new_value[sub_key]
                        for sub_key in data[key]
                        ])
                # Parse values
                if data[key] == new_value or nested_match:
                    log.debug("New and old '%s' values match. Moving on.", key)
                else:
                    log.info(
                        "New and old object values do not match. Updating "
                        "NetBox with the latest object data."
                        )
                    log.debug(
                        "Old %s value is '%s' and new value is '%s'.",
                        key, data[key], new_value
                        )
                    self.request(
                        req_type="put", nb_obj_type=nb_obj_type,
                        nb_id=req["results"][0]["id"],
                        data=data
                        )
                    break
        else:
            log.info(
                "Object '%s' in %s not found.", data["name"],
                nb_obj_type
                )
            self.request(req_type="post", nb_obj_type=nb_obj_type, data=data)

    def sync_objects(self, vc_obj_type, nb_obj_type, compare=False):
        """Collects objects from vCenter and syncs them to NetBox.
        Some object types do not support tags so they will be a one-way sync
        meaning orphaned objects will not be removed from NetBox.
        """
        log.info(
            "Initiated sync of vCenter %s objects to NetBox.", vc_obj_type[:-1]
            )
        vc_objects = self.vc.get_objects(vc_obj_type=vc_obj_type)
        # For each object record for each NetBox object type, pass it to NB
        for nb_obj_type in vc_objects:
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
            # When True collect all objects of type from from NetBox, compares
            # their names to the vCenter objects and go through a
            # pruning process if they're orphaned
            if compare:
                # Collect all NetBox objects of type with vCenter tag
                nb_objects = self.request(
                    req_type="get", nb_obj_type=nb_obj_type, tag="vcenter"
                    )["results"]
                # Determine whether objects match
                temp = self.compare_objects(nb_objects, vc_objects)

    def compare_objects(self, nb_objects, vc_objects):
        """Compares current objects from NetBox to vCenter collected objects.
        If there are objects that do not match they are returned in a list."""
        log.info("Comparing vCenter objects to existing NetBox objects.")
        # For every object type collected from vCenter
        for nb_obj_type in vc_objects:
            # Compare the objects of each type
            for obj in vc_objects[nb_obj_type]:
                # Build lookup of obj name key to nb_objects.
                log.debug(obj)
                import pdb;pdb.set_trace()

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
                ]
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
