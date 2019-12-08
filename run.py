#!/usr/bin/env python3
"""Exports vCenter objects and imports them into Netbox via Python3"""

import atexit
from socket import gaierror
from sys import exit as sysexit
from pyVim.connect import SmartConnectNoSSL, Disconnect
from pyVmomi import vim
import settings
from logger import log

# Export from vCenter

def main():
    """Main function to run if script is called directly"""
    vc = vCenterHandler()
    vc.view_explorer()

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
            sysexit(
                log.critical(
                    "Unable to connect to vCenter instance '%s' on port %s. "
                    "Reason: %s",
                    settings.VC_HOST, settings.VC_PORT, err
                ))

    def create_view(self, obj_type):
        """Create a view scoped to the vCenter object type desired.
        This should be called by gets for vCenter object types.
        """
        # Mapping of object type keywords to view types
        obj_types = {
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
            [obj_types[obj_type]], # Object types to look for
            True # Should we recurively look into view
            )

    def get_datacenters(self):
        """Collect all datacenters from vCenter"""
        log.info("Collecting vCenter datacenter objects.")
        container_view = self.create_view("datacenters")
        datacenters = [dc.name for dc in container_view.view]
        log.debug(
            "%s datacenters were collected. The first datacenter is '%s'.",
            len(datacenters), datacenters[0]
            )
        container_view.Destroy()
        return datacenters

    def get_hosts(self):
        """Collect all hosts from vCenter"""
        log.info("Collecting vCenter host objects.")
        container_view = self.create_view("hosts")
        hosts = [host for host in container_view.view]
        log.debug(
            "%s hosts were collected. The first host is '%s'.", len(hosts),
            hosts[0].name
            )
        container_view.Destroy()
        return hosts

    def get_vms(self):
        """Collect all Virtual Machines from vCenter"""
        log.info("Collecting vCenter virtual machine objects.")
        container_view = self.create_view("virtual_machines")
        vms = [vm for vm in container_view.view]
        log.debug(
            "%s VMs were collected. The first VM is '%s'.", len(vms),
            vms[0].name
            )
        container_view.Destroy()

    def view_explorer(self):
        """Interactive view explorer for exploring models"""
        log.warning("View Explorer mode activated! Use with caution!")
        obj_type = input("Object Type to Explore: ")
        container_view = self.create_view(obj_type)
        log.debug("Created view for object type '%s'.", obj_type)
        objects = [obj for obj in container_view.view]
        log.debug(
            "Collected %s objects of object type %s.", len(objects), obj_type
            )
        log.warning(
            "Entering interactive mode. Current data stored in 'objects' "
            "variable."
            )
        import pdb
        pdb.set_trace()
        container_view.Destroy()

if __name__ == "__main__":
    main()
