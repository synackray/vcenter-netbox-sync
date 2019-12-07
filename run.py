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
    vc.get_hosts()

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
                "Successfully authenticated to vCenter instance '%s'",
                settings.VC_HOST
                )
        except (gaierror, vim.fault.InvalidLogin) as err:
            sysexit(
                log.critical(
                    "Unable to connect to vCenter instance '%s' on port %s. "
                    "Reason: %s",
                    settings.VC_HOST, settings.VC_PORT, err
                ))

    def get_hosts(self):
        """Collect all hosts from vCenter"""
        # Ensure an active vCenter session exists
        if not self.vc_content:
            self.authenticate()
        host_view = self.vc_content.viewManager.CreateContainerView(
            self.vc_content.rootFolder,
            [vim.HostSystem],
            True
            )
        obj = [host for host in host_view.view]
        host_view.Destroy()
        return obj


if __name__ == "__main__":
    main()
