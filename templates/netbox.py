#!/usr/bin/env python3
"""A collection of NetBox object templates"""


def remove_empty_fields(obj):
    """
    Removes empty fields from NetBox objects.

    This ensures NetBox objects do not return invalid None values in fields.
    :param obj: A NetBox formatted object
    :type obj: dict
    """
    return {k: v for k, v in obj.items() if v is not None}


def format_slug(text, max_len=50):
    """
    Format string to comply to NetBox slug acceptable pattern and max length.

    :param text: Text to be formatted into an acceptable slug
    :type text: str
    :return: Slug of allowed characters [-a-zA-Z0-9_] with max length of 50
    :rtype: str
    """
    allowed_chars = (
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" # Alphabet
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
    return truncate(text, max_len).lower()


def truncate(text="", max_len=50):
    """Ensure a string complies to the maximum length specified."""
    return text if len(text) < max_len else text[:max_len]


class Templates:
    """NetBox object templates"""
    # Maps NetBox object types friendly name key, api path, and prunability
    obj_type_map = {
        "cluster_groups": {
            "api_app": "virtualization",
            "api_model": "cluster-groups",
            "key": "name",
            "prune": False,
            "sync_pref": 3
            },
        "cluster_types": {
            "api_app": "virtualization",
            "api_model": "cluster-types",
            "key": "name",
            "prune": False,
            "sync_pref": 4
            },
        "clusters": {
            "api_app": "virtualization",
            "api_model": "clusters",
            "key": "name",
            "prune": True,
            "prune_pref": 2,
            "sync_pref": 5
            },
        "device_roles": {
            "api_app": "dcim",
            "api_model": "device-roles",
            "key": "name",
            "prune": False,
            "sync_pref": 6
            },
        "device_types": {
            "api_app": "dcim",
            "api_model": "device-types",
            "key": "model",
            "prune": True,
            "prune_pref": 3,
            "sync_pref": 7
            },
        "devices": {
            "api_app": "dcim",
            "api_model": "devices",
            "key": "name",
            "prune": True,
            "prune_pref": 4,
            "sync_pref": 10
            },
        "interfaces": {
            "api_app": "dcim",
            "api_model": "interfaces",
            "key": "name",
            "prune": True,
            "prune_pref": 5,
            "sync_pref": 12
            },
        "ip_addresses": {
            "api_app": "ipam",
            "api_model": "ip-addresses",
            "key": "address",
            "prune": True,
            "prune_pref": 8,
            "sync_pref": 16
            },
        "manufacturers": {
            "api_app": "dcim",
            "api_model": "manufacturers",
            "key": "name",
            "prune": False,
            "sync_pref": 7
            },
        "platforms": {
            "api_app": "dcim",
            "api_model": "platforms",
            "key": "name",
            "prune": False,
            "sync_pref": 8
            },
        "prefixes": {
            "api_app": "ipam",
            "api_model": "prefixes",
            "key": "prefix",
            "prune": False,
            "sync_pref": 15
            },
        "sites": {
            "api_app": "dcim",
            "api_model": "sites",
            "key": "name",
            "prune": True,
            "prune_pref": 1,
            "sync_pref": 1
            },
        "tags": {
            "api_app": "extras",
            "api_model": "tags",
            "key": "name",
            "prune": False,
            "sync_pref": 2
            },
        "tenants": {
            "api_app": "tenancy",
            "api_model": "tenants",
            "key": "name",
            "prune": True,
            "prune_pref": 1,
            "sync_pref": 9
            },
        "virtual_machines": {
            "api_app": "virtualization",
            "api_model": "virtual-machines",
            "key": "name",
            "prune": True,
            "prune_pref": 6,
            "sync_pref": 13
            },
        "virtual_interfaces": {
            "api_app": "virtualization",
            "api_model": "interfaces",
            "key": "name",
            "prune": True,
            "prune_pref": 7,
            "sync_pref": 14
            },
        "vlans": {
            "api_app": "ipam",
            "api_model": "vlans",
            "key": "name",
            "prune": True,
            "prune_pref": 8,
            "sync_pref": 11
            }
        }

    def __init__(self, api_version):
        """
        Required parameters for the NetBox class

        :param api_version: NetBox API version objects must be formatted to
        :type api_version: float
        """
        self.api_version = api_version

    def cluster(self, name, ctype, group=None, tags=None):
        """
        Template for NetBox clusters at /virtualization/clusters/

        :param name: Name of the cluster group
        :type name: str
        :param ctype: Name of NetBox cluster type object
        :type ctype: str
        :param group: Name of NetBox cluster group object
        :type group: str, optional
        :param tags: Tags to apply to the object
        :type tags: list, optional
        """
        obj = {
            "name": truncate(name, max_len=100),
            "type": {"name": ctype},
            "group": {"name": truncate(group, max_len=50)} if group else None,
            "tags": tags,
            }
        return remove_empty_fields(obj)

    def cluster_group(self, name, slug=None):
        """
        Template for NetBox cluster groups at /virtualization/cluster-groups/

        :param name: Name of the cluster group
        :type name: str
        :param slug: Unique slug for cluster group.
        :type slug: str, optional
        """
        obj = {
            "name": truncate(name, max_len=50),
            "slug": slug if slug else format_slug(name)
            }
        return remove_empty_fields(obj)

    def device(self, name, device_role, device_type, platform=None, site=None,
               serial=None, asset_tag=None, cluster=None, status=None,
               tags=None):
        """
        Template for NetBox devices at /dcim/devices/

        :param name: Hostname of the device
        :type name: str
        :param device_role: Name of device role
        :type device_role: str
        :param device_type: Model name of device type
        :type device_type: str
        :param platform: Platform running on the device
        :type platform: str, optional
        :param site: Site where the device resides
        :type site: str, optional
        :param serial: Serial number of the device
        :type serial: str, optional
        :param asset_tag: Asset tag of the device
        :type asset_tag: str, optional
        :param cluster: Cluster the device belongs to
        :type cluster: str, optional
        :param status: NetBox IP address status in NB API v2.6 format
        :type status: int
        :param tags: Tags to apply to the object
        :type tags: list, optional
        """
        obj = {
            "name": name,
            "device_role": {"name": device_role} if device_role else None,
            "device_type": {"model": device_type} if device_type else None,
            "platform": {"name": platform} if platform else None,
            "site": {"name": site} if site else None,
            "serial": truncate(serial, max_len=50) if serial else None,
            "asset_tag": truncate(asset_tag, max_len=50) if asset_tag else None,
            "cluster": {
                "name": truncate(cluster, max_len=100)
                } if cluster else None,
            "status": self._version_dependent(
                nb_obj_type="devices",
                key="status",
                value=status
                ),
            "tags": tags,
            }
        return remove_empty_fields(obj)

    def device_interface(self, device, name, itype=None, enabled=None, mtu=None,
                         mac_address=None, mgmt_only=None, description=None,
                         cable=None, mode=None, untagged_vlan=None,
                         tagged_vlans=None, tags=None):
        """
        Template for NetBox device interfaces at /dcim/interfaces/

        :param device: Name of parent device the interface belongs to
        :type device: str
        :param name: Name of the physical interface
        :type name: str
        :param itype: Type of interface `0` if Virtual else `32767` for Other
        :type itype: str, optional
        :param enabled: `True` if the interface is up else `False`
        :type enabled: bool,optional
        :param mtu: The configured MTU for the interface
        :type mtu: int,optional
        :param mac_address: The MAC address of the interface
        :type mac_address: str, optional
        :param mgmt_only: `True` if interface is only for out of band else `False`
        :type mgmt_only: bool, optional
        :param description: Description for the interface
        :type description: str, optional
        :param cable: NetBox cable object ID of the interface is attached to
        :type cable: int, optional
        :param mode: `100` if access, `200` if tagged, or `300 if` tagged for all vlans
        :type mode: int, optional
        :param untagged_vlan: NetBox VLAN object id of untagged vlan
        :type untagged_vlan: int, optional
        :param tagged_vlans: List of NetBox VLAN object ids for tagged VLANs
        :type tagged_vlans: str, optional
        :param tags: Tags to apply to the object
        :type tags: list, optional
        """
        obj = {
            "device": {"name": device},
            "name": name,
            "type": self._version_dependent(
                nb_obj_type="interfaces",
                key="type",
                value=itype
                ) if itype else None,
            "enabled": enabled,
            "mtu": mtu,
            "mac_address": mac_address.upper() if mac_address else None,
            "mgmt_only": mgmt_only,
            "description": description,
            "cable": cable,
            "mode": mode,
            "untagged_vlan": untagged_vlan,
            "tagged_vlans": tagged_vlans,
            "tags": tags,
            }
        return remove_empty_fields(obj)

    def device_role(self, name, color=None, slug=None):
        """
        Template for NetBox device roles at /dcim/device-roles/

        :param name: Name of the device role
        :type name: str
        :param slug: Unique slug for the device role
        :type slug: str, optional
        :param color: 6 character hex value of device role color
        :type color: str, optional
        """
        obj = {
            "name": truncate(name, max_len=50),
            "color": color if color else "607d8b",
            "slug": slug if slug else format_slug(name)
            }
        return remove_empty_fields(obj)

    def device_type(self, manufacturer, model, slug=None, part_number=None,
                    tags=None):
        """
        Template for NetBox device types at /dcim/device-types/

        :param manufacturer: Name of NetBox manufacturer object
        :type manufacturer: str
        :param model: Name of NetBox model object
        :type model: str
        :param slug: Unique slug for manufacturer.
        :type slug: str, optional
        :param part_number: Unique partner number for the device
        :type part_number: str, optional
        :param tags: Tags to apply to the object
        :type tags: list, optional
        """
        obj = {
            "manufacturer": {"name": manufacturer},
            "model": truncate(model, max_len=50),
            "slug": slug if slug else format_slug(model),
            "part_number": truncate(
                part_number, max_len=50
                ) if part_number else truncate(model, max_len=50),
            "tags": tags
            }
        return remove_empty_fields(obj)

    def ip_address(self, address, description=None, device=None, dns_name=None,
                   interface=None, status=1, tags=None, tenant=None,
                   virtual_machine=None, vrf=None):
        """
        Template for NetBox IP addresses at /ipam/ip-addresses/

        :param address: IP address
        :type address: str
        :param description: A description of the IP address purpose
        :type description: str, optional
        :param device: The device which the IP and its interface are attached to
        :type device: str, optional
        :param dns_name: FQDN pointed to the IP address
        :type dns_name: str, optional
        :param interface: Name of the parent interface IP is configured on
        :type interface: str, optional
        :param status: `1` if active, `0` if deprecated
        :type status: int
        :param tags: Tags to apply to the object
        :type tags: list, optional
        :param tenant: The tenant the IP address belongs to
        :type tenant: str, optional
        :param virtual_machine: Name of the NetBox VM object the IP is configured on
        :type virtual_machine: str, optional
        :param vrf: Virtual Routing and Forwarding instance for the IP
        :type vrf: str, optional
        """
        # Validate user did not try to provide a parent device and VM
        if bool(device and virtual_machine):
            raise ValueError(
                "Values provided for both parent device and virtual machine "
                "but they are exclusive to each other."
                )
        obj = {
            "address": address,
            "description": description,
            "dns_name": dns_name,
            "status": self._version_dependent(
                nb_obj_type="ip_addresses",
                key="status",
                value=status
                ),
            "tags": tags,
            "tenant": tenant,
            "vrf": vrf
            }
        if interface and bool(device or virtual_machine):
            obj["interface"] = {"name": interface}
            if device:
                obj["interface"] = {
                    **obj["interface"], **{"device": {"name": device}}
                    }
            elif virtual_machine:
                obj["interface"] = {
                    **obj["interface"],
                    **{"virtual_machine": {
                        "name": truncate(virtual_machine, max_len=64)
                        }}
                    }
        return remove_empty_fields(obj)

    def manufacturer(self, name, slug=None):
        """
        Template for NetBox manufacturers at /dcim/manufacturers

        :param name: Name of the manufacturer
        :type name: str
        :param slug: Unique slug for manufacturer.
        :type slug: str, optional
        """
        obj = {
            "name": truncate(name, max_len=50),
            "slug": slug if slug else format_slug(name)
            }
        return remove_empty_fields(obj)

    def platform(self, name, slug=None, manufacturer=None,
                 napalm_driver=None, napalm_args=None):
        """
        Template for NetBox manufacturers at /dcim/manufacturers

        :param name: Name of the platform
        :type name: str
        :param slug: Unique slug for the platform
        :type slug: str, optional
        :param manufacturer: Limit this platform to devices of provided manufacturer
        :type manufacturer: str, optional
        :param napalm_driver: The name of the NAPALM driver to use when interacting with devices
        :type napalm_driver: str
        :param napam_args: Arguments to pass when initiating the NAPALM driver (JSON format)
        :type napalm_args: dict
        """
        obj = {
            "name": truncate(name, max_len=100),
            "slug": slug if slug else format_slug(name, max_len=100),
            "manufacturer": manufacturer,
            "napalm_driver": napalm_driver,
            "napalm_args": napalm_args,
            }
        return remove_empty_fields(obj)

    def _version_dependent(self, nb_obj_type, key, value):
        """
        Formats object values depending on the NetBox API version.

        Prior to NetBox API v2.7 NetBox used integers for multiple choice
        fields. We use the version of NetBox API to determine whether we need
        to return integers or named strings.

        :param nb_obj_type: NetBox object type, must match keys in self.obj_map
        :type nb_obj_type: str
        :param key: The dictionary key to check against
        :type key: str
        :param value: Value to the provided key in NetBox 2.6 or less format
        :return: NetBox API version safe value
        :rtype: str
        """
        obj_map = {
            "circuits": {
                "status": {
                    0: "deprovisioning",
                    1: "active",
                    2: "planned",
                    3: "provisioning",
                    4: "offline",
                    5: "decomissioned"
                }},
            "devices": {
                "status": {
                    0: "offline",
                    1: "active",
                    2: "planned",
                    3: "staged",
                    4: "failed",
                    5: "inventory",
                    6: "decomissioning"
                }},
            "interfaces": {
                "type": {
                    0: "virtual",
                    32767: "other"
                },
                "mode": {
                    100: "access",
                    200: "tagged",
                    300: "tagged-all",
                }},
            "ip_addresses": {
                "role": {
                    10: "loopback",
                    20: "secondary",
                    30: "anycast",
                    40: "vip",
                    41: "vrrp",
                    42: "hsrp",
                    43: "glbp",
                    44: "carp"
                    },
                "status": {
                    1: "active",
                    2: "reserved",
                    3: "deprecated",
                    5: "dhcp"
                    },
                "type": {
                    0: "virtual",
                    32767: "other"
                }},
            "prefixes": {
                "status": {
                    0: "container",
                    1: "active",
                    2: "reserved",
                    3: "deprecated"
                }},
            "sites": {
                "status": {
                    1: "active",
                    2: "planned",
                    4: "retired"
                }},
            "vlans": {
                "status": {
                    1: "active",
                    2: "reserved",
                    3: "deprecated"
                }},
            "virtual_machines": {
                "status": {
                    0: "offline",
                    1: "active",
                    3: "staged"
                    }
            }}
        # isinstance is used as a safety check. If a string is passed we'll
        # assume someone passed a value for API v2.7 and return the result.
        if isinstance(value, int) and self.api_version > 2.6:
            result = obj_map[nb_obj_type][key][value]
        else:
            result = value
        return result

    def virtual_machine(self, name, cluster, status=None, role=None,
                        tenant=None, platform=None, primary_ip4=None,
                        primary_ip6=None, vcpus=None, memory=None, disk=None,
                        comments=None, local_context_data=None, tags=None):
        """
        Template for NetBox virtual machines at /virtualization/virtual-machines/

        :param name: Name of the virtual machine
        :type name: str
        :param cluster: Name of the cluster the virtual machine resides on
        :type cluster: str
        :param status: `0` if offline, `1` if active, `3` if staged
        :type status: int, optional
        :param role: Name of NetBox role object
        :type role: str, optional
        :param tenant: Name of NetBox tenant object
        :type tenant: str, optional
        :param platform: Name of NetBox platform object
        :type platform: str, optional
        :param primary_ip4: NetBox IP address object ID
        :type primary_ip4: int, optional
        :param primary_ip6: NetBox IP address object ID
        :type primary_ip6: int, optional
        :param vcpus: Quantity of virtual CPUs assigned to VM
        :type vcpus: int, optional
        :param memory: Quantity of RAM assigned to VM in MB
        :type memory: int, optional
        :param disk: Quantity of disk space assigned to VM in GB
        :type disk: str, optional
        :param comments: Comments regarding the VM
        :type comments: str, optional
        :param local_context_data: Additional context data regarding the VM
        :type local_context_data: dict, optional
        :param tags: Tags to apply to the object
        :type tags: list, optional
        """
        obj = {
            "name": name,
            "cluster": {"name": cluster},
            "status": self._version_dependent(
                nb_obj_type="virtual_machines",
                key="status",
                value=status
                ),
            "role": {"name": role} if role else None,
            "tenant": {"name": tenant} if tenant else None,
            "platform": platform,
            "primary_ip4": primary_ip4,
            "primary_ip6": primary_ip6,
            "vcpus": vcpus,
            "memory": memory,
            "disk": disk,
            "comments": comments,
            "local_context_data": local_context_data,
            "tags": tags
            }
        return remove_empty_fields(obj)

    def vlan(self, vid, name, site=None, group=None, tenant=None, status=None,
             role=None, description=None, tags=None):
        """
        Template for NetBox VLANs at /ipam/vlans/

        :param vid: VLAN ID, maximum value 4094
        :type vid: int
        :param name: Name of the VLAN, max length 64
        :type name: str
        :param site: Name of site where the VLAN resides
        :type site: str, optional
        :param group: Name of VLAN group the VLAN belongs to
        :type group: str, optional
        :param tenant: Name of tenant the VLAN belongs to
        :type tenant: str, optional
        :param status: `1` if active, `2` if reserved, `3` if deprecated
        :type status: int, optional
        :param role: Name of VLAN role
        :type role: str, optional
        :param description: Description of VLAN, max length 100
        :type description: str, optional
        :param tags: Tags to apply to the object
        :type tags: list, optional
        """
        obj = {
            "vid": vid,
            "name": truncate(name, max_len=64),
            "site": {"name": site} if site else None,
            "group": {"name": group} if group else None,
            "tenant": {"name": tenant} if tenant else None,
            "status": self._version_dependent(
                nb_obj_type="vlans",
                key="status",
                value=status
                ),
            "role": {"name": role} if role else None,
            "description": truncate(description, max_len=100),
            "tags": tags,
            }
        return remove_empty_fields(obj)

    def vm_interface(self, virtual_machine, name, itype=0, enabled=None,
                     mtu=None, mac_address=None, description=None, mode=None,
                     untagged_vlan=None, tagged_vlans=None, tags=None):
        """
        Template for NetBox virtual machine interfaces at /virtualization/interfaces/

        :param virtual_machine: Name of parent virtual machine the interface belongs to
        :type virtual_machine: str
        :param name: Name of the physical interface
        :type name: str
        :param itype: Type of interface `0` if Virtual else `32767` for Other
        :type itype: str, optional
        :param enabled: `True` if the interface is up else `False`
        :type enabled: bool,optional
        :param mtu: The configured MTU for the interface
        :type mtu: int,optional
        :param mac_address: The MAC address of the interface
        :type mac_address: str, optional
        :param description: Description for the interface
        :itype description: str, optional
        :param mode: `100` if access, `200` if tagged, or `300 if` tagged for all vlans
        :itype mode: int, optional
        :param untagged_vlan: NetBox VLAN object id of untagged vlan
        :type untagged_vlan: int, optional
        :param tagged_vlans: List of NetBox VLAN object ids for tagged VLANs
        :type tagged_vlans: str, optional
        :param tags: Tags to apply to the object
        :type tags: list, optional
        """
        obj = {
            "virtual_machine": {"name": truncate(virtual_machine, max_len=64)},
            "name": name,
            "itype": self._version_dependent(
                nb_obj_type="interfaces",
                key="type",
                value=itype
                ),
            "enabled": enabled,
            "mtu": mtu,
            "mac_address": mac_address.upper() if mac_address else None,
            "description": description,
            "mode": mode,
            "untagged_vlan": untagged_vlan,
            "tagged_vlans": tagged_vlans,
            "tags": tags,
            }
        return remove_empty_fields(obj)
