# vCenter NetBox Sync

![Build](https://github.com/synackray/vcenter-netbox-sync/workflows/Build/badge.svg?branch=master)

Exports vCenter objects using the [VMware pyVmomi](https://github.com/vmware/pyvmomi) SDK, transforms them into NetBox objects, and syncs them.

## Principles

The [NetBox documentation](https://netbox.readthedocs.io/en/stable/#serve-as-a-source-of-truth) makes it clear the tool is intended to act as a "Source of Truth". The automated import of live network state is strongly discouraged. While this is sound logic we've aimed to provide a middle-ground solution for those who desire the functionality.

All objects collected from vCenter have a "lifecycle". Upon import, for supported object types, they are tagged "Synced" and "vCenter" to note their origin and distinguish them from other objects. Using this tagging system also allows for the orphaning of objects which are no longer detected in vCenter. This ensures stale objects are removed from NetBox keeping an accurate current state. Note, adding the tag `Manual` to synced objects will ensure they are not pruned even if they become orphaned.

## Object Codex

The following objects are tracked and synced between vCenter and NetBox. Object types which support tags are also eligible to be pruned.

| vCenter          | NetBox                                     | Supports Tags |
|------------------|--------------------------------------------|---------------|
| Datacenters      | Cluster Groups                             | No            |
| Clusters         | Clusters                                   | Yes           |
| Hosts            | Manufacturers                              | No            |
| Hosts            | Device Types, Devices, Interfaces          | Yes           |
| Virtual Machines | Platforms                                  | No            |
| Virtual Machines | Interfaces, IP Addresses, Virtual Machines | Yes           |

## Requirements

The following minimum software versions have been tested for compatibility.

* VMware vCenter 6
* NetBox v2.6.7

The following permissions are required for this script to function.
* VMware vCenter - User account with "Read-only" role on vCenter root scope. The "Propogate to children" setting must also be checked.
* NetBox - API token with "write enabled" permissions. Instructions are available in the [NetBox documentation](https://netbox.readthedocs.io/en/stable/api/authentication/).

## Installation

1. Clone the repository.
2. Create a Python Virtual Environment [(venv)](https://docs.python.org/3/library/venv.html) and activate it.
3. Install the package requirements by running `pip install -r requirements.txt`.
4. Copy the `settings.example.py` to `settings.py` and fill in the values.
5. Execute `run.py`.
6. [optional] Schedule a cron job to execute the script on a regular basis.

## Examples

### Help Menu

```
$ run.py -h
usage: run.py [-h] [-c] [-v]

optional arguments:
  -h, --help     show this help message and exit
  -c, --cleanup  Remove all vCenter synced objects which support tagging. This
                 is helpful if you want to start fresh or stop using this
                 script.
  -v, --verbose  Enable verbose output. This overrides the log level in the
                 settings file. Intended for debugging purposes only.
```

### Cron Job

The following job runs every 4 hours at minute 15. The full paths to python and the script are provided so that the virtual environment instance and packages are used.

```
# vCenter to NetBox Sync
15 */4 * * * /opt/vcenter-netbox-sync/bin/python /opt/vcenter-netbox-sync/run.py >/dev/null 2>&1
```
