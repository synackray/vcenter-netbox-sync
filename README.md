# vCenter NetBox Sync

Exports vCenter objects using the [VMware pyVmomi](https://github.com/vmware/pyvmomi) SDK, transforms them into NetBox objects, and syncs them.

## Principles

The [NetBox documentation](https://netbox.readthedocs.io/en/stable/#serve-as-a-source-of-truth) makes it clear the tool is intended to act as a "Source of Truth". The automated import of live network state is strongly discouraged. While this is sound logic, we've aimed to provide a middle-ground solution.

All objects collected from vCenter have a "lifecycle". Upon import, for supported object types, they are tagged "Synced" and "vCenter" to note their origin and distinguish them from other objects. Using this tagging system also allows for the orphaning of objects which are no longer detected in vCenter. This ensures stale objects are removed from NetBox keeping an accurate current state.

## Workflow

This program follows the [ETL](https://en.wikipedia.org/wiki/Extract,_transform,_load) methodology.

1. Objects are extracted from vCenter using the pyVmomi SDK.
2. Extracted vCenter objects are converted into their corresponding NetBox objects.
3. The transformed objects are imported into NetBox.

## Requirements

The following minimum software versions have been tested for compatibility.

* VMware vCenter 6
* NetBox v2.6.7

## Installation

1. Clone the repo.
2. Create a Python Virtual Environment [(venv)](https://docs.python.org/3/library/venv.html) and activate it.
3. Install the package requirements by running `pip install -r requirements.txt`.
4. Copy the `settings.example.py` to `settings.py` and fill in the values.
5. Execute `run.py`.
6. [optional] Schedule a cron job to execute the script on a regular basis.

## Example

```
.
```
