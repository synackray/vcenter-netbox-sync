#!/usr/bin/env python3

# Program Settings
# Valid options are debug, info, warning, error, critical
LOG_LEVEL = "info"
 # Logs to console if True, disables console logging if False
LOG_CONSOLE = True
 # Places all logs in a rotating file if True
LOG_FILE = True
# IPv4 networks eligible to be synced to NetBox
IPV4_ALLOWED = ["192.168.0.0/16", "172.16.0.0/12", "10.0.0.0/8"]
 # IPv6 networks eligible to be synced to NetBox
IPV6_ALLOWED = ["fe80::/10"]


# Optional Settings
# Attempt to collect asset tags from vCenter hosts
ASSET_TAGS = True
# Perform reverse DNS lookup on all eligible IP addresses and populate DNS name field in NetBox
POPULATE_DNS_NAME = True
# Use custom DNS servers defined below for reverse DNS lookups
CUSTOM_DNS_SERVERS = False
# List of DNS servers to query for PTR records
DNS_SERVERS = ["192.168.1.11", "192.168.1.12"]
# Create a custom field for virtual machines to track the current host they reside on
TRACK_VM_HOST = False
# Specify custom NetBox Device / vCenter Host role. Must match the name of an existing NetBox Device Role.
DEVICE_ROLE = "Server"


# vCenter Settings
# Hostname (FQDN or IP), Port, User, and Password for each vCenter instance
# The USER argument supports SSO with @domain.tld suffix
VC_HOSTS = [
    # You can add more vCenter instances by duplicating the line below
    {"HOST": "vcenter1.example.com", "PORT": 443, "USER": "", "PASS": ""},
    ]


# NetBox Settings
# NetBox API Key
NB_API_KEY = ""
# Disables SSL/TLS and uses HTTP for requests. Not ever recommended.
NB_DISABLE_TLS = False
# The fully qualified domain name to reach NetBox
NB_FQDN = "netbox.example.com"
# Leverage SSL/TLS but ignore certificate errors (ex. expired, untrusted)
NB_INSECURE_TLS = False
# NetBox port to connect to
NB_PORT = 443
# Automatically orphan and delete objects if they are no longer in their source system
NB_PRUNE_ENABLED = True
# How many days should to wait before pruning an orphaned object
NB_PRUNE_DELAY_DAYS = 0
