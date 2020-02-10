#!/usr/bin/env python3

# Program Settings
LOG_LEVEL = "info" # Valid options are debug, info, warning, error, critical
LOG_CONSOLE = True # Logs to console if True, disables console logging if False
LOG_FILE = True # Places all logs in a rotating file if True
IPV4_ALLOWED = ["192.168.0.0/16", "172.16.0.0/12", "10.0.0.0/8"] # IPv4 networks eligible to be synced to NetBox
IPV6_ALLOWED = ["fe80::/10"] # IPv6 networks eligible to be synced to NetBox
POPULATE_DNS_NAME = True  # Perform reverse DNS lookup on all eligible IP addresses and populate DNS name field in NetBox
CUSTOM_DNS_SERVERS = False # Use custom DNS servers defined below
DNS_SERVERS = ["192.168.1.11", "192.168.1.12"] # [optional] List of DNS servers to query for PTR records
ASSET_TAGS = True # Attempt to collect asset tags from vCenter hosts

# vCenter Settings
VC_HOSTS = [
    # Hostname (FQDN or IP), Port, User, and Password for each vCenter instance
    # The USER argument supports SSO with @domain.tld suffix
    # You can add more vCenter instances by duplicating the line below and
    # updating the values
    {"HOST": "vcenter1.example.com", "PORT": 443, "USER": "", "PASS": ""},
    ]

# NetBox Settings
NB_API_KEY = "" # NetBox API Key
NB_DISABLE_TLS = False # Disables SSL/TLS and uses HTTP for requests. Not ever recommended.
NB_FQDN = "netbox.example.com" # The fully qualified domain name to reach NetBox
NB_INSECURE_TLS = False # Leverage SSL/TLS but ignore certificate errors (ex. expired, untrusted)
NB_PORT = 443 # [optional] NetBox port to connect to if changed from the default
NB_PRUNE_ENABLED = True # Automatically orphan and delete objects if they are no longer in their source system
NB_PRUNE_DELAY_DAYS = 0 # How many days should we wait before pruning an orphaned object
