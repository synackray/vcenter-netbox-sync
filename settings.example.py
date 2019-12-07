#!/usr/bin/env python3

# Program Settings
LOG_LEVEL = "info" # Valid options are debug, info, warning, error, critical
LOG_CONSOLE = True # Logs to console if True, disables console logging if False
LOG_FILE = True # Places all logs in a rotating file if True

# vCenter Settings
VC_HOST = "" # IP or Hostname - vcenter1.example.com
VC_PORT = 443 # vCenter port to connect if changed from default
VC_USER = "" # User account to authenticate to vCenter, supports SSO with @domain.tld suffix
VC_PASS = "" # Password for the account defined in VC_USER

# NetBox Settings
NB_API_KEY = "" # NetBox API Key
