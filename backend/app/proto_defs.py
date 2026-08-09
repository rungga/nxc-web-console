"""Static metadata describing each NetExec protocol for the GUI form builder.

This does not try to replicate every single CLI flag (NetExec has hundreds
across modules) - instead it exposes the common ones, plus a free-text
"extra CLI arguments" field on every scan so any flag/module option supported
by the installed `nxc` binary can still be used, preserving full CLI parity.
"""
from __future__ import annotations

PROTOCOLS = {
    "smb": {
        "label": "SMB",
        "default_port": 445,
        "supports_modules": True,
        "supports_exec": True,
        "notes": "Primary AD lateral movement protocol. Exec methods: wmiexec, atexec, smbexec, mmcexec.",
    },
    "ldap": {
        "label": "LDAP",
        "default_port": 389,
        "supports_modules": True,
        "supports_exec": False,
    },
    "winrm": {
        "label": "WinRM",
        "default_port": 5985,
        "supports_modules": True,
        "supports_exec": True,
    },
    "mssql": {
        "label": "MSSQL",
        "default_port": 1433,
        "supports_modules": True,
        "supports_exec": True,
    },
    "ssh": {
        "label": "SSH",
        "default_port": 22,
        "supports_modules": True,
        "supports_exec": True,
        "supports_local_auth": False,
        "supports_kerberos": False,
        "supports_powershell": False,
    },
    "rdp": {
        "label": "RDP",
        "default_port": 3389,
        "supports_modules": False,
        "supports_exec": True,
    },
    "ftp": {
        "label": "FTP",
        "default_port": 21,
        "supports_modules": False,
        "supports_exec": False,
    },
    "vnc": {
        "label": "VNC",
        "default_port": 5900,
        "supports_modules": False,
        "supports_exec": False,
    },
    "wmi": {
        "label": "WMI",
        "default_port": 135,
        "supports_modules": True,
        "supports_exec": True,
    },
    "nfs": {
        "label": "NFS",
        "default_port": 2049,
        "supports_modules": False,
        "supports_exec": False,
    },
}

EXEC_METHODS = {
    "smb": ["wmiexec", "atexec", "smbexec", "mmcexec"],
    "wmi": ["wmiexec", "wmiexec-event"],
}

# Protocols whose nxc database schema includes an admin_relations table,
# i.e. where "Pwn3d!" / admin access is tracked persistently.
PROTOCOLS_WITH_ADMIN_RELATIONS = {"smb", "winrm", "mssql", "ssh"}
