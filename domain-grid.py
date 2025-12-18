#!/usr/bin/env python3
"""
Domain Grid - Advanced Active Directory Enumeration Tool

A comprehensive AD enumeration tool using rpcclient for authorized security testing.
Enumerates users, groups, computers, trusts, and identifies high-value targets.
"""

import os
import subprocess
import sys
import time
import uuid
import json
import csv
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Set, Optional, Tuple

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    COLORAMA_AVAILABLE = True
except ImportError:
    COLORAMA_AVAILABLE = False
    class Fore:
        RED = YELLOW = GREEN = CYAN = MAGENTA = BLUE = WHITE = ""
    class Style:
        RESET_ALL = BRIGHT = ""

# Constants
MAX_WORKERS = 10
MAX_RETRIES = 3
TIMEOUT = 15
SEPARATOR = "=" * 70 + "\n"

# Privileged groups to highlight
PRIVILEGED_GROUPS = {
    "Domain Admins", "Enterprise Admins", "Schema Admins",
    "Administrators", "Account Operators", "Backup Operators",
    "Server Operators", "Print Operators", "DnsAdmins",
    "Group Policy Creator Owners", "Remote Desktop Users",
    "Cert Publishers", "Key Admins", "Enterprise Key Admins"
}

# Data stores
class DomainData:
    def __init__(self):
        self.groups: Dict[str, str] = {}  # rid -> name
        self.users: Dict[str, str] = {}   # rid -> name
        self.computers: Dict[str, str] = {}  # rid -> name
        self.group_members: Dict[str, List[str]] = {}  # group_rid -> [member_rids]
        self.user_info: Dict[str, List[str]] = {}  # user_rid -> [info lines]
        self.group_info: Dict[str, List[str]] = {}  # group_rid -> [info lines]
        self.user_groups: Dict[str, List[str]] = {}  # user_rid -> [group_rids]
        self.nested_groups: Dict[str, Set[str]] = {}  # group_rid -> {all_member_rids}
        self.trusts: List[Dict] = []
        self.password_policy: Dict[str, str] = {}
        self.kerberoastable: List[str] = []  # user rids with SPNs
        self.asrep_roastable: List[str] = []  # users without preauth
        self.failed_commands: List[str] = []
        self.domain_sid: str = ""
        self.domain_name: str = ""


def print_status(message: str, color: str = Fore.WHITE):
    """Print colored status message."""
    print(f"{color}{message}{Style.RESET_ALL}")


def print_progress(current: int, total: int, desc: str):
    """Print progress indicator."""
    percent = (current / total) * 100 if total > 0 else 0
    bar_len = 30
    filled = int(bar_len * current / total) if total > 0 else 0
    bar = "█" * filled + "░" * (bar_len - filled)
    print(f"\r{Fore.CYAN}[{bar}] {percent:5.1f}% - {desc} ({current}/{total}){Style.RESET_ALL}", end="", flush=True)


def execute_command(command: str, timeout: int = TIMEOUT, return_stderr: bool = False) -> Tuple[List[str], bool]:
    """Execute command with retries. Returns (output_lines, success) or (output_lines, success, stderr) if return_stderr=True."""
    last_stderr = ""
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            result = subprocess.run(
                command,
                shell=True,
                executable='/bin/bash',  # Use bash for process substitution support
                timeout=timeout,
                capture_output=True,
                text=True
            )
            last_stderr = result.stderr
            if result.returncode == 0:
                if return_stderr:
                    return result.stdout.splitlines(), True, result.stderr
                return result.stdout.splitlines(), True
            if "NT_STATUS_ACCESS_DENIED" in result.stderr:
                if return_stderr:
                    return [], False, result.stderr
                return [], False
        except subprocess.TimeoutExpired:
            last_stderr = "TIMEOUT"
        except Exception as e:
            last_stderr = str(e)
        time.sleep(0.5)
    if return_stderr:
        return [], False, last_stderr
    return [], False


def build_rpc_command(user: str, password: str, host: str, rpc_cmd: str) -> str:
    """Build rpcclient command string with quoted password."""
    # Quote only the password with single quotes (don't use shlex.quote as it escapes !)
    # Single quotes preserve all special characters literally in bash
    # Escape any single quotes in the password by ending quote, adding escaped quote, starting new quote
    escaped_pass = password.replace("'", "'\"'\"'")
    # Also quote the rpc command with single quotes
    return f"rpcclient -U {user}%'{escaped_pass}' {host} -c '{rpc_cmd}'"


def fetch_domain_info(user: str, password: str, host: str, data: DomainData):
    """Fetch basic domain information."""
    # Get domain SID
    cmd = build_rpc_command(user, password, host, "lsaquery")
    output, success = execute_command(cmd)
    for line in output:
        if "Domain Sid:" in line:
            data.domain_sid = line.split("Domain Sid:")[1].strip()
        elif "Domain Name:" in line:
            data.domain_name = line.split("Domain Name:")[1].strip()


def fetch_groups(user: str, password: str, host: str, data: DomainData, debug: bool = False):
    """Fetch all domain groups."""
    cmd = build_rpc_command(user, password, host, "enumdomgroups")
    if debug:
        print(f"DEBUG CMD: {cmd}")
        output, success, stderr = execute_command(cmd, return_stderr=True)
        print(f"DEBUG OUTPUT: {output}")
        print(f"DEBUG STDERR: {stderr}")
        print(f"DEBUG SUCCESS: {success}")
    else:
        output, success = execute_command(cmd)
    for line in output:
        if line.startswith("group:["):
            try:
                name = line.split("group:[")[1].split("]")[0]
                rid = line.split("rid:[")[1].split("]")[0]
                data.groups[rid] = name
            except IndexError:
                pass


def fetch_users(user: str, password: str, host: str, data: DomainData):
    """Fetch all domain users."""
    cmd = build_rpc_command(user, password, host, "enumdomusers")
    output, success = execute_command(cmd)
    for line in output:
        if line.startswith("user:["):
            try:
                name = line.split("user:[")[1].split("]")[0]
                rid = line.split("rid:[")[1].split("]")[0]
                # Filter out computer accounts (end with $)
                if not name.endswith("$"):
                    data.users[rid] = name
                else:
                    data.computers[rid] = name
            except IndexError:
                pass


def fetch_group_members_single(user: str, password: str, host: str, rid: str) -> Tuple[str, List[str]]:
    """Fetch members for a single group."""
    cmd = build_rpc_command(user, password, host, f"querygroupmem {rid}")
    output, success = execute_command(cmd)
    members = []
    for line in output:
        if "rid:[" in line:
            try:
                member_rid = line.split("rid:[")[1].split("]")[0]
                members.append(member_rid)
            except IndexError:
                pass
    return rid, members


def fetch_group_members_parallel(user: str, password: str, host: str, data: DomainData):
    """Fetch group members in parallel."""
    total = len(data.groups)
    completed = 0

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {
            executor.submit(fetch_group_members_single, user, password, host, rid): rid
            for rid in data.groups.keys()
        }

        for future in as_completed(futures):
            rid, members = future.result()
            data.group_members[rid] = members
            completed += 1
            print_progress(completed, total, "Group members")

    print()  # Newline after progress


def fetch_group_info_single(user: str, password: str, host: str, rid: str) -> Tuple[str, List[str]]:
    """Fetch info for a single group."""
    cmd = build_rpc_command(user, password, host, f"querygroup {rid}")
    output, success = execute_command(cmd)
    return rid, output


def fetch_group_info_parallel(user: str, password: str, host: str, data: DomainData):
    """Fetch group info in parallel."""
    total = len(data.groups)
    completed = 0

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {
            executor.submit(fetch_group_info_single, user, password, host, rid): rid
            for rid in data.groups.keys()
        }

        for future in as_completed(futures):
            rid, info = future.result()
            data.group_info[rid] = info
            completed += 1
            print_progress(completed, total, "Group info")

    print()


def fetch_user_info_single(user: str, password: str, host: str, rid: str) -> Tuple[str, List[str], bool, bool]:
    """Fetch info for a single user. Returns (rid, info, has_spn, no_preauth)."""
    cmd = build_rpc_command(user, password, host, f"queryuser {rid}")
    output, success = execute_command(cmd)

    has_spn = False
    no_preauth = False

    for line in output:
        # Check for Kerberoastable (has SPN)
        if "service_principal_names" in line.lower():
            has_spn = True
        # Check for AS-REP roastable (DONT_REQ_PREAUTH flag = 0x400000)
        if "acct_flags:" in line.lower():
            try:
                flags_str = line.split(":")[1].strip()
                if "0x" in flags_str:
                    flags = int(flags_str, 16)
                    if flags & 0x400000:  # DONT_REQ_PREAUTH
                        no_preauth = True
            except (IndexError, ValueError):
                pass

    return rid, output, has_spn, no_preauth


def fetch_user_info_parallel(user: str, password: str, host: str, data: DomainData):
    """Fetch user info in parallel."""
    total = len(data.users)
    completed = 0

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {
            executor.submit(fetch_user_info_single, user, password, host, rid): rid
            for rid in data.users.keys()
        }

        for future in as_completed(futures):
            rid, info, has_spn, no_preauth = future.result()
            data.user_info[rid] = info
            if has_spn:
                data.kerberoastable.append(rid)
            if no_preauth:
                data.asrep_roastable.append(rid)
            completed += 1
            print_progress(completed, total, "User info")

    print()


def fetch_trusts(user: str, password: str, host: str, data: DomainData):
    """Enumerate domain trusts."""
    cmd = build_rpc_command(user, password, host, "dsenumdomtrusts")
    output, success = execute_command(cmd)

    for line in output:
        if line.strip():
            parts = line.split()
            if len(parts) >= 1:
                trust_info = {
                    "domain": parts[0] if len(parts) > 0 else "",
                    "raw": line.strip()
                }
                data.trusts.append(trust_info)

    # Also try lsaenumsid for additional info
    cmd = build_rpc_command(user, password, host, "lsaenumsid")
    output, success = execute_command(cmd)
    # Store SIDs for reference


def fetch_password_policy(user: str, password: str, host: str, data: DomainData):
    """Fetch domain password policy."""
    cmd = build_rpc_command(user, password, host, "getdompwinfo")
    output, success = execute_command(cmd)

    for line in output:
        if ":" in line:
            key, _, value = line.partition(":")
            data.password_policy[key.strip()] = value.strip()

    # Also get account policy
    cmd = build_rpc_command(user, password, host, "getusrdompwinfo 500")
    output, success = execute_command(cmd)
    for line in output:
        if ":" in line:
            key, _, value = line.partition(":")
            data.password_policy[f"admin_{key.strip()}"] = value.strip()


def resolve_nested_groups(data: DomainData, max_depth: int = 10):
    """Resolve nested group memberships."""
    for group_rid in data.groups.keys():
        all_members = set()
        to_process = set(data.group_members.get(group_rid, []))
        processed = set()
        depth = 0

        while to_process and depth < max_depth:
            current = to_process.pop()
            if current in processed:
                continue
            processed.add(current)
            all_members.add(current)

            # If this member is a group, add its members to process
            if current in data.groups:
                for member in data.group_members.get(current, []):
                    if member not in processed:
                        to_process.add(member)

            depth += 1

        data.nested_groups[group_rid] = all_members


def calculate_user_groups(data: DomainData):
    """Calculate which groups each user belongs to."""
    for user_rid in data.users.keys():
        groups = []
        for group_rid, members in data.group_members.items():
            if user_rid in members:
                groups.append(group_rid)
        data.user_groups[user_rid] = groups


def save_results_txt(data: DomainData, results_dir: str):
    """Save results in text format."""

    # Domain info
    with open(os.path.join(results_dir, "domain-info.txt"), "w") as f:
        f.write(SEPARATOR)
        f.write("DOMAIN INFORMATION\n")
        f.write(SEPARATOR)
        f.write(f"Domain Name: {data.domain_name}\n")
        f.write(f"Domain SID: {data.domain_sid}\n")
        f.write(f"Total Users: {len(data.users)}\n")
        f.write(f"Total Groups: {len(data.groups)}\n")
        f.write(f"Total Computers: {len(data.computers)}\n")
        f.write(f"Domain Trusts: {len(data.trusts)}\n")
        f.write(f"Kerberoastable Users: {len(data.kerberoastable)}\n")
        f.write(f"AS-REP Roastable Users: {len(data.asrep_roastable)}\n")

    # Groups
    with open(os.path.join(results_dir, "domain-groups.txt"), "w") as f:
        for rid, name in sorted(data.groups.items(), key=lambda x: x[1]):
            priv_marker = " [PRIVILEGED]" if name in PRIVILEGED_GROUPS else ""
            f.write(f"{name}{priv_marker}\n")

    # Users
    with open(os.path.join(results_dir, "domain-users.txt"), "w") as f:
        for rid, name in sorted(data.users.items(), key=lambda x: x[1]):
            f.write(f"{name}\n")

    # Computers
    with open(os.path.join(results_dir, "domain-computers.txt"), "w") as f:
        for rid, name in sorted(data.computers.items(), key=lambda x: x[1]):
            f.write(f"{name}\n")

    # Group details with members
    with open(os.path.join(results_dir, "domain-group-details.txt"), "w") as f:
        for rid, name in sorted(data.groups.items(), key=lambda x: x[1]):
            priv_marker = " *** PRIVILEGED GROUP ***" if name in PRIVILEGED_GROUPS else ""
            f.write(SEPARATOR)
            f.write(f"GROUP: {name}{priv_marker}\n")
            f.write(f"RID: {rid}\n")

            # Group info
            if rid in data.group_info:
                for line in data.group_info[rid]:
                    if line.strip():
                        f.write(f"  {line}\n")

            # Direct members
            members = data.group_members.get(rid, [])
            f.write(f"\nDirect Members ({len(members)}):\n")
            for member_rid in members:
                member_name = data.users.get(member_rid, data.groups.get(member_rid, f"Unknown-{member_rid}"))
                member_type = "User" if member_rid in data.users else "Group" if member_rid in data.groups else "Unknown"
                f.write(f"  - {member_name} ({member_type})\n")

            # Nested members (all)
            nested = data.nested_groups.get(rid, set())
            nested_users = [m for m in nested if m in data.users]
            if len(nested_users) > len(members):
                f.write(f"\nAll Members (including nested) ({len(nested_users)}):\n")
                for member_rid in nested_users:
                    member_name = data.users.get(member_rid, f"Unknown-{member_rid}")
                    f.write(f"  - {member_name}\n")

            f.write("\n")

    # User details
    with open(os.path.join(results_dir, "domain-user-details.txt"), "w") as f:
        for rid, name in sorted(data.users.items(), key=lambda x: x[1]):
            f.write(SEPARATOR)
            f.write(f"USER: {name}\n")
            f.write(f"RID: {rid}\n")

            # Flags
            flags = []
            if rid in data.kerberoastable:
                flags.append("KERBEROASTABLE")
            if rid in data.asrep_roastable:
                flags.append("AS-REP ROASTABLE")
            if flags:
                f.write(f"FLAGS: {', '.join(flags)}\n")

            # User info
            if rid in data.user_info:
                for line in data.user_info[rid]:
                    if line.strip():
                        f.write(f"  {line}\n")

            # Group memberships
            groups = data.user_groups.get(rid, [])
            f.write(f"\nGroup Memberships ({len(groups)}):\n")
            for group_rid in groups:
                group_name = data.groups.get(group_rid, f"Unknown-{group_rid}")
                priv_marker = " [PRIVILEGED]" if group_name in PRIVILEGED_GROUPS else ""
                f.write(f"  - {group_name}{priv_marker}\n")

            f.write("\n")

    # RID mappings
    with open(os.path.join(results_dir, "domain-users-rids.txt"), "w") as f:
        for rid, name in sorted(data.users.items(), key=lambda x: int(x[0], 16) if x[0].startswith("0x") else int(x[0])):
            f.write(f"{name} - {rid}\n")

    with open(os.path.join(results_dir, "domain-groups-rids.txt"), "w") as f:
        for rid, name in sorted(data.groups.items(), key=lambda x: int(x[0], 16) if x[0].startswith("0x") else int(x[0])):
            f.write(f"{name} - {rid}\n")

    # Privileged users
    with open(os.path.join(results_dir, "privileged-users.txt"), "w") as f:
        f.write(SEPARATOR)
        f.write("PRIVILEGED GROUP MEMBERS\n")
        f.write(SEPARATOR)
        f.write("Users with membership in high-privilege groups\n\n")

        for group_rid, group_name in data.groups.items():
            if group_name in PRIVILEGED_GROUPS:
                all_members = data.nested_groups.get(group_rid, set())
                user_members = [m for m in all_members if m in data.users]
                if user_members:
                    f.write(f"\n{group_name}:\n")
                    for member_rid in user_members:
                        f.write(f"  - {data.users.get(member_rid, member_rid)}\n")

    # Kerberoastable users
    with open(os.path.join(results_dir, "kerberoastable-users.txt"), "w") as f:
        f.write(SEPARATOR)
        f.write("KERBEROASTABLE USERS\n")
        f.write(SEPARATOR)
        f.write("Users with Service Principal Names (SPNs) set\n\n")
        for rid in data.kerberoastable:
            name = data.users.get(rid, rid)
            f.write(f"{name}\n")

    # AS-REP roastable users
    with open(os.path.join(results_dir, "asrep-roastable-users.txt"), "w") as f:
        f.write(SEPARATOR)
        f.write("AS-REP ROASTABLE USERS\n")
        f.write(SEPARATOR)
        f.write("Users with 'Do not require Kerberos preauthentication' enabled\n\n")
        for rid in data.asrep_roastable:
            name = data.users.get(rid, rid)
            f.write(f"{name}\n")

    # Domain trusts
    with open(os.path.join(results_dir, "domain-trusts.txt"), "w") as f:
        f.write(SEPARATOR)
        f.write("DOMAIN TRUSTS\n")
        f.write(SEPARATOR)
        for trust in data.trusts:
            f.write(f"{trust.get('raw', trust.get('domain', 'Unknown'))}\n")

    # Password policy
    with open(os.path.join(results_dir, "password-policy.txt"), "w") as f:
        f.write(SEPARATOR)
        f.write("PASSWORD POLICY\n")
        f.write(SEPARATOR)
        for key, value in data.password_policy.items():
            f.write(f"{key}: {value}\n")

    # Counted files
    with open(os.path.join(results_dir, "domain-users-counted.txt"), "w") as f:
        user_counts = []
        for rid, name in data.users.items():
            count = len(data.user_groups.get(rid, []))
            user_counts.append((name, count))
        for name, count in sorted(user_counts, key=lambda x: x[1], reverse=True):
            f.write(f"{name}: {count} groups\n")

    with open(os.path.join(results_dir, "domain-groups-counted.txt"), "w") as f:
        group_counts = []
        for rid, name in data.groups.items():
            count = len(data.group_members.get(rid, []))
            group_counts.append((name, count))
        for name, count in sorted(group_counts, key=lambda x: x[1], reverse=True):
            f.write(f"{name}: {count} members\n")


def save_results_json(data: DomainData, results_dir: str):
    """Save results in JSON format."""
    output = {
        "domain": {
            "name": data.domain_name,
            "sid": data.domain_sid,
            "password_policy": data.password_policy
        },
        "statistics": {
            "total_users": len(data.users),
            "total_groups": len(data.groups),
            "total_computers": len(data.computers),
            "kerberoastable_users": len(data.kerberoastable),
            "asrep_roastable_users": len(data.asrep_roastable),
            "domain_trusts": len(data.trusts)
        },
        "users": [
            {
                "rid": rid,
                "name": name,
                "kerberoastable": rid in data.kerberoastable,
                "asrep_roastable": rid in data.asrep_roastable,
                "groups": [data.groups.get(g, g) for g in data.user_groups.get(rid, [])]
            }
            for rid, name in data.users.items()
        ],
        "groups": [
            {
                "rid": rid,
                "name": name,
                "privileged": name in PRIVILEGED_GROUPS,
                "direct_members": len(data.group_members.get(rid, [])),
                "total_members": len([m for m in data.nested_groups.get(rid, set()) if m in data.users])
            }
            for rid, name in data.groups.items()
        ],
        "computers": [{"rid": rid, "name": name} for rid, name in data.computers.items()],
        "trusts": data.trusts,
        "high_value_targets": {
            "privileged_users": [],
            "kerberoastable": [data.users.get(rid, rid) for rid in data.kerberoastable],
            "asrep_roastable": [data.users.get(rid, rid) for rid in data.asrep_roastable]
        }
    }

    # Populate privileged users
    for group_rid, group_name in data.groups.items():
        if group_name in PRIVILEGED_GROUPS:
            all_members = data.nested_groups.get(group_rid, set())
            for member_rid in all_members:
                if member_rid in data.users:
                    user_name = data.users.get(member_rid)
                    entry = {"user": user_name, "group": group_name}
                    if entry not in output["high_value_targets"]["privileged_users"]:
                        output["high_value_targets"]["privileged_users"].append(entry)

    with open(os.path.join(results_dir, "domain-data.json"), "w") as f:
        json.dump(output, f, indent=2)


def save_results_csv(data: DomainData, results_dir: str):
    """Save results in CSV format."""

    # Users CSV
    with open(os.path.join(results_dir, "users.csv"), "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["RID", "Username", "Kerberoastable", "AS-REP Roastable", "Group Count", "Privileged"])
        for rid, name in data.users.items():
            is_priv = any(
                data.groups.get(g, "") in PRIVILEGED_GROUPS
                for g in data.user_groups.get(rid, [])
            )
            writer.writerow([
                rid, name,
                "Yes" if rid in data.kerberoastable else "No",
                "Yes" if rid in data.asrep_roastable else "No",
                len(data.user_groups.get(rid, [])),
                "Yes" if is_priv else "No"
            ])

    # Groups CSV
    with open(os.path.join(results_dir, "groups.csv"), "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["RID", "Group Name", "Privileged", "Direct Members", "Total Members"])
        for rid, name in data.groups.items():
            writer.writerow([
                rid, name,
                "Yes" if name in PRIVILEGED_GROUPS else "No",
                len(data.group_members.get(rid, [])),
                len([m for m in data.nested_groups.get(rid, set()) if m in data.users])
            ])

    # Computers CSV
    with open(os.path.join(results_dir, "computers.csv"), "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["RID", "Computer Name"])
        for rid, name in data.computers.items():
            writer.writerow([rid, name])


def print_summary(data: DomainData):
    """Print enumeration summary."""
    print()
    print(f"{Fore.GREEN}{SEPARATOR}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}ENUMERATION COMPLETE{Style.RESET_ALL}")
    print(f"{Fore.GREEN}{SEPARATOR}{Style.RESET_ALL}")
    print(f"Domain: {Fore.CYAN}{data.domain_name}{Style.RESET_ALL}")
    print(f"Domain SID: {Fore.CYAN}{data.domain_sid}{Style.RESET_ALL}")
    print()
    print(f"  Users:      {Fore.YELLOW}{len(data.users)}{Style.RESET_ALL}")
    print(f"  Groups:     {Fore.YELLOW}{len(data.groups)}{Style.RESET_ALL}")
    print(f"  Computers:  {Fore.YELLOW}{len(data.computers)}{Style.RESET_ALL}")
    print(f"  Trusts:     {Fore.YELLOW}{len(data.trusts)}{Style.RESET_ALL}")
    print()

    if data.kerberoastable:
        print(f"{Fore.RED}[!] Kerberoastable Users: {len(data.kerberoastable)}{Style.RESET_ALL}")
        for rid in data.kerberoastable[:5]:
            print(f"    - {data.users.get(rid, rid)}")
        if len(data.kerberoastable) > 5:
            print(f"    ... and {len(data.kerberoastable) - 5} more")

    if data.asrep_roastable:
        print(f"{Fore.RED}[!] AS-REP Roastable Users: {len(data.asrep_roastable)}{Style.RESET_ALL}")
        for rid in data.asrep_roastable[:5]:
            print(f"    - {data.users.get(rid, rid)}")
        if len(data.asrep_roastable) > 5:
            print(f"    ... and {len(data.asrep_roastable) - 5} more")

    # Privileged users summary
    priv_users = set()
    for group_rid, group_name in data.groups.items():
        if group_name in PRIVILEGED_GROUPS:
            for member_rid in data.nested_groups.get(group_rid, set()):
                if member_rid in data.users:
                    priv_users.add(data.users[member_rid])

    if priv_users:
        print(f"{Fore.MAGENTA}[*] Privileged Users: {len(priv_users)}{Style.RESET_ALL}")
        for user in sorted(priv_users)[:10]:
            print(f"    - {user}")
        if len(priv_users) > 10:
            print(f"    ... and {len(priv_users) - 10} more")

    print()


def main():
    global MAX_WORKERS

    parser = argparse.ArgumentParser(
        description="Domain Grid - Advanced Active Directory Enumeration Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -u admin -p 'P@ssw0rd' -t 192.168.1.10
  %(prog)s -u admin -p 'P@ssw0rd' -t dc01.domain.local -o /tmp/results
  %(prog)s -u admin -p 'P@ssw0rd' -t 192.168.1.10 --json --csv
  %(prog)s -u admin -p 'P@ssw0rd' -t 192.168.1.10 -w 20
        """
    )

    parser.add_argument("-u", "--user", required=True, help="Domain username")
    parser.add_argument("-p", "--password", required=True, help="Domain password")
    parser.add_argument("-t", "--target", required=True, help="Domain Controller IP or hostname")
    parser.add_argument("-o", "--output", help="Output directory (default: results_<uuid>)")
    parser.add_argument("-w", "--workers", type=int, default=MAX_WORKERS, help=f"Parallel workers (default: {MAX_WORKERS})")
    parser.add_argument("--json", action="store_true", help="Export results as JSON")
    parser.add_argument("--csv", action="store_true", help="Export results as CSV")
    parser.add_argument("--no-nested", action="store_true", help="Skip nested group resolution")
    parser.add_argument("-q", "--quiet", action="store_true", help="Minimal output")

    # Support legacy positional arguments
    if len(sys.argv) == 4 and not sys.argv[1].startswith("-"):
        # Legacy mode: domain-grid.py <user> <pass> <host>
        args = argparse.Namespace(
            user=sys.argv[1],
            password=sys.argv[2],
            target=sys.argv[3],
            output=None,
            workers=MAX_WORKERS,
            json=False,
            csv=False,
            no_nested=False,
            quiet=False
        )
    else:
        args = parser.parse_args()

    # Update MAX_WORKERS from args (it's already a module-level variable)
    MAX_WORKERS = args.workers

    # Create results directory
    results_dir = args.output or f"results_{uuid.uuid4().hex[:8]}"
    os.makedirs(results_dir, exist_ok=True)

    data = DomainData()

    if not args.quiet:
        print(f"{Fore.CYAN}")
        print("=" * 60)
        print("  DOMAIN GRID - Active Directory Enumeration Tool")
        print("=" * 60)
        print(f"{Style.RESET_ALL}")
        print(f"Target: {Fore.YELLOW}{args.target}{Style.RESET_ALL}")
        print(f"Output: {Fore.YELLOW}{results_dir}{Style.RESET_ALL}")
        print()

    # Phase 1: Basic enumeration
    print_status("[*] Fetching domain information...", Fore.YELLOW)
    fetch_domain_info(args.user, args.password, args.target, data)

    print_status("[*] Fetching domain groups...", Fore.YELLOW)
    fetch_groups(args.user, args.password, args.target, data, debug=True)
    print_status(f"    Found {len(data.groups)} groups", Fore.GREEN)

    print_status("[*] Fetching domain users...", Fore.YELLOW)
    fetch_users(args.user, args.password, args.target, data)
    print_status(f"    Found {len(data.users)} users, {len(data.computers)} computers", Fore.GREEN)

    # Phase 2: Parallel detailed enumeration
    print_status("[*] Fetching group memberships (parallel)...", Fore.YELLOW)
    fetch_group_members_parallel(args.user, args.password, args.target, data)

    print_status("[*] Fetching group details (parallel)...", Fore.YELLOW)
    fetch_group_info_parallel(args.user, args.password, args.target, data)

    print_status("[*] Fetching user details (parallel)...", Fore.YELLOW)
    fetch_user_info_parallel(args.user, args.password, args.target, data)

    # Phase 3: Additional enumeration
    print_status("[*] Fetching domain trusts...", Fore.YELLOW)
    fetch_trusts(args.user, args.password, args.target, data)

    print_status("[*] Fetching password policy...", Fore.YELLOW)
    fetch_password_policy(args.user, args.password, args.target, data)

    # Phase 4: Analysis
    if not args.no_nested:
        print_status("[*] Resolving nested group memberships...", Fore.YELLOW)
        resolve_nested_groups(data)

    print_status("[*] Calculating user group memberships...", Fore.YELLOW)
    calculate_user_groups(data)

    # Phase 5: Save results
    print_status("[*] Saving results...", Fore.YELLOW)
    save_results_txt(data, results_dir)

    if args.json:
        save_results_json(data, results_dir)
        print_status("    Saved JSON export", Fore.GREEN)

    if args.csv:
        save_results_csv(data, results_dir)
        print_status("    Saved CSV export", Fore.GREEN)

    # Print summary
    if not args.quiet:
        print_summary(data)

    print_status(f"[+] Results saved to: {results_dir}", Fore.GREEN)


if __name__ == "__main__":
    main()
