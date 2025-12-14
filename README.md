# Domain Grid

Advanced Active Directory enumeration tool using `rpcclient` for authorized security testing.

## Features

- **Parallel Execution** - Multi-threaded enumeration with configurable worker count
- **User Enumeration** - All domain users with RID mapping
- **Group Enumeration** - All domain groups with membership details
- **Computer Enumeration** - Domain-joined computer accounts
- **Nested Group Resolution** - Recursive group membership analysis
- **Domain Trust Enumeration** - Inter-domain trust relationships
- **Password Policy Retrieval** - Domain password requirements
- **Privileged Group Detection** - Highlights Domain Admins, Enterprise Admins, etc.
- **Kerberoastable User Detection** - Users with SPNs set
- **AS-REP Roastable Detection** - Users without Kerberos pre-authentication
- **Multiple Output Formats** - TXT, JSON, and CSV exports
- **Progress Indicators** - Real-time enumeration progress

## Requirements

- Python 3.6+
- Linux system with `rpcclient` installed (part of Samba)
- Valid Active Directory credentials with read permissions

### Installation

```bash
# Install rpcclient (Debian/Ubuntu)
sudo apt install smbclient

# Install rpcclient (RHEL/CentOS)
sudo yum install samba-client

# Install Python dependency (optional, for colored output)
pip install colorama
```

## Usage

### Basic Usage

```bash
# Named arguments (recommended)
python3 domain-grid.py -u <username> -p <password> -t <DC_IP>

# Legacy positional arguments (backwards compatible)
python3 domain-grid.py <username> <password> <DC_IP>
```

### Options

| Option | Description |
|--------|-------------|
| `-u, --user` | Domain username (required) |
| `-p, --password` | Domain password (required) |
| `-t, --target` | Domain Controller IP or hostname (required) |
| `-o, --output` | Output directory (default: results_<uuid>) |
| `-w, --workers` | Parallel workers (default: 10) |
| `--json` | Export results as JSON |
| `--csv` | Export results as CSV |
| `--no-nested` | Skip nested group resolution |
| `-q, --quiet` | Minimal output |

### Examples

```bash
# Basic enumeration
python3 domain-grid.py -u admin -p 'P@ssw0rd' -t 192.168.1.10

# With all export formats
python3 domain-grid.py -u admin -p 'P@ssw0rd' -t dc01.domain.local --json --csv

# Custom output directory with more workers
python3 domain-grid.py -u admin -p 'P@ssw0rd' -t 192.168.1.10 -o /tmp/ad-enum -w 20

# Quiet mode for scripting
python3 domain-grid.py -u admin -p 'P@ssw0rd' -t 192.168.1.10 -q --json
```

## Output Files

Results are saved in a unique directory (`results_<uuid>` or custom via `-o`):

| File | Description |
|------|-------------|
| `domain-info.txt` | Domain summary and statistics |
| `domain-users.txt` | List of all domain users |
| `domain-groups.txt` | List of all domain groups (privileged marked) |
| `domain-computers.txt` | List of all computer accounts |
| `domain-group-details.txt` | Groups with member lists (direct + nested) |
| `domain-user-details.txt` | Users with attributes and group memberships |
| `domain-users-rids.txt` | User to RID mapping |
| `domain-groups-rids.txt` | Group to RID mapping |
| `domain-users-counted.txt` | Users sorted by group membership count |
| `domain-groups-counted.txt` | Groups sorted by member count |
| `privileged-users.txt` | Users in privileged groups |
| `kerberoastable-users.txt` | Users vulnerable to Kerberoasting |
| `asrep-roastable-users.txt` | Users vulnerable to AS-REP roasting |
| `domain-trusts.txt` | Domain trust relationships |
| `password-policy.txt` | Domain password policy |
| `domain-data.json` | Complete data export (with `--json`) |
| `users.csv` | User data export (with `--csv`) |
| `groups.csv` | Group data export (with `--csv`) |
| `computers.csv` | Computer data export (with `--csv`) |

## High-Value Target Detection

Domain Grid automatically identifies and highlights:

### Privileged Groups
- Domain Admins
- Enterprise Admins
- Schema Admins
- Administrators
- Account Operators
- Backup Operators
- Server Operators
- DnsAdmins
- Group Policy Creator Owners
- Cert Publishers
- Key Admins
- Enterprise Key Admins

### Attack Vectors
- **Kerberoastable Users**: Service accounts with SPNs that can be targeted for offline password cracking
- **AS-REP Roastable Users**: Accounts with "Do not require Kerberos preauthentication" enabled

## Example Output

```
============================================================
  DOMAIN GRID - Active Directory Enumeration Tool
============================================================
Target: 192.168.1.10
Output: results_a1b2c3d4

[*] Fetching domain information...
[*] Fetching domain groups...
    Found 52 groups
[*] Fetching domain users...
    Found 1247 users, 89 computers
[*] Fetching group memberships (parallel)...
[██████████████████████████████] 100.0% - Group members (52/52)
[*] Fetching group details (parallel)...
[██████████████████████████████] 100.0% - Group info (52/52)
[*] Fetching user details (parallel)...
[██████████████████████████████] 100.0% - User info (1247/1247)
[*] Fetching domain trusts...
[*] Fetching password policy...
[*] Resolving nested group memberships...
[*] Calculating user group memberships...
[*] Saving results...

======================================================================
ENUMERATION COMPLETE
======================================================================
Domain: CORP
Domain SID: S-1-5-21-1234567890-1234567890-1234567890

  Users:      1247
  Groups:     52
  Computers:  89
  Trusts:     2

[!] Kerberoastable Users: 3
    - svc_sql
    - svc_backup
    - svc_exchange
[!] AS-REP Roastable Users: 1
    - legacy_user
[*] Privileged Users: 8
    - Administrator
    - admin.jones
    - admin.smith
    ...

[+] Results saved to: results_a1b2c3d4
```

## Security Notice

This tool is intended for **authorized security testing only**. Ensure you have:

- Written authorization from the system owner
- A defined scope that includes AD enumeration
- Proper rules of engagement

Unauthorized use may violate computer crime laws.

## License

MIT License - See [LICENSE](LICENSE) file.
