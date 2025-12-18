#!/bin/bash

# SMB Share Enumeration Script with Proxychains
# Enumerates shares and checks read/write access

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

usage() {
    echo "Usage: $0 -u <username> -p <password> -t <target> [-d <domain>] [-P]"
    echo ""
    echo "Options:"
    echo "  -u    Username"
    echo "  -p    Password"
    echo "  -t    Target IP or hostname"
    echo "  -d    Domain (optional)"
    echo "  -P    Use proxychains (optional)"
    echo ""
    echo "Example:"
    echo "  $0 -u admin -p 'P@ssw0rd' -t 192.168.1.10 -d DOMAIN -P"
    exit 1
}

PROXY=""
DOMAIN=""

while getopts "u:p:t:d:Ph" opt; do
    case $opt in
        u) USER="$OPTARG" ;;
        p) PASS="$OPTARG" ;;
        t) TARGET="$OPTARG" ;;
        d) DOMAIN="$OPTARG" ;;
        P) PROXY="proxychains -q" ;;
        h) usage ;;
        *) usage ;;
    esac
done

if [ -z "$USER" ] || [ -z "$PASS" ] || [ -z "$TARGET" ]; then
    usage
fi

# Build auth string
if [ -n "$DOMAIN" ]; then
    AUTH_USER="${DOMAIN}\\${USER}"
else
    AUTH_USER="$USER"
fi

echo -e "${BLUE}================================================${NC}"
echo -e "${BLUE}  SMB Share Enumeration - ${TARGET}${NC}"
echo -e "${BLUE}================================================${NC}"
echo -e "User: ${YELLOW}${AUTH_USER}${NC}"
echo ""

# Get list of shares
echo -e "${YELLOW}[*] Enumerating shares...${NC}"
SHARES=$($PROXY smbclient -L "//${TARGET}" -U "${AUTH_USER}%${PASS}" -g 2>/dev/null | grep "^Disk" | cut -d'|' -f2)

if [ -z "$SHARES" ]; then
    echo -e "${RED}[!] Could not enumerate shares or no shares found${NC}"
    exit 1
fi

echo -e "${GREEN}[+] Found shares:${NC}"
echo "$SHARES" | while read share; do
    echo "    - $share"
done
echo ""

# Check access for each share
echo -e "${YELLOW}[*] Checking access permissions...${NC}"
echo ""
printf "%-30s %-10s %-10s\n" "SHARE" "READ" "WRITE"
printf "%-30s %-10s %-10s\n" "-----" "----" "-----"

echo "$SHARES" | while read share; do
    # Skip common non-accessible shares
    if [ "$share" == "IPC\$" ] || [ "$share" == "print\$" ]; then
        printf "%-30s %-10s %-10s\n" "$share" "-" "-"
        continue
    fi

    READ_ACCESS="NO"
    WRITE_ACCESS="NO"

    # Test read access by listing directory
    READ_TEST=$($PROXY smbclient "//${TARGET}/${share}" -U "${AUTH_USER}%${PASS}" -c "ls" 2>&1)
    if echo "$READ_TEST" | grep -qvE "NT_STATUS_ACCESS_DENIED|NT_STATUS_NO_SUCH_FILE|LOGON_FAILURE"; then
        if echo "$READ_TEST" | grep -qE "blocks of size|blocks available"; then
            READ_ACCESS="YES"
        fi
    fi

    # Test write access by creating and deleting a temp file
    if [ "$READ_ACCESS" == "YES" ]; then
        RANDOM_FILE=".test_write_$$_$RANDOM"
        WRITE_TEST=$($PROXY smbclient "//${TARGET}/${share}" -U "${AUTH_USER}%${PASS}" -c "put /dev/null ${RANDOM_FILE}; rm ${RANDOM_FILE}" 2>&1)
        if echo "$WRITE_TEST" | grep -qvE "NT_STATUS_ACCESS_DENIED|NT_STATUS_MEDIA_WRITE_PROTECTED|NT_STATUS_OBJECT_NAME_NOT_FOUND"; then
            # Check if no error occurred
            if ! echo "$WRITE_TEST" | grep -q "NT_STATUS"; then
                WRITE_ACCESS="YES"
            fi
        fi
    fi

    # Color output based on access
    if [ "$WRITE_ACCESS" == "YES" ]; then
        printf "%-30s ${GREEN}%-10s${NC} ${RED}%-10s${NC}\n" "$share" "$READ_ACCESS" "$WRITE_ACCESS"
    elif [ "$READ_ACCESS" == "YES" ]; then
        printf "%-30s ${GREEN}%-10s${NC} %-10s\n" "$share" "$READ_ACCESS" "$WRITE_ACCESS"
    else
        printf "%-30s %-10s %-10s\n" "$share" "$READ_ACCESS" "$WRITE_ACCESS"
    fi
done

echo ""
echo -e "${BLUE}[*] Enumeration complete${NC}"
