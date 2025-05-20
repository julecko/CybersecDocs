# SMB Enumeration Cheatsheet

Quick reference for enumerating SMB services (ports 139, 445) using enumeration-focused commands. Replace `192.168.1.100` with the target host, `wordlist.txt` with your wordlist. Always obtain permission before enumerating.

## 1. Enumerate SMB Shares and Info (nmap)
Gather detailed SMB information.
```bash
nmap -p 139,445 --script smb-enum-shares,smb-os-discovery,smb-enum-users 192.168.1.100
```
- `--script smb-enum-shares,smb-os-discovery,smb-enum-users`: Enumerates shares, OS details, and users.

## 2. List SMB Shares (smbclient)
View accessible shares without authentication.
```bash
smbclient -L //192.168.1.100 -N
```
- `-L`: Lists shares.
- `-N`: Attempts anonymous access (no credentials).

## 3. Connect to SMB Share (smbclient)
Access a specific SMB share.
```bash
smbclient //192.168.1.100/share_name -U user%password
```
- `-U user%password`: Specifies username and password.
- Use `-N` for anonymous if no credentials.

## 4. Enumerate SMB Users and Shares (enum4linux)
Extract users, shares, and other SMB details.
```bash
enum4linux -a 192.168.1.100
```
- `-a`: Performs all enumeration tasks (users, shares, groups, etc.).

## 5. Brute-Force SMB Credentials (hydra)
Attempt SMB password brute-forcing.
```bash
hydra -L users.txt -P passwords.txt smb://192.168.1.100
```
- `-L users.txt`: Username wordlist.
- `-P passwords.txt`: Password wordlist.

## 6. Check Null Session (smbclient)
Test for null session access (anonymous, no password).
```bash
smbclient //192.168.1.100/IPC$ -N
```
- `IPC$`: Common share for null session testing.

## 7. Download Files from SMB Share
Retrieve files from an accessible share.
```bash
smbclient //192.168.1.100/share_name -U user%password -c "get filename"
```
- `-c "get filename"`: Downloads the specified file.

## 8. Upload Files to SMB Share
Test write permissions by uploading files.
```bash
smbclient //192.168.1.100/share_name -U user%password -c "put localfile"
```
- `-c "put localfile"`: Uploads the specified file.

## Tips
- Use SecLists for `users.txt` and `passwords.txt`.
- Check for misconfigurations like null sessions or guest access.