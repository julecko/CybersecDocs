# FTP/SFTP Enumeration Cheatsheet

Quick reference for enumerating FTP (port 21) and SFTP (port 22) services. Replace `target.com` with the target host, `wordlist.txt` with your wordlist, and adjust ports as needed. Always obtain permission before enumerating.

## 1. Enumerate FTP Version and Scripts (nmap)
Gather detailed FTP service information.
```bash
nmap -sV -p 21 --script ftp* target.com
```
- `--script ftp*`: Runs FTP-related scripts (e.g., `ftp-anon`, `ftp-banner`).

## 2. Check Anonymous FTP Login
Test for anonymous FTP access.
```bash
ftp target.com
```
- At prompt: Use `anonymous` as username, blank or `guest` as password.
- **Alternative (curl)**:
```bash
curl ftp://target.com --user anonymous:guest
```

## 3. Connect to SFTP
Test SFTP connectivity.
```bash
sftp user@target.com
```
- Replace `user` with a known username or try `anonymous`.
- Requires valid credentials or key-based authentication.

## 4. Brute-Force FTP Credentials (hydra)
Attempt FTP password brute-forcing.
```bash
hydra -L users.txt -P passwords.txt ftp://target.com
```
- `-L users.txt`: Username wordlist.
- `-P passwords.txt`: Password wordlist.

## 5. Brute-Force SFTP Credentials (hydra)
Attempt SFTP password brute-forcing.
```bash
hydra -L users.txt -P passwords.txt sftp://target.com
```
- Use SSH/SFTP wordlists for usernames and passwords.

## 6. Enumerate FTP Directory Listing
List files in FTP directory (if authenticated).
```bash
ftp target.com
> dir
```
- **Alternative (curl)**:
```bash
curl ftp://target.com/ --user user:pass
```

## 7. Download Files from FTP
Retrieve files from FTP server.
```bash
ftp target.com
> get filename
```
- **Alternative (curl)**:
```bash
curl ftp://target.com/filename --user user:pass -o filename
```

## 8. Upload Files to FTP
Test write permissions by uploading files.
```bash
ftp target.com
> put localfile
```
- **Alternative (curl)**:
```bash
curl -T localfile ftp://target.com/ --user user:pass
```

## 9. Check SFTP Directory Listing
List files in SFTP directory.
```bash
sftp user@target.com
> ls
```

## Tips
- Use SecLists for `users.txt` and `passwords.txt`.
- Check for weak credentials or misconfigurations (e.gs., anonymous access).