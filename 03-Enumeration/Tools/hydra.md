# Hydra Commands Cheatsheet

**Hydra** is a password-cracking tool used for brute-forcing credentials across various protocols. This guide provides essential Hydra commands for users familiar with the tool, serving as a quick reference. Always ensure you have explicit permission to test target systems.

## Basic Usage
- **Launch Hydra with Help**:  
  ```bash
  hydra -h
  ```

- **Check Version**:  
  ```bash
  hydra -V
  ```

## Password Cracking
- **Basic Syntax**:  
  ```bash
  hydra [options] <target> <service>
  ```

- **Single Username and Password**:  
  ```bash
  hydra -l <username> -p <password> <target> <service>
  ```

- **Username List and Password List**:  
  ```bash
  hydra -L <userlist> -P <passlist> <target> <service>
  ```

- **Single Username with Password List**:  
  ```bash
  hydra -l <username> -P <passlist> <target> <service>
  ```

- **Single Password with Username List**:  
  ```bash
  hydra -L <userlist> -p <password> <target> <service>
  ```

- **Specify Target Port**:  
  ```bash
  hydra -s <port> <target> <service>
  ```

- **Use SSL**:  
  ```bash
  hydra -S <target> <service>
  ```

- **Verbose Output**:  
  ```bash
  hydra -v <target> <service>
  ```

- **Debug Mode**:  
  ```bash
  hydra -d <target> <service>
  ```

- **Save Output to File**:  
  ```bash
  hydra -o <output_file> <target> <service>
  ```

- **Resume Previous Session**:  
  ```bash
  hydra -R
  ```

- **Set Number of Tasks/Threads** (default: 16):  
  ```bash
  hydra -t <number> <target> <service>
  ```

- **Set Timeout** (seconds):  
  ```bash
  hydra -T <seconds> <target> <service>
  ```

## Common Services
- **SSH Example**:  
  ```bash
  hydra -L users.txt -P passwords.txt ssh://<target>
  ```

- **FTP Example**:  
  ```bash
  hydra -l admin -P passwords.txt ftp://<target>
  ```

- **HTTP Form POST Example**:  
  ```bash
  hydra -L users.txt -P passwords.txt <target> http-post-form "/login:username=^USER^&password=^PASS^:F=incorrect"
  ```

- **HTTP Form GET Example**:  
  ```bash
  hydra -L users.txt -P passwords.txt <target> http-get-form "/login?username=^USER^&password=^PASS^:F=incorrect"
  ```

- **RDP Example**:  
  ```bash
  hydra -L users.txt -P passwords.txt rdp://<target>
  ```

- **SMB Example**:  
  ```bash
  hydra -L users.txt -P passwords.txt smb://<target>
  ```

- **MySQL Example**:  
  ```bash
  hydra -l root -P passwords.txt mysql://<target>
  ```

## Advanced Options
- **Custom Module Path**:  
  ```bash
  hydra -M <module_path> <target> <service>
  ```

- **Proxy Support**:  
  ```bash
  hydra -X <proxy> <target> <service>
  ```

- **Ignore SSL Certificate**:  
  ```bash
  hydra -I <target> <service>
  ```

- **Custom Header for HTTP**:  
  ```bash
  hydra -H "Header: Value" <target> http-post-form
  ```

- **Combination Attack** (combine username/password):  
  ```bash
  hydra -C <combo_list> <target> <service>
  ```

- **Exit After First Found Credential**:  
  ```bash
  hydra -f <target> <service>
  ```

## Supported Services
- Common protocols: `ssh`, `ftp`, `telnet`, `http-get`, `http-post-form`, `http-get-form`, `https-get`, `https-post-form`, `rdp`, `smb`, `mysql`, `postgres`, `pop3`, `imap`, `smtp`, `vnc`, `ldap`, `mssql`, `oracle`, `redis`, etc.
- List all supported modules:  
  ```bash
  hydra -U <service>
  ```

## Updating Hydra
- **Update on Debian-based Systems**:  
  ```bash
  sudo apt update && sudo apt install hydra
  ```

- **Update on Kali Linux**:  
  ```bash
  sudo apt update && sudo apt install hydra-gtk
  ```

## Tips
- Use `-v` for verbose output to troubleshoot issues.
- Test on authorized systems only (e.g., your own servers or lab environments).
- Combine with tools like Nmap to identify open services:  
  ```bash
  nmap -sV <target> -oN scan.txt
  ```
- Optimize performance by adjusting `-t` (threads) based on target responsiveness.
- For HTTP forms, inspect the login page source to identify correct field names for `http-post-form` or `http-get-form`.
- Use strong wordlists like `rockyou.txt` or custom-generated lists for better results.
- Check service-specific options with `hydra -U <service>`.