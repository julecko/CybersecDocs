# Nmap Commands Cheat Sheet

**Nmap** (Network Mapper) is a powerful open-source tool for network scanning, discovery, and security auditing. This guide covers essential Nmap commands, including host discovery, port scanning, and evasion techniques. Always ensure you have permission to scan target networks or hosts.

## Basic Usage
- **Syntax**:  
  ```bash
  nmap [scan type] [options] <target>
  ```
  - `<target>`: IP address, hostname, or range (e.g., `192.168.1.0/24`).

- Scan a single host:  
  ```bash
  nmap 192.168.1.1
  ```

- Scan multiple hosts:  
  ```bash
  nmap 192.168.1.1,2,3
  ```

- Scan a subnet:  
  ```bash
  nmap 192.168.1.0/24
  ```

- Scan from a file:  
  ```bash
  nmap -iL targets.txt
  ```

- Save output to a file:  
  ```bash
  nmap -oN output.txt 192.168.1.1
  ```

## Scanning Modes

### Host Discovery
- **Ping Scan** (check if hosts are up, no port scanning):  
  ```bash
  nmap -sn 192.168.1.0/24
  ```

- **No Ping Scan** (skip host discovery, assume hosts are up):  
  ```bash
  nmap -Pn 192.168.1.1
  ```

- **ARP Scan** (discover hosts on local network):  
  ```bash
  nmap -PR 192.168.1.0/24
  ```

- **TCP SYN Ping** (use TCP SYN packets for discovery):  
  ```bash
  nmap -PS22,80,443 192.168.1.1
  ```

- **TCP ACK Ping** (use TCP ACK packets for discovery):  
  ```bash
  nmap -PA22,80,443 192.168.1.1
  ```

- **UDP Ping** (use UDP packets for discovery):  
  ```bash
  nmap -PU53,161 192.168.1.1
  ```

### Port Scanning
- **TCP SYN Scan** (stealth scan, no connection):  
  ```bash
  nmap -sS 192.168.1.1
  ```

- **TCP Connect Scan** (full TCP connection):  
  ```bash
  nmap -sT 192.168.1.1
  ```

- **UDP Scan** (scan UDP ports):  
  ```bash
  nmap -sU 192.168.1.1
  ```

- **Port Scan** (specify ports):  
  ```bash
  nmap -p 22,80,443 192.168.1.1
  ```

- **All Ports Scan** (scan all 65,535 ports):  
  ```bash
  nmap -p- 192.168.1.1
  ```

- **Service Version Detection** (identify services and versions):  
  ```bash
  nmap -sV 192.168.1.1
  ```

- **OS Detection** (identify operating system):  
  ```bash
  nmap -O 192.168.1.1
  ```

- **Aggressive Scan** (combines OS, version, script, traceroute):  
  ```bash
  nmap -A 192.168.1.1
  ```

## Evasion Techniques
- **Fragment Packets** (split packets to evade detection):  
  ```bash
  nmap -f 192.168.1.1
  ```

- **Decoy Scan** (use fake IPs to mask source):  
  ```bash
  nmap -D RND:10 192.168.1.1
  ```

- **Spoof Source IP**:  
  ```bash
  nmap -S <fake-ip> 192.168.1.1
  ```

- **Idle Scan** (use a zombie host to hide source):  
  ```bash
  nmap -sI <zombie-host> 192.168.1.1
  ```

- **Randomize Host Order**:  
  ```bash
  nmap --randomize-hosts 192.168.1.0/24
  ```

- **Custom Timing** (slow scan to avoid detection):  
  ```bash
  nmap -T2 192.168.1.1
  ```
  - Timing options: `-T0` (paranoid) to `-T5` (insane).

- **Source Port Spoofing**:  
  ```bash
  nmap --source-port 53 192.168.1.1
  ```

- **MTU Adjustment** (smaller packets):  
  ```bash
  nmap --mtu 24 192.168.1.1
  ```

## Advanced Options
- **Script Scanning** (use NSE scripts):  
  ```bash
  nmap --script default 192.168.1.1
  ```

- **Specific Script**:  
  ```bash
  nmap --script http-title 192.168.1.1
  ```

- **Traceroute**:  
  ```bash
  nmap --traceroute 192.168.1.1
  ```

- **Verbose Output**:  
  ```bash
  nmap -v 192.168.1.1
  ```

- **Disable DNS Resolution**:  
  ```bash
  nmap -n 192.168.1.1
  ```

- **Scan for Specific Protocols**:  
  ```bash
  nmap -sO 192.168.1.1
  ```

## Output Formats
- **Normal Output**:  
  ```bash
  nmap -oN output.txt 192.168.1.1
  ```

- **XML Output**:  
  ```bash
  nmap -oX output.xml 192.168.1.1
  ```

- **Grepable Output**:  
  ```bash
  nmap -oG output.grep 192.168.1.1
  ```

- **All Formats**:  
  ```bash
  nmap -oA output 192.168.1.1
  ```

## Tips
- Always use `sudo` for scans requiring root privileges (e.g., SYN scan, OS detection).
- Check Nmap scripts: `/usr/share/nmap/scripts/`.
- Combine options for custom scans:  
  ```bash
  nmap -sV -sC -p- -oN scan.txt <target>
  ```
- Use `--reason` to see why ports are reported as open/closed.