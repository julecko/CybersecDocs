# DNS Enumeration Cheatsheet

Quick reference for enumerating DNS (ports 53 TCP/UDP) services. Replace `target.com` with the target domain, `wordlist.txt` with your wordlist, and adjust as needed. Always obtain permission before enumerating.

## 1. Enumerate DNS Service and Version (nmap)
Gather DNS service and version information.
```
nmap -p53 -Pn -sV -sC target.com
```
- `-p53`: Scans port 53 (TCP/UDP).
- `-Pn`: Skips host discovery.
- `-sV`: Detects service and version.
- `-sC`: Runs default scripts (e.g., DNS-related).

## 2. Perform DNS Zone Transfer (dig)
Attempt to dump DNS zone data.
```
dig AXFR @ns1.target.com target.com
```
- `AXFR`: Requests full zone transfer.
- `@ns1.target.com`: Specifies the target name server.

## 3. Enumerate DNS Servers and Zone Transfer (fierce)
Scan for DNS servers and attempt zone transfers.
```
fierce --domain target.com
```
- `--domain`: Specifies the target domain.
- Checks for misconfigured servers allowing zone transfers.

## 4. Subdomain Enumeration (subfinder)
Discover subdomains using open sources.
```
subfinder -d target.com -v
```
- `-d`: Specifies the target domain.
- `-v`: Verbose output to show sources (e.g., DNSdumpster).

## 5. Brute-Force Subdomains (subbrute)
Perform DNS brute-forcing for subdomains.
```
subbrute target.com -s wordlist.txt -r resolvers.txt
```
- `-s wordlist.txt`: Subdomain wordlist.
- `-r resolvers.txt`: Custom DNS resolvers for internal networks.

## 6. Check CNAME Records (host)
Enumerate CNAME records for a subdomain.
```
host subdomain.target.com
```
- Resolves the domain and checks for aliases (e.g., pointing to AWS, CDNs).

## 7. DNS Spoofing Setup (ettercap)
Spoof DNS responses via MITM (edit `/etc/ettercap/etter.dns` first).
```
# Edit /etc/ettercap/etter.dns
target.com      A   192.168.1.100
*.target.com    A   192.168.1.100
```
- Then run Ettercap:
```
ettercap -T -P dns_spoof -M arp /192.168.1.2/ /192.168.1.129/
```
- `-T`: Text interface.
- `-P dns_spoof`: Activates DNS spoofing plugin.
- `-M arp`: Performs ARP poisoning for MITM.
- Redirects `target.com` to attacker IP (e.g., 192.168.1.100).

## 8. Verify DNS Spoofing (ping)
Test if DNS spoofing redirects to the fake IP.
```
ping target.com
```
- Check if the resolved IP matches the attacker’s IP (e.g., 192.168.1.100).

## Tips
- Use SecLists or custom wordlists for subdomain brute-forcing.
- Check for misconfigurations (e.g., open zone transfers, dangling CNAMEs).
- Be cautious with DNS spoofing; requires network access and MITM setup.
- Reference `can-i-take-over-xyz` repo for subdomain takeover checks.