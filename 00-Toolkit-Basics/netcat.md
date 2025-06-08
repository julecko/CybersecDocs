# Netcat Command Cheatsheet

Netcat (`nc`) is a versatile networking tool for connecting, listening, and transferring data.

## Basic Connection
Connect to a remote host and port.
```bash
nc -n -v example.com 80
```
- `-n`: No DNS lookup; use IP addresses only (faster, no hostname resolution).
- `-v`: Verbose output for connection details.

## Listening Mode
Listen for incoming connections on a port.
```bash
nc -n -l -p 1234
```
- `-n`: No DNS lookup; use IP addresses only.
- `-l`: Listen mode.
- `-p 1234`: Specify port (e.g., 1234).

## Port Scanning
Scan a host for open ports.
```bash
nc -n -v -z example.com 20-80
```
- `-n`: No DNS lookup; use IP addresses only.
- `-v`: Verbose output for connection details.
- `-z`: Zero-I/O mode (scan without sending data).
- `20-80`: Port range to scan.

## File Transfer (Sender)
Send a file to a remote host.
```bash
nc -n -v example.com 1234 < file.txt
```
- `-n`: No DNS lookup; use IP addresses only.
- `-v`: Verbose output for connection details.

## File Transfer (Receiver)
Listen and save incoming file.
```bash
nc -n -l -p 1234 > output.txt
```
- `-n`: No DNS lookup; use IP addresses only.
- `-l`: Listen mode.
- `-p 1234`: Specify port (e.g., 1234).

## Simple TCP Server
Listen and respond to incoming connections.
```bash
nc -n -l -p 1234 -e /bin/bash
```
- `-n`: No DNS lookup; use IP addresses only.
- `-l`: Listen mode.
- `-p 1234`: Specify port (e.g., 1234).
- `-e /bin/bash`: Execute a program (e.g., shell) on connection.
- **Caution**: Use with care; exposes system.

## Simple Chat
Host a basic chat server.
```bash
nc -n -l -p 1234
```
- `-n`: No DNS lookup; use IP addresses only.
- `-l`: Listen mode.
- `-p 1234`: Specify port (e.g., 1234).
- Client connects: `nc -n example.com 1234`
- Type to send messages back and forth.

## UDP Mode
Connect or listen using UDP instead of TCP.
```bash
nc -n -u example.com 53
```
- `-n`: No DNS lookup; use IP addresses only.
- `-u`: Use UDP protocol.
- Listen: `nc -n -u -l -p 1234`

## Banner Grabbing
Grab service banners for info.
```bash
echo "" | nc -n -v example.com 22
```
- `-n`: No DNS lookup; use IP addresses only.
- `-v`: Verbose output for connection details.
- Send empty line to get response (e.g., SSH banner).

## Timeout Control
Set a timeout for connections.
```bash
nc -n -w 5 example.com 80
```
- `-n`: No DNS lookup; use IP addresses only.
- `-w 5`: Wait 5 seconds before timing out.

## Tips
- Use `-n` to skip DNS resolution for faster connections or when DNS is unavailable.
- Use `-k` with `-l` to keep server listening after disconnect.
- Combine with `echo` or scripts for automation.
- Test connectivity: `nc -n -zv example.com 80`.
- Use responsibly; get permission for scanning or testing.