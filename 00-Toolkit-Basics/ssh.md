# SSH Usage Guide

This guide covers the basics of using SSH (Secure Shell) to connect to remote servers, including common options and their usage.

## What is SSH?

SSH is a cryptographic network protocol for secure communication over an unsecured network. It is commonly used for remote command-line login and file transfer.

## Basic SSH Command

The basic syntax for SSH is:

    ssh [options] [user@]hostname [command]

### Common SSH Options

- `-i <identity_file>`: Specifies the private key file for authentication.
  - Example: `ssh -i ~/.ssh/id_rsa user@hostname`
- `-p <port>`: Specifies the port to connect to on the remote host (default is 22).
  - Example: `ssh -p 2222 user@hostname`
- `-l <login_name>`: Specifies the username to log in as.
  - Example: `ssh -l user hostname`
- `-o <option>`: Sets configuration options (e.g., `StrictHostKeyChecking=no`).
  - Example: `ssh -o StrictHostKeyChecking=no user@hostname`
- `-X`: Enables X11 forwarding for graphical applications.
  - Example: `ssh -X user@hostname`
- `-L <local_port:remote_host:remote_port>`: Sets up local port forwarding.
  - Example: `ssh -L 8080:localhost:80 user@hostname`
- `-R <remote_port:local_host:local_port>`: Sets up remote port forwarding.
  - Example: `ssh -R 9000:localhost:3000 user@hostname`
- `-D <port>`: Sets up dynamic port forwarding (SOCKS proxy).
  - Example: `ssh -D 1080 user@hostname`
- `-v`: Verbose mode, useful for debugging.
  - Example: `ssh -v user@hostname`
- `-A`: Enables agent forwarding for SSH agent.
  - Example: `ssh -A user@hostname`
- `-t`: Forces pseudo-terminal allocation (useful for running interactive commands).
  - Example: `ssh -t user@hostname bash`

## SSH Configuration File

You can store SSH settings in `~/.ssh/config` to simplify connections:

    Host alias
        HostName hostname
        User username
        Port 2222
        IdentityFile ~/.ssh/id_rsa

Then connect using: `ssh alias`

## File Permissions for SSH

- **Private key** (`~/.ssh/id_rsa`): Must have permissions set to `600` (read/write for owner only).
  - Set with: `chmod 600 ~/.ssh/id_rsa`
- **Public key** (`~/.ssh/id_rsa.pub`): Can have permissions set to `644` (read/write for owner, read for others).
  - Set with: `chmod 644 ~/.ssh/id_rsa.pub`
- **SSH config file** (`~/.ssh/config`): Must have permissions set to `600`.
  - Set with: `chmod 600 ~/.ssh/config`
- **Authorized keys file** (`~/.ssh/authorized_keys`): Must have permissions set to `600`.
  - Set with: `chmod 600 ~/.ssh/authorized_keys`
- **SSH directory** (`~/.ssh/`): Must have permissions set to `700` (read/write/execute for owner only).
  - Set with: `chmod 700 ~/.ssh`

## Example Usage

1. **Connect to a remote server**:
   ```bash
   ssh user@192.168.1.100
   ```
2. **Copy files using SCP**:
   ```bash
   scp -i ~/.ssh/id_rsa file.txt user@hostname:/path/to/destination
   ```
3. **Run a command remotely**:
   ```bash
   ssh user@hostname "ls -la"
   ```

## Troubleshooting

- Use `-v`, `-vv`, or `-vvv` for increasing levels of verbosity to debug connection issues.
- Check file permissions if authentication fails.
- Ensure the remote host’s SSH service is running and the port is open.