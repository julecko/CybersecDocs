# Certificates Usage Guide

This guide explains how to create SSH certificates, use them with services like SSH, SFTP, and Git, and set appropriate file permissions.

## Creating SSH Certificates

SSH certificates are used to authenticate users or hosts without relying solely on public/private key pairs. They are signed by a Certificate Authority (CA).

### Steps to Create SSH Certificates

1. **Generate a CA Key**:
   ```bash
   ssh-keygen -t rsa -f ssh_ca -C "SSH CA"
   ```
   This creates `ssh_ca` (private key) and `ssh_ca.pub` (public key).
a
2. **Generate a User Key Pair**:
   ```bash
   ssh-keygen -t rsa -f id_user -C "user@hostname"
   ```

3. **Sign the User Public Key with the CA**:
   ```bash
   ssh-keygen -s ssh_ca -I user_id -n user -V +1w id_user.pub
   ```
   - `-s ssh_ca`: Specifies the CA private key.
   - `-I user_id`: Sets the certificate identity.
   - `-n user`: Specifies the principal (username).
   - `-V +1w`: Sets validity for one week.
   This creates `id_user-cert.pub`.

4. **Configure the SSH Server**:
   Add the CA public key to the server’s `/etc/ssh/sshd_config`:
   ```
   TrustedUserCAKeys /etc/ssh/ssh_ca.pub
   ```
   Restart the SSH service:
   ```bash
   sudo systemctl restart sshd
   ```

5. **Add Certificate to SSH Agent**:
   ```bash
   ssh-add id_user
   ```

## Using Certificates with SSH

- Connect using the certificate:
  ```bash
  ssh -i id_user user@hostname
  ```
- The server verifies the certificate against the CA’s public key.

## Using Certificates with SFTP

SFTP uses the same authentication as SSH:
```bash
sftp -i id_user user@hostname
```
The certificate (`id_user-cert.pub`) is used automatically if loaded in the SSH agent.

## Using Certificates with Git

To use SSH certificates with Git (e.g., GitHub, GitLab):

1. **Configure Git to Use SSH**:
   Ensure your `.gitconfig` uses SSH URLs:
   ```bash
   git config --global url.ssh://git@github.com/.insteadOf https://github.com/
   ```

2. **Add the Certificate to SSH Agent**:
   ```bash
   ssh-add id_user
   ```

3. **Clone or Push to Repositories**:
   ```bash
   git clone ssh://git@github.com/username/repo.git
   git push origin main
   ```
   The SSH certificate is used for authentication if the server supports it.

## Using Certificates with Other Services

Services like Rsync or SCP can also use SSH certificates:
- **Rsync**:
  ```bash
  rsync -e "ssh -i id_user" source user@hostname:destination
  ```
- **SCP**:
  ```bash
  scp -i id_user file.txt user@hostname:/path
  ```

## File Permissions for Certificates

- **CA Private Key** (`ssh_ca`): Must have permissions set to `600` (read/write for owner only).
  - Set with: `chmod 600 ssh_ca`
- **CA Public Key** (`ssh_ca.pub`): Can have permissions set to `644`.
  - Set with: `chmod 644 ssh_ca.pub`
- **User Private Key** (`id_user`): Must have permissions set to `600`.
  - Set with: `chmod 600 id_user`
- **User Public Key** (`id_user.pub`): Can have permissions set to `644`.
  - Set with: `chmod 644 id_user.pub`
- **Certificate File** (`id_user-cert.pub`): Must have permissions set to `644`.
  - Set with: `chmod 644 id_user-cert.pub`
- **SSH Directory** (`~/.ssh/`): Must have permissions set to `700`.
  - Set with: `chmod 700 ~/.ssh`

## Best Practices

- **Secure the CA Key**: Store the CA private key in a secure location, as it can sign certificates for any user.
- **Set Certificate Expiry**: Use `-V` to limit certificate validity (e.g., `+1w` for one week).
- **Backup Keys**: Regularly back up private keys and certificates securely.
- **Test Authentication**: Verify certificate-based authentication works before deploying to production.

## Troubleshooting

- Ensure the SSH server has the correct `TrustedUserCAKeys` setting.
- Check certificate validity with:
  ```bash
  ssh-keygen -L -f id_user-cert.pub
  ```
- Verify file permissions if authentication fails.
- Use `ssh -v` to debug connection issues.