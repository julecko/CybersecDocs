# SQL General Commands Cheatsheet

Enumerating SQL services (MySQL on port 3306, MSSQL on ports 1433, 2433).

## 1. Enumerate SQL Service and Version (nmap)
Gather SQL service and version information for MySQL and MSSQL.
```bash
nmap -Pn -sV -sC -p1433,3306,2433 target.com
```
- `-Pn`: Skips host discovery.
- `-sV`: Detects service and version.
- `-sC`: Runs default scripts (e.g., `ms-sql-info`).