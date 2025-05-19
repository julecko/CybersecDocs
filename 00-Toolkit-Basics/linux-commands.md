
# Standard Linux Commands Cheatsheet

A reference to commonly used Linux commands with explanations and examples. This is aimed at helping you gain full control over the system—useful in system administration, penetration testing, and scripting.

---

## Filesystem Navigation

### `pwd` – Print Working Directory
Displays the absolute path of your current directory.
```bash
pwd
```

### `cd` – Change Directory
Navigate between directories in the filesystem.
```bash
cd /path/to/dir    # Go to specific path
cd ~               # Go to home directory
cd ..              # Go up one directory
cd -               # Switch to previous directory
```

### `ls` – List Directory Contents
Lists files and directories.
```bash
ls                 # basic listing
ls -l              # long listing with permissions and timestamps
ls -a              # show hidden files (starting with .)
ls -lh             # human-readable sizes
```

---

## File Manipulation

### `cat` – Concatenate and Display Files
Reads and outputs file content.
```bash
cat file.txt
cat file1 file2 > combined.txt   # merge files
```

### `echo` – Display Text or Variables
Prints text or values of variables. Also used to write to files.
```bash
echo "Hello World"            # print to terminal
echo "Hello" > file.txt       # write to file (overwrite)
echo "More" >> file.txt       # append to file
```

### `head` / `tail` – View Start/End of File
See the beginning or end of files.
```bash
head -n 10 file.txt           # first 10 lines
tail -n 20 file.txt           # last 20 lines
tail -f logfile.log           # live updates as file changes
```

### `touch` – Create Empty Files or Update Timestamps
```bash
touch file.txt                # create file or update modified time
```

### `cp`, `mv`, `rm` – Copy, Move, and Delete Files
```bash
cp file.txt /backup/         # copy file
mv file.txt /archive/        # move or rename
rm file.txt                  # delete file
rm -r folder/                # delete folder recursively
```

---

## Searching and Filtering

### `grep` – Search Text in Files
Looks for matching patterns using regex or plain strings.
```bash
grep "error" logfile.log
grep -r "admin" /etc          # recursive search
```

### `find` – Locate Files by Attributes
Searches directories for files with various filters.
```bash
find /var -name "*.log"       # find log files
find . -type f -mtime -1      # modified in last 1 day
```

### `awk` – Pattern Scanning and Processing
Extracts and processes fields from text.
```bash
awk '{print $1}' file.txt         # print first column
awk -F: '{print $1}' /etc/passwd  # split by colon
```

### `cut` – Remove Sections from Each Line
Cuts columns from input.
```bash
cut -d ':' -f 1 /etc/passwd       # first field using : delimiter
```

### `sort`, `uniq`, `wc`
```bash
sort file.txt | uniq -c          # count unique lines
wc -l file.txt                   # count lines
wc -w file.txt                   # count words
```

---

## Process and Service Management

### `ps` – View Running Processes
Lists running processes with details.
```bash
ps aux | grep ssh                # show ssh processes
```

### `top` / `htop` – Real-Time Process Monitor
Monitors CPU and memory usage live.
```bash
top                             # built-in
htop                            # better, requires installation
```

### `kill` / `killall` – Terminate Processes
Sends signals to processes.
```bash
kill 1234                       # kill by PID
killall firefox                 # kill all firefox processes
```

---

## Services with systemctl

### `systemctl` – Control Systemd Services
Used to start, stop, enable, and inspect services.
```bash
systemctl status nginx          # check status
systemctl start nginx           # start now
systemctl stop nginx            # stop now
systemctl restart nginx         # restart service
systemctl enable nginx          # start on boot
systemctl disable nginx         # disable auto-start
```

### `service` – Legacy Service Management
```bash
service apache2 status
service apache2 restart
```

---

## Networking Basics

### `ip`, `ifconfig` – Show Network Interfaces
```bash
ip a                            # show addresses
ifconfig                        # older command, still used
```

### `ping`, `traceroute`, `netstat`, `ss`
```bash
ping 8.8.8.8                    # test reachability
traceroute example.com          # path to host
netstat -tuln                   # list ports (older)
ss -tulnp                       # modern replacement for netstat
```

---

## Disk and Permissions

### `df`, `du` – Disk Space
```bash
df -h                           # space usage of mounted disks
du -sh *                        # size of folders/files
```

### `chmod`, `chown` – Permissions
```bash
chmod +x script.sh              # make executable
chmod 644 file.txt              # rw-r--r--
chown user:group file.txt       # change ownership
```

---

## Miscellaneous

### `history` – View Command History
```bash
history | grep ssh              # filter history for ssh
```

### `alias` – Create Command Shortcuts
```bash
alias ll='ls -alF'              # quick list command
```

### `man` – Read Manual Pages
```bash
man grep                        # learn about grep
```

---

## Pro Tips

- Chain commands with `&&` or `||`:
  ```bash
  mkdir logs && cd logs         # if mkdir succeeds, go to dir
  ```

- Use pipes (`|`) to pass output to another command:
  ```bash
  cat logs.txt | grep "error" | sort | uniq
  ```

- Use `xargs` to act on input lines:
  ```bash
  cat urls.txt | xargs curl -O
  ```
