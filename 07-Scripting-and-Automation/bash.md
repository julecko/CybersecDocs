# Bash Scripting Commands Cheatsheet

**Bash** (Bourne Again Shell) is a powerful scripting language for automating tasks and managing systems. This guide covers essential Bash scripting commands for users who know the tool but need a quick reference. Always test scripts in a safe environment.

## Basic Usage
- **Create/Run Script**:  
  ```bash
  #!/bin/bash
  # Save as script.sh, then: chmod +x script.sh
  ./script.sh
  ```

- **Add Shebang**:  
  ```bash
  #!/bin/bash
  ```

- **Echo Output**:  
  ```bash
  echo "Hello, World!"
  ```

- **Comment Line**:  
  ```bash
  # This is a comment
  ```

- **Check Bash Version**:  
  ```bash
  bash --version
  ```

- **Debug Script** (show commands as executed):  
  ```bash
  bash -x script.sh
  ```

- **Exit Script with Status**:  
  ```bash
  exit 0  # 0 for success, non-zero for failure
  ```

## Variables
- **Declare Variable**:  
  ```bash
  name="value"
  ```

- **Access Variable**:  
  ```bash
  echo "$name"
  ```

- **Read User Input**:  
  ```bash
  read -p "Enter value: " input
  ```

- **Set Environment Variable**:  
  ```bash
  export MY_VAR="value"
  ```

- **Unset Variable**:  
  ```bash
  unset MY_VAR
  ```

- **Positional Parameters** (script arguments):  
  ```bash
  echo "$1"  # First argument
  echo "$@"  # All arguments
  echo "$#"  # Number of arguments
  ```

- **Default Value for Variable**:  
  ```bash
  echo "${VAR:-default}"  # Use default if VAR unset
  ```

## Control Structures
- **If Statement**:  
  ```bash
  if [ "$var" == "value" ]; then
    echo "Match"
  else
    echo "No match"
  fi
  ```

- **For Loop**:  
  ```bash
  for i in {1..5}; do
    echo "Number $i"
  done
  ```

- **While Loop**:  
  ```bash
  while [ "$count" -lt 5 ]; do
    echo "Count: $count"
    ((count++))
  done
  ```

- **Case Statement**:  
  ```bash
  case "$var" in
    "value1") echo "Option 1";;
    "value2") echo "Option 2";;
    *) echo "Default";;
  esac
  ```

- **Test Conditions**:  
  ```bash
  [ -f "file" ]  # File exists
  [ -d "dir" ]   # Directory exists
  [ "$a" -eq "$b" ]  # Equal numbers
  [ "$a" != "$b" ]   # Not equal strings
  ```

## File Operations
- **Create/Write to File**:  
  ```bash
  echo "Content" > file.txt  # Overwrite
  echo "Content" >> file.txt  # Append
  ```

- **Read File Line by Line**:  
  ```bash
  while IFS= read -r line; do
    echo "Line: $line"
  done < file.txt
  ```

- **Check File Existence**:  
  ```bash
  if [ -f "file.txt" ]; then
    echo "File exists"
  fi
  ```

- **Create Directory**:  
  ```bash
  mkdir mydir
  ```

- **Remove File/Directory**:  
  ```bash
  rm file.txt
  rm -r mydir
  ```

- **Copy File/Directory**:  
  ```bash
  cp source.txt dest.txt
  cp -r sourcedir destdir
  ```

## Text Processing
- **Grep for Pattern**:  
  Search for lines containing a pattern in a file.  
  ```bash
  grep "error" log.txt
  ```
  *Example*: For `log.txt` with:
  ```
  info: starting
  error: connection failed
  info: retrying
  ```
  Output: `error: connection failed`

- **Sed Replace**:  
  Replace text in a file or stream (use `-i` for in-place edit).  
  ```bash
  sed 's/old/new/g' file.txt
  ```
  *Example*: For `file.txt` with:
  ```
  hello world
  hello universe
  ```
  Command: `sed 's/hello/hi/g' file.txt`  
  Output:
  ```
  hi world
  hi universe
  ```

- **Awk Extract Field**:  
  Extract specific fields from delimited text.  
  ```bash
  awk '{print $1}' file.txt
  ```
  *Example*: For `file.txt` with:
  ```
  john doe 30
  jane smith 25
  ```
  Command: `awk '{print $1}' file.txt`  
  Output:
  ```
  john
  jane
  ```

- **Cut Field by Delimiter**:  
  Extract fields from text using a delimiter.  
  ```bash
  cut -d',' -f1 file.txt
  ```
  *Example*: For `file.txt` with:
  ```
  john,doe,30
  jane,smith,25
  ```
  Command: `cut -d',' -f1 file.txt`  
  Output:
  ```
  john
  jane
  ```

- **Sort Lines**:  
  Sort lines in a file alphabetically or numerically.  
  ```bash
  sort file.txt
  ```
  *Example*: For `file.txt` with:
  ```
  banana
  apple
  cherry
  ```
  Command: `sort file.txt`  
  Output:
  ```
  apple
  banana
  cherry
  ```

- **Count Lines/Words**:  
  Count lines, words, or characters in a file.  
  ```bash
  wc -l file.txt  # Lines
  wc -w file.txt  # Words
  ```
  *Example*: For `file.txt` with:
  ```
  hello world
  bash scripting
  ```
  Command: `wc -l file.txt`  
  Output: `2 file.txt`  
  Command: `wc -w file.txt`  
  Output: `4 file.txt`

## Advanced Options
- **Redirect Output**:  
  ```bash
  command > output.txt  # Standard output
  command 2> error.txt  # Error output
  ```

- **Pipe Commands**:  
  ```bash
  ls | grep ".txt"
  ```

- **Background Job**:  
  ```bash
  command &
  ```

- **Trap Signals**:  
  ```bash
  trap 'echo "Script interrupted"; exit' INT
  ```

- **Function Definition**:  
  ```bash
  my_function() {
    echo "Function called with $1"
  }
  my_function "arg"
  ```

- **Check Exit Status**:  
  ```bash
  command
  echo "$?"  # 0 for success, non-zero for failure
  ```

- **Arithmetic Operations**:  
  ```bash
  result=$((5 + 3))
  echo "$result"
  ```

- **Here Document**:  
  ```bash
  cat << EOF
  Multi-line
  text
  EOF
  ```

- **Run Command as Another User**:  
  ```bash
  sudo -u user command
  ```

- **Schedule Script with Cron**:  
  ```bash
  crontab -e
  # Add: * * * * * /path/to/script.sh
  ```

## Tips
- Always use double quotes around variables (`"$var"`) to handle empty values.
- Test conditions with `[ ]` require spaces around operators.
- Use `set -e` to exit on error, `set -u` to catch unset variables.
- Debug with `set -x` or `bash -x` to trace execution.
- Use `man bash` or `help` for detailed documentation.
- Test scripts in a non-production environment to avoid unintended changes.