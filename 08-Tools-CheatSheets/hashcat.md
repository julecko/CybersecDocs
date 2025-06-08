# Hashcat Command Cheatsheet

Hashcat is a powerful password cracking tool supporting multiple attack modes for recovering passwords from hashes.

## Basic Command Structure
```bash
hashcat -m <mode> -a <attack> hash.txt wordlist.txt
```
- `-m <mode>`: Specify hash type (e.g., 0 for MD5, 100 for SHA1).
- `-a <attack>`: Attack mode (see below).
- `hash.txt`: File with target hash(es).
- `wordlist.txt`: File with potential passwords.

## Attack Mode 0: Straight (Wordlist)
Crack using a wordlist directly.
```bash
hashcat -m 0 -a 0 hash.txt wordlist.txt
```
- `-a 0`: Straight mode; tests each word from the list.
- Good for common or leaked passwords.

## Attack Mode 1: Combination
Combine words from two wordlists.
```bash
hashcat -m 0 -a 1 hash.txt wordlist1.txt wordlist2.txt
```
- `-a 1`: Combination mode; merges words (e.g., "pass" + "word" = "password").
- Useful for patterns like "word1word2".

## Attack Mode 3: Brute-Force (Mask)
Test all combinations within a mask.
```bash
hashcat -m 0 -a 3 hash.txt ?l?l?l?l
```
- `-a 3`: Brute-force mode; tries all possibilities for a mask.
- `?l?l?l?l`: Mask for 4 lowercase letters (e.g., ?l = a-z, ?u = A-Z, ?d = 0-9, ?s = symbols).

## Mask Creation
Define custom masks for brute-force or hybrid attacks.
```bash
hashcat -m 0 -a 3 hash.txt -1 abc123 -2 !@# ?1?1?2?d
```
- `-1 abc123`: Define custom charset 1 (e.g., letters a,b,c and digits 1,2,3).
- `-2 !@#`: Define custom charset 2 (e.g., symbols !,@,#).
- `?1?1?2?d`: Mask using custom sets (?1 = a,b,c,1,2,3; ?2 = !,@,#; ?d = 0-9).
- Built-in masks: ?l (lowercase), ?u (uppercase), ?d (digits), ?s (symbols), ?a (all).
- Example: "ab!5", "ca#9", etc.

## Attack Mode 6: Hybrid (Wordlist + Mask)
Combine wordlist with masks.
```bash
hashcat -m 0 -a 6 hash.txt wordlist.txt ?d?d
```
- `-a 6`: Hybrid mode; appends mask to each word (e.g., "pass" + "?d?d" = "pass12").
- Tests wordlist with added digits, symbols, etc.

## Attack Mode 7: Hybrid (Mask + Wordlist)
Prepend mask to wordlist entries.
```bash
hashcat -m 0 -a 7 hash.txt ?d?d wordlist.txt
```
- `-a 7`: Hybrid mode; prepends mask to each word (e.g., "?d?d" + "pass" = "12pass").
- Useful for prefixes like years or numbers.

## Rule-Based Attack
Apply rules to transform wordlist entries.
```bash
hashcat -m 0 -a 0 hash.txt wordlist.txt -r rules.txt
```
- `-a 0`: Straight mode with rules.
- `-r rules.txt`: File with rules (e.g., "p1" appends "1", "s$@e" replaces "$" with "@").
- Enhances wordlist with variations (e.g., "pass" -> "pass1", "p@ss").

## Common Options
- `-o output.txt`: Save cracked passwords to file.
- `--increment`: Test masks incrementally (e.g., ?l, ?l?l, ?l?l?l).
- `-w 3`: Workload profile (3 = high performance, GPU-intensive).
- `--potfile-disable`: Disable potfile (no caching of cracked hashes).

## Hash Type Examples
- `-m 0`: MD5
- `-m 100`: SHA1
- `-m 1000`: NTLM
- `-m 3200`: bcrypt
- `-m 1800`: SHA-512 (Unix)
- Full list: `hashcat --help` or online docs.

## Tips
- Use `-O` for optimized kernels (faster for some hashes).
- Check GPU support: `hashcat -I` (lists devices).
- Get wordlists: SecLists, RockYou, etc.
- Always have permission; cracking without consent is illegal.