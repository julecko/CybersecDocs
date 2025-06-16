# Ffuf Command Cheatsheet

Fuzzing websites with `ffuf`.

## Directory Fuzzing
Discover hidden directories.
```bash
ffuf -w wordlist.txt -u http://example.com/FUZZ
```

## Page Fuzzing
Find hidden pages in a directory.
```bash
ffuf -w pages.txt -u http://example.com/FUZZ
```

## Extension Fuzzing
Fuzz files with different extensions.
```bash
ffuf -w filenames.txt -e .php,.html,.txt,.bak -u http://example.com/FUZZ
```

## Recursive Fuzzing
Fuzz subdirectories recursively.
```bash
ffuf -w wordlist.txt -u http://example.com/FUZZ -recursion
```

## DNS Fuzzing
Discover subdomains.
```bash
ffuf -w subdomains.txt -u http://FUZZ.example.com
```

## VHost Fuzzing
Fuzz virtual hosts via the `Host` header.
```bash
ffuf -w vhosts.txt -u http://example.com -H "Host: FUZZ.example.com"
```

## Filtering
Reduce noise with response filters.
```bash
ffuf -w wordlist.txt -u http://example.com/FUZZ -fc 404 -fs 1234 -fw 50
```
- `-fc 404`: Filter status code 404.
- `-fs 1234`: Filter response size (1234 bytes).
- `-fw 50`: Filter word count (50 words).

## Parameter Fuzzing (GET)
Fuzz query parameters in GET requests.
```bash
ffuf -w params.txt -u http://example.com/?FUZZ=test
```

## Parameter Fuzzing (POST)
Fuzz parameters in POST requests.
```bash
ffuf -w params.txt -u http://example.com/ -X POST -d "FUZZ=test" -H "Content-Type: application/x-www-form-urlencoded"
```

## Tips
- Use `-t 50` to adjust threads for speed.
- Save results: `-o output.json`.
- Use SecLists for wordlists.
- Always fuzz with permission.