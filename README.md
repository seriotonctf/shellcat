# ShellCat

ShellCat is a python tool for generating reverse shell payloads. It supports a variety of shell types, including bash, python, php, nc, and more. It also provides options for URL encoding, Base64 encoding, writing the payload to a file, and copying the payload to the clipboard.

## Installation

Clone the repository:

```bash
git clone https://github.com/seriotonctf/shellcat.git
```

Navigate to the shellcat directory:

```bash
cd shellcat
```

Install the required Python packages:

```bash
pip install -r requirements.txt
```

## Usage

```bash
python3 shellcat.py <shell_type> <ip> <port> [options]
```

```bash
   _____ _          _ _  _____      _   
  / ____| |        | | |/ ____|    | |  
 | (___ | |__   ___| | | |     __ _| |_ 
  \___ \| '_ \ / _ \ | | |    / _` | __|
  ____) | | | |  __/ | | |___| (_| | |_ 
 |_____/|_| |_|\___|_|_|\_____\__,_|\__| by @serioton
                                         version: 1.0.0 


usage: shellcat.py [-h] [-e] [-b] [-w FILENAME] [-c] shell_type ip port

Generate reverse shell payload

positional arguments:
  shell_type                     Type of the shell (bash, python, php, nc, ...)
  ip                             IP address of the attacker
  port                           Port to listen on

options:
  -h, --help                     show this help message and exit
  -e, --encode                   URL encode the payload
  -b, --base64                   Base64 encode the payload
  -w FILENAME, --write FILENAME  Write the payload to a file
  -c, --copy                     Copy the payload to clipboard
```

## Examples

Generate a bash reverse shell payload:

```bash
python shellcat.py bash 10.10.10.10 1234
```

Generate a python reverse shell payload, URL encode it, and copy it to the clipboard:

```bash
python shellcat.py python 10.10.10.10 1234 -e -c
```

Generate a php reverse shell payload, Base64 encode it, and write it to a file:

```bash
python shellcat.py php 10.10.10.10 1234 -b -w shell.php
```

Generate a nc reverse shell payload, URL encode it, Base64 encode it, write it to a file, and copy it to the clipboard:

```bash
python shellcat.py nc 10.10.10.10 1234 -e -b -w payload.txt -c
```
