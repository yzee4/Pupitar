# Dottler by Yzee4
#
# MIT License
#
# Copyright (c) 2023 Yzee4
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import os
import subprocess
import shutil
import sys
import re
import random
import readline

class Colors:
    WHITE = '\033[0;97m'
    CYAN = '\033[0;36m'
    LIGHT_RED = '\033[0;91m'
    LIGHT_GREEN = '\033[0;92m'
    YELLOW = '\033[0;93m'
    LIGHT_BLUE = '\033[0;94m'
    PINK = '\033[0;95m'
    NEG_LIGHT_GREEN = '\033[1;92m'
    NEG_LIGHT_RED = '\033[1;91m'
    NEG_YELLOW = '\033[1;93m'
    NEG_PINK = '\033[1;95m'

def verify_root():
    global root
    if os.geteuid() != 0:
        root = False
    else:
        root = True
        
def check_tool_installed(tool_name):
    if tool_name == 'net-tools':
        return os.path.exists('/sbin/ifconfig')
    return shutil.which(tool_name) is not None

def initializing_pupitar_root():
    if root == True:
        subprocess.run("clear")
        tools_to_check = ['arp-scan', 'nmap']
        not_installed_tools = [tool for tool in tools_to_check if not check_tool_installed(tool)]
        
        if not_installed_tools:
            for tool in not_installed_tools:
                print(f"{Colors.LIGHT_RED}[-] {Colors.YELLOW}{tool} {Colors.WHITE}not installed. To install, use {Colors.LIGHT_GREEN}'sudo apt install {tool}'{Colors.WHITE}.")
            sys.exit()

def initializing_pupitar_noroot():
    if root == False:
        subprocess.run("clear")
        tools_to_check = ['nmap']
        not_installed_tools = [tool for tool in tools_to_check if not check_tool_installed(tool)]
        
        if not_installed_tools:
            for tool in not_installed_tools:
                print(f"{Colors.LIGHT_RED}[-] {Colors.YELLOW}{tool} {Colors.WHITE}not installed. To install, use {Colors.LIGHT_GREEN}'pkg install {tool}'{Colors.WHITE}.")
            sys.exit()

def scan_network():
    if localnet == True:
        if root ==  False:
            print("\n" + f"{Colors.LIGHT_RED}[-] {Colors.WHITE}Root is required to use --localnet flag.")
            print(f"{Colors.LIGHT_RED}[-] {Colors.WHITE}Use -ip flag without --localnet or execute as root.\n")
            main()

    try:
        print("\n" + f"{Colors.LIGHT_BLUE}[#] {Colors.WHITE}Scanning may take a while, please wait a moment. Varies depending on network speed.\n")

        if localnet ==  True:
            if verbose:
                print(f"{Colors.PINK}[/] {Colors.WHITE}Checking IP on the network.")
            if verbose:
                print(f"{Colors.PINK}[/] {Colors.WHITE}Checking IP in network.\n")
            try:
                with open('/dev/null', 'w') as null_file:
                    output = subprocess.check_output(['arp-scan', "--localnet"], universal_newlines=True, stderr=null_file)

                    if "0 responded" in output:
                        print(f"{Colors.LIGHT_RED}[-] {Colors.WHITE}Not found IP in network.\n")
                        main()
            except subprocess.CalledProcessError as e:
                print(f"{Colors.LIGHT_RED}[-] {Colors.WHITE}Unknown error.\n")
                main()

            ip_info = []
            lines = output.split('\n')
            
            for line in lines:
                parts = line.split()
                if len(parts) >= 3:
                    ip_address = parts[0]

                    if re.match(r'\d+\.\d+\.\d+\.\d+', ip_address):
                        ip_info.append(ip_address)

            for ip_address in ip_info:
                if verbose:
                    print(f"{Colors.PINK}[/] {Colors.WHITE}Collecting IP information.")
                
                try:
                    with open('/dev/null', 'w') as null_file:
                        nmap_output = subprocess.check_output(['nmap', '-T5', '-open', ip_address, *command_list], universal_newlines=True, stderr=null_file)

                    lines = nmap_output.split('\n')
                    vulnerabilities = []
                    seconds = None
                    name = None
                    mac = None

                    for line in lines:
                        if "seconds" in line:
                            parts = line.split()
                            seconds = parts[10]

                        if "MAC Address:" in line:
                            parts = line.split()
                            mac = parts[2]
                            capture_name = " ".join(parts[3:])
                            name = capture_name.replace('(', '').replace(')', '')

                        if "/tcp" in line:
                            parts = line.split()
                            port = parts[0]
                            state = parts[1]
                            service = parts[2]

                            chars_to_add = max(0, 9 - len(port))
                            port = port + " " * chars_to_add

                            color_state = (Colors.NEG_LIGHT_GREEN if state == "open"
                                        else Colors.NEG_YELLOW if state == "filtered"
                                        else Colors.NEG_LIGHT_RED)

                            vulnerabilities.append(f"{Colors.LIGHT_GREEN}PORT: {Colors.WHITE}{port} {Colors.LIGHT_GREEN}STATE: {color_state}{state.ljust(5)} {Colors.LIGHT_GREEN}SERVICE: {Colors.WHITE}{service.ljust(5)}")

                    if vulnerabilities:
                        print(f"{Colors.LIGHT_GREEN}----| IP: {Colors.WHITE}{ip_address}")
                        if name and mac:
                            if root == True:
                                print(f"""{Colors.YELLOW}NAME: {Colors.WHITE}{name}\n{Colors.YELLOW}MAC:  {Colors.WHITE}{mac}""")
                        for vulnerability in vulnerabilities:
                            print(vulnerability)
                        print(f"{Colors.LIGHT_GREEN}----| ")
                        if verbose:
                            print(f"{Colors.PINK}[/] {Colors.WHITE}Scanned in {seconds} seconds.")
                        print()
                    else:
                        print(f"""{Colors.NEG_LIGHT_GREEN}----| {Colors.LIGHT_GREEN}IP: {Colors.WHITE}{ip_address}""")
                        print(f"{Colors.LIGHT_RED}[-] {Colors.WHITE}No result.")
                        print(f"{Colors.NEG_LIGHT_GREEN}----|")
                        if verbose:
                            print(f"{Colors.PINK}[/] {Colors.WHITE}Scanned in {seconds} seconds.")
                        print()

                except subprocess.CalledProcessError as e:
                    print(f"{Colors.LIGHT_RED}[-] {Colors.WHITE}Failed to determinate route.")
            main()
            
        else:
            if verbose:
                print(f"{Colors.PINK}[/] {Colors.WHITE}Collecting IP information.")

            try:
                with open('/dev/null', 'w') as null_file:
                    nmap_output = subprocess.check_output(['nmap', '-T5', '-open', *command_list], universal_newlines=True, stderr=null_file)
                paragraphs = re.split(r'\n(?=Nmap scan report)', nmap_output)
                num_ips_scanned = 0

                for paragraph in paragraphs:
                    match_ip = re.search(r'Nmap scan report for (\d+\.\d+\.\d+\.\d+)', paragraph)
                    match_ports = re.finditer(r'(\d+\/[a-zA-Z]+)\s+(open)\s+([a-zA-Z-]+)', paragraph)
                    match_mac = re.search(r'MAC Address: ([0-9A-F:]+) \((.*?)\)', paragraph)

                    if match_ip:
                        ip_address = match_ip.group(1)
                        print(f"{Colors.LIGHT_GREEN}----| IP: {Colors.WHITE}{ip_address}")

                        if match_mac:
                            mac = match_mac.group(1)
                            name = match_mac.group(2)
                        if root == True:
                            print(f"""{Colors.YELLOW}NAME: {Colors.WHITE}{name}\n{Colors.YELLOW}MAC:  {Colors.WHITE}{mac}""")

                        if match_ports:
                            for match in match_ports:
                                port = match.group(1)
                                state = match.group(2)
                                service = match.group(3)

                                chars_to_add = max(0, 9 - len(port))
                                port = port + " " * chars_to_add

                                color_state = (Colors.NEG_LIGHT_GREEN if state == "open"
                                            else Colors.NEG_YELLOW if state == "filtered"
                                            else Colors.NEG_LIGHT_RED)

                                print(f"{Colors.LIGHT_GREEN}PORT: {Colors.WHITE}{port} {Colors.LIGHT_GREEN}STATE: {color_state}{state.ljust(5)} {Colors.LIGHT_GREEN}SERVICE: {Colors.WHITE}{service.ljust(5)}")

                        print(f"{Colors.LIGHT_GREEN}----|")
                        print()
                        num_ips_scanned += 1

                    if "Nmap done" in paragraph:
                        match_time = re.search(r'in (\d+\.\d+) seconds', paragraph)
                        if match_time:
                            total_scan_time = match_time.group(1)
                
                if total_scan_time:
                    if num_ips_scanned == 0:
                        if rangeip:
                            print(f"{Colors.LIGHT_GREEN}----| IP: {Colors.WHITE}{rangeipaddress}")
                        else:
                            print(f"{Colors.LIGHT_GREEN}----| IP: {Colors.WHITE}{ip}")
                        print(f"{Colors.LIGHT_RED}[-] {Colors.WHITE}No result.")
                        print(f"{Colors.LIGHT_GREEN}----|")
                        print()
                    if verbose:
                        print(f"{Colors.PINK}[/] {Colors.WHITE}{num_ips_scanned} hosts scanned in {total_scan_time} seconds.")
                        print()

            except subprocess.CalledProcessError as e:
                print(f"{Colors.LIGHT_RED}[-] {Colors.WHITE}Unknown error: {str(e)}")
                print()
            main()

    except KeyboardInterrupt:
        print(f"{Colors.LIGHT_GREEN}[+] {Colors.WHITE}Scan interrupted\n")
        main()

def interface_variables():
    global color
    global pupitar

    color_codes = {
        'yellow': '\033[0;93m',
        'lightblue': '\033[0;94m',
        'lightred': '\033[0;91m',
        'lightgreen': '\033[0;92m',
        'cyan': '\033[0;96m',
        'pink': '\033[0;95m',
    }

    pupitar_values = {
        'yellow': '\033[1;3;93m',
        'lightblue': '\033[1;3;94m',
        'lightred': '\033[1;3;91m',
        'lightgreen': '\033[0;92m',
        'cyan': '\033[1;3;96m',
        'pink': '\033[1;3;95m',
    }

    randomcolor_name = random.choice(list(color_codes.keys()))
    color = color_codes[randomcolor_name]
    pupitar = pupitar_values.get(randomcolor_name)

    def interface_arguments():
        global head
        global noroot
        global randominterface
        global interface

        head = (f"""{Colors.WHITE}Termux version.""")
        noroot = (f"{color}* {Colors.WHITE}Use root to access more detailed information.")   
        interfaces_codes = {
        "Interface 1":f"""
 ▄▄▄  ▄  ▄▌ ▄▄▄    ▄▄▄▄▄ ▄▄▄  ▄▄▄  
▐█ ▄█  █ █▌▐█ ▄█ █  ██  ▐█ ▀█ ▀▄ █   
 ██▀  █▌▐█▌ ██▀ ▐█  ▐█  ▄█▀▀█ ▐▀▀▄   
▐█    ▐█▄█▌▐█    █▌ ▐█▌ ▐█  ▐▌▐█ █▌     
 ▀     ▀▀▀  ▀   ▀▀▀ ▀▀▀  ▀  ▀  ▀  ▀""",}
                                            
        interfaces = list(interfaces_codes.keys())
        randominterface_name = random.choice(interfaces)
        randominterface = interfaces_codes[randominterface_name]

        interface = (f"""{Colors.WHITE}Make sure you are using the latest version at {Colors.LIGHT_GREEN}'https://github/com/yzee4/Pupitar'{Colors.WHITE}.

    {color}-| {Colors.WHITE}coded by Yzee4
    {color}-| {Colors.WHITE}produced on Python                                                    

{Colors.WHITE}Need help? Use {Colors.WHITE}'{Colors.LIGHT_GREEN}--help {Colors.WHITE}or {Colors.LIGHT_GREEN}-h{Colors.WHITE}'.
""") 
    interface_arguments()

interface_variables()
subprocess.run("clear")
def show_interface():
    reset_color = '\033[0m'
    if root == True:
        print(f"{color}{head}{color}{randominterface}\n{interface}{reset_color}")
    else:
        print(f"{color}{head}{color}{randominterface}\n{interface}\n{noroot}{reset_color}")

def show_help():
    print(f"""
{Colors.LIGHT_GREEN}syntax:
    scan        start scan without arguments  < scan >    

{Colors.LIGHT_GREEN}flags:
    --verbose or -v       shows process details      < --verbose or -v >
    -localnet or --l      scans a local network      < --localnet or  -l >
    -ip                   scans a specific ip        < -ip 'ip address, ex: 192.168.1.0' > 
    --port or -p          scans a specific port      < --port or -p 'port number, ex: 80' >
    --rangeip or -rip     scans a range of ports     < -ip 'ip address, ex: 192.168.1.0' --rangeip or -rip 'range ip, ex: 10' >  
    --rangeport or -rp    scans a range of ports     < --port or -p 'port number, ex: 80' --rangeport or -rp 'range port, ex: 80' >

    you can combine arguments: < scan -open -port 80 >

{Colors.LIGHT_GREEN}others:
    --help or -h    shows help menu       < --help or -h >
    --clear or -c   clean the terminal    < --clear or -c >
    --exit or -e    say goodbye           < --exit or -e >
""")
    main()

def main():
    global ip
    global localnet
    global rangeport
    global rangeip
    global rangeipaddress
    global verbose
    global command_list
    command_list = []

    try:
        def is_valid_ip(ip):
            ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
            if re.match(ip_pattern, ip):
                parts = ip.split('.')
                for part in parts:
                    if not (0 <= int(part) <= 255):
                        return False
                return True
            
        def is_valid_port(port):
            try:
                port = int(port)
                if 1 <= port <= 65535:
                    return True
            except ValueError:
                return False

        def is_valid_rangeip(rangeip):
            try:
                rangeip = int(rangeip)
                if 1 <= rangeip <= 255:
                    return True
            except ValueError:
                return False
            
        def is_valid_rangeport(port, rangeport):
            try:
                port = int(port)
                rangeport = int(rangeport)
                return 0 <= port <= 65535 and rangeport >= port
            except ValueError:
                return False


        while True:
            pconsole = input(f"{Colors.WHITE}|-{Colors.WHITE}[{color}pupitar{Colors.WHITE}]-{Colors.WHITE}--> ")
            verbose = False

            words = pconsole.split()
            if len(words) == 0:
                continue
            command = words[0]

            pconsole = pconsole.strip()

            if pconsole == "scan":
                print(f"{Colors.LIGHT_GREEN}scan <ip_address or --localnet flag> <additional flags>. Use scan --help for more details.")
                print()
                main()

            if command == "scan":
                if pconsole.count("  ") > 0:
                    print(f"{Colors.LIGHT_GREEN}scan <ip_address or --localnet flag> <additional flags>. Use scan --help for more details.")
                    print()
                    main()

                ip = None
                port = None
                rangeip = None
                rangeport = None
                localnet = False
                verbose = False
                help = False

                i = 1
                while i < len(words):
                    if words[i] == "-ip" and i + 1 < len(words):
                        ip = words[i + 1]
                        i += 2
                    elif words[i] == "--rangeip" and i + 1 < len(words) or words[i] == "-rip" and i + 1 < len(words):
                        rangeip = words[i + 1]
                        i += 2
                    elif words[i] == "--port" and i + 1 < len(words) or words[i] == "-p" and i + 1 < len(words):
                        port = words[i + 1]
                        i += 2
                    elif words[i] == "--rangeport" and i + 1 < len(words) or words[i] == "-rp" and i + 1 < len(words):
                        rangeport = words[i + 1]
                        i += 2
                    elif words[i] == "--localnet" or words[i] == "-l":
                        localnet = True
                        i += 1
                    elif words[i] == "--verbose" or words[i] == "-v":
                        verbose = True
                        i += 1
                    else:
                        print(f"{Colors.LIGHT_RED}[-] {Colors.WHITE}Invalid flag(s).")
                        print()
                        main()
                        break

                if ip or localnet:
                    if help:
                        show_help()
                        main()

                    if ip:        
                        if ip and not is_valid_ip(ip):
                            print(f"{Colors.LIGHT_RED}[-] {Colors.WHITE}Invalid ip format.")
                            print()
                            main()

                    if port:
                        if port and not is_valid_port(port):
                            print(f"{Colors.LIGHT_RED}[-] {Colors.WHITE}Invalid port format.")
                            print()
                            main()

                    if rangeip:
                        if rangeip and not is_valid_rangeip(rangeip):    
                            print(f"{Colors.LIGHT_RED}[-] {Colors.WHITE}Invalid range ip format.")
                            print()
                            main()
                    if rangeport:
                        if rangeport and not is_valid_rangeport(port, rangeport):
                            print(f"{Colors.LIGHT_RED}[-] {Colors.WHITE}Invalid range port format.")
                            print()
                            main()

                    if ip or port or rangeport or rangeip or localnet:

                        if localnet:
                            if ip:
                                print(f"{Colors.LIGHT_RED}[-] {Colors.WHITE} If use --localnet cannot set ip.")
                                print()
                                main()

                        if ip:
                            localnet = False
                            command_list.clear()
                            command_list.append(ip)

                        if rangeip:
                            rangeipaddress = f"{ip} <---> {rangeip}"
                            command_list.clear()
                            command_list.append(f"{ip}-{rangeip}")
                        
                        if port:
                            if not rangeport:
                                command_list.append(f"-p {port}")

                        if rangeport:
                            print(port)
                            print(rangeport)
                            if not port:
                                print(f"{Colors.LIGHT_RED}[-] {Colors.WHITE} If use --rangeport first set a port value.")
                                print()
                                main()
                            command_list.append(f"-p {port}-{rangeport}")

                else:
                    print(f"{Colors.LIGHT_RED}[-] {Colors.WHITE}First set IP address with the -ip flag, or use the local network with --localnet flag.")
                    print()
                    main()

                scan_network()

            if pconsole == "--exit" or pconsole == "-e":
                print('')
                print(f'{Colors.YELLOW}[/] {Colors.WHITE}Thank for using! :)')
                sys.exit()

            elif pconsole == "--clear" or pconsole == "-c":
                subprocess.run("clear")
                main()

            elif pconsole == "--help" or pconsole == "-h":
                show_help()
                
            else:
                print(f"{Colors.LIGHT_RED}[-] {Colors.WHITE}Invalid command.")
                print()
                continue
            scan_network()

    except KeyboardInterrupt:
        print('')
        print(f'{Colors.YELLOW}[/] {Colors.WHITE}Thank for using! :)')
        sys.exit()

if __name__ == "__main__":
    Colors()
    verify_root()
    initializing_pupitar_root()
    initializing_pupitar_noroot()
    interface_variables()
    show_interface()
    main()
