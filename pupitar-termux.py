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
                print(f"{Colors.LIGHT_RED}[-] {Colors.YELLOW}{tool} {Colors.WHITE}not installed. To install, use {Colors.LIGHT_GREEN}'sudo apt install {tool}'{Colors.WHITE}.")
            sys.exit()


def scan_network_noroot():
    try:
        print("")
        print(f"{Colors.LIGHT_BLUE}[#] {Colors.WHITE}Scanning may take a while, please wait a moment. Varies depending on network speed.")
        print("")
        if verbose == True:
            print(f"{Colors.PINK}[/] {Colors.WHITE}Collecting IP information.")      
        try:
            with open('/dev/null', 'w') as null_file:
                nmap_output = subprocess.check_output(['nmap', *command_ip_list, *command_list], universal_newlines=True, stderr=null_file)
            lines = nmap_output.split('\n')
            vulnerabilities = []

            print(f"""{Colors.NEG_LIGHT_GREEN}----| {Colors.LIGHT_GREEN}IP: {Colors.WHITE}{ip} 
{Colors.YELLOW}NAME: {Colors.NEG_LIGHT_RED}Need root   
{Colors.YELLOW}MAC:  {Colors.NEG_LIGHT_RED}Need root""") 
            
            for line in lines:
                if "seconds" in line:
                    parts = line.split()
                    seconds = parts[10]

            for line in lines:
                if "/tcp" in line:
                    parts = line.split()
                    port = parts[0]
                    state = parts[1]
                    service = parts[2]

                    chars_to_add = max(0, 9 - len(port))
                    port = port + "" + " " * chars_to_add

                    color_state = (Colors.NEG_LIGHT_GREEN if state == "open"
                                else Colors.NEG_YELLOW if state == "filtered"
                                else Colors.NEG_LIGHT_RED)
                    
                    if root == True:
                        vulnerabilities.append(f"{Colors.WHITE}{Colors.LIGHT_GREEN}PORT: {Colors.WHITE}{port.ljust(5)} {Colors.LIGHT_GREEN}STATE: {color_state}{state.ljust(5)} {Colors.LIGHT_GREEN}SERVICE: {Colors.WHITE}{service.ljust(5)}")
                    if root == False:
                        vulnerabilities.append(f"{Colors.WHITE}{Colors.LIGHT_GREEN}PORT: {Colors.WHITE}{port.ljust(5)} {Colors.LIGHT_GREEN}STATE: {color_state}{state.ljust(5)} {Colors.LIGHT_GREEN}SERVICE: {Colors.WHITE}{service.ljust(5)}")
                    print(" ".join(vulnerabilities))
                    vulnerabilities = []

            if not any("/tcp" in line for line in lines):
                vulnerabilities.append(f"{Colors.LIGHT_RED}[-] {Colors.WHITE}No result.")
                print(" ".join(vulnerabilities))
            print(f"{Colors.NEG_LIGHT_GREEN}----| {Colors.WHITE}{seconds}s")    
            print("")

        except subprocess.CalledProcessError as e:
            print(f"{Colors.LIGHT_RED}[-] {Colors.WHITE}Failed to determine route{Colors.WHITE}.")
            print(f"{Colors.NEG_LIGHT_GREEN}----| {Colors.WHITE}")  
            print("")
        main()

    except subprocess.CalledProcessError as e:
        print(f"{Colors.LIGHT_RED}[-] {Colors.WHITE}Unknown error{Colors.WHITE}.")
        print("")
    except KeyboardInterrupt:
        print(f"{Colors.LIGHT_GREEN}[+] {Colors.WHITE}Scan interrupted")
        print("")
        main()

def scan_network():
    if root == False:
        print("")
        print(f"{Colors.LIGHT_RED}[-] {Colors.WHITE}Root is required when the -ip flag is not used.")
        print(f"{Colors.LIGHT_RED}[-] {Colors.WHITE}Use -ip flag or execute as root.")
        print("")
        main()
    try:
        print("")
        print(f"{Colors.LIGHT_BLUE}[#] {Colors.WHITE}Scanning may take a while, please wait a moment. Varies depending on network speed.")
        print("")
        if verbose == True:
            print(f"{Colors.PINK}[/] {Colors.WHITE}Checking IP on the network.")
        try:
            if verbose == True:
                print(f"{Colors.PINK}[/] {Colors.WHITE}Checking if the IP is valid.")
                print("")
            with open('/dev/null', 'w') as null_file:
                arp_scan_output = subprocess.check_output(['arp-scan', *command_ip_list], universal_newlines=True, stderr=null_file)
            if "0 responded" in arp_scan_output:
                print(f"{Colors.LIGHT_RED}[-] {Colors.WHITE}IP not responded.")
                print("")
                main()
        except subprocess.CalledProcessError as e:
            print(f"{Colors.LIGHT_RED}[-] {Colors.WHITE}Invalid ip.")
            print("")
            main()
    
        ip_info = {}
        lines = arp_scan_output.split('\n')
        
        for line in lines:
            parts = line.split()
            if len(parts) >= 3:
                ip_address = parts[0]
                ip_mac = parts[1]
                ip_name = " ".join(parts[2:])

                if re.match(r'\d+\.\d+\.\d+\.\d+', ip_address):
                    if ip_name == "unknown":
                        ip_name = f"{Colors.YELLOW}Unknown"
                    ip_info[ip_address] = [ip_name, ip_mac]

        for ip_address, info in ip_info.items():
            ip_name, ip_mac = info
            if verbose == True:
                print(f"{Colors.PINK}[/] {Colors.WHITE}Collecting IP information.")
            
            try:
                with open('/dev/null', 'w') as null_file:
                    nmap_output = subprocess.check_output(['nmap', *command_list, ip_address], universal_newlines=True, stderr=null_file)
                print(f"""{Colors.NEG_LIGHT_GREEN}----| {Colors.LIGHT_GREEN}IP: {Colors.WHITE}{ip_address} 
{Colors.YELLOW}NAME: {Colors.WHITE}{ip_name}
{Colors.YELLOW}MAC:  {Colors.WHITE}{ip_mac}""")
                lines = nmap_output.split('\n')
                vulnerabilities = []

                for line in lines:
                    if "seconds" in line:
                        parts = line.split()
                        seconds = parts[10]

                for line in lines:
                    if "/tcp" in line:
                        parts = line.split()
                        port = parts[0]
                        state = parts[1]
                        service = parts[2]
                        
                        if service == "unknown":
                            service = f"{Colors.YELLOW}unknown"

                        chars_to_add = max(0, 9 - len(port))
                        
                        port = port + "" + " " * chars_to_add

                        color_state = (Colors.NEG_LIGHT_GREEN if state == "open"
                                    else Colors.NEG_YELLOW if state == "filtered"
                                    else Colors.NEG_LIGHT_RED)
                        
                        vulnerabilities.append(f"{Colors.WHITE}{Colors.LIGHT_GREEN}PORT: {Colors.WHITE}{port} {Colors.LIGHT_GREEN}STATE: {color_state}{state.ljust(5)} {Colors.LIGHT_GREEN}SERVICE: {Colors.WHITE}{service.ljust(5)}")
                        print(" ".join(vulnerabilities))
                        vulnerabilities = []

                if not any("/tcp" in line for line in lines):
                    vulnerabilities.append(f"{Colors.LIGHT_RED}[-] {Colors.WHITE}No result.")
                    print(" ".join(vulnerabilities))
                print(f"{Colors.NEG_LIGHT_GREEN}----| {Colors.WHITE}{seconds}s")    
                print("")

            except subprocess.CalledProcessError as e:
                print(f"{Colors.LIGHT_RED}[-] {Colors.WHITE}Failed to determine route.{Colors.WHITE}.")
                print("")
        main()

    except subprocess.CalledProcessError as e:
        print(f"{Colors.LIGHT_RED}[-] {Colors.WHITE}Failed to determine route. Check your network{Colors.WHITE}.")
        print("")
    except KeyboardInterrupt:
        print(f"{Colors.LIGHT_GREEN}[+] {Colors.WHITE}Scan interrupted")
        print("")
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

        head = (f"""{Colors.WHITE}What do you know?""")
        noroot = (f"{color}* {Colors.WHITE}Use root to access more detailed information")   
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
        print(f"{color}{head}{color}{randominterface}\n{interface}{reset_color}"
              
              
              )
    else:
        print(f"{color}{head}{color}{randominterface}\n{interface}\n{noroot}{reset_color}")

def show_help():
    print(f"""
{Colors.LIGHT_RED}without -ip flag, root is required{Colors.LIGHT_GREEN}
{Colors.LIGHT_GREEN}syntax:
    scan        start scan without arguments  < scan >    

{Colors.LIGHT_GREEN}flags:
    --verbose or -v       shows process details      < --verbose or -v >    
    --open or -o          shows only open ports      < --open or -o >    
    -ip                   scans a specific ip        < -ip 'ip address, ex: 192.168.1.0' >    
    --port or -p          scans a specific port      < --port or -p 'port number, ex: 80' >
    --rangeport or -rp    scans a range of ports     < --rangeport or -rp 'range port, ex: 50-74. Maximum range is 24'>

    you can combine arguments: < scan -open -port 80 >

{Colors.LIGHT_GREEN}others:
    help    shows help menu       < help >
    clear   clean the terminal    < clear >
    exit    say goodbye           < exit >
""")
    main()

def main():
    global ip
    global ip_address
    global rangeport
    global verbose
    global command_list
    global command_ip_list
    command_list = []
    command_ip_list = []
    command_ip_list = ['--localnet']

    try:
        def is_valid_ip(ip):
            ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
            return re.match(ip_pattern, ip)

        def is_valid_port(port):
            try:
                port = int(port)
                if 1 <= port <= 65535:
                    return True
                else:
                    print(f"{Colors.LIGHT_RED}[-] {Colors.WHITE}Maximum port is 65535.")
                    print("")
                    main()
            except ValueError:
                return False
            
        def is_valid_rangeport(rangeport):
            if re.match(r'^\d+-\d+$', rangeport):
                min_port, max_port = parse_rangeport(rangeport)
                if min_port is not None and max_port is not None:
                    if max_port - min_port > 24:
                        print(f"{Colors.LIGHT_RED}[-] {Colors.WHITE}The maximum number of intervals is 24, example 50-74.")
                        print("")
                        main()
                        return True
                    elif min_port > max_port:
                        print(f"{Colors.LIGHT_RED}[-] {Colors.WHITE}Invalid range port. First number is greater than the second.")
                        print("")
                        main()
                else:
                    print(f"{Colors.LIGHT_RED}[-] {Colors.WHITE}Maximum port is 65535.")
                    print("")
                    main()
            else:
                print(f"{Colors.LIGHT_RED}[-] {Colors.WHITE}Invalid range port format.")
                print("")
                main()
            return False

        def parse_rangeport(rangeport):
            match = re.match(r'^(\d+)-(\d+)$', rangeport)
            if match:
                min_port, max_port = map(int, match.groups())
                if 1 <= min_port <= 65535 and 1 <= max_port <= 65535:
                    return (min_port, max_port)
            return (None, None)
        
        while True:
            dconsole = input(f"{Colors.WHITE}|-{Colors.WHITE}[{color}pupitar{Colors.WHITE}]-{Colors.WHITE}--> ")
            ip_address = "--localnet"
            verbose = False
            
            if dconsole == "scan":
                scan_network()
            
            words = dconsole.split()
            if len(words) == 0:
                continue
            command = words[0]

            if command == "scan":
                rangeport = None
                verbose = False
                ip = None
                port = None
                open_flag = False

                i = 1
                while i < len(words):
                    if words[i] == "-ip" and i + 1 < len(words):
                        ip = words[i + 1]
                        i += 2
                    elif words[i] == "--port" and i + 1 < len(words) or words[i] == "-p" and i + 1 < len(words):
                        port = words[i + 1]
                        i += 2
                    elif words[i] == "--rangeport" and i + 1 < len(words) or words[i] == "-rp" and i + 1 < len(words):
                        rangeport = words[i + 1]
                        i += 2
                    elif words[i] == "--open" or words[i] == "-o":
                        open_flag = True
                        i += 1
                    elif words[i] == "--verbose" or words[i] == "-v":
                        verbose = True
                        i += 1
                    else:
                        print(f"{Colors.LIGHT_RED}[-] {Colors.WHITE}Invalid flag.")
                        print("")
                        main()
                        break

                if ip:        
                    if ip and not is_valid_ip(ip):
                        print(f"{Colors.LIGHT_RED}[-] {Colors.WHITE}Invalid ip format.")
                        print("")
                        main()
                else:
                    ip = "--localnet"
                if port and not is_valid_port(port):
                    print(f"{Colors.LIGHT_RED}[-] {Colors.WHITE}Invalid port format.")
                    print("")
                    main()
                if rangeport and is_valid_rangeport(rangeport):
                    print("")
                    main()

                if ip or port or open_flag or rangeport:
                    if open_flag:
                        command_list.append("-open")
                    if port:
                        command_list.append(f"-p {port}")
                    if rangeport:
                        if port:
                            print(f"{Colors.LIGHT_RED}[-] {Colors.WHITE} If you set the range port, you cannot set a port number.")
                            print("")
                            main()
                        command_list.append(f"-p {rangeport}")
                    if ip:
                        command_ip_list.clear()
                        command_ip_list.append(ip)
                    
                if root == True:
                    scan_network()
                elif root == False:
                    if not ip == "--localnet":
                        scan_network_noroot()
                    else:
                        print("")
                        print(f"{Colors.LIGHT_RED}[-] {Colors.WHITE}Root is required when the -ip flag is not used.")
                        print(f"{Colors.LIGHT_RED}[-] {Colors.WHITE}Use -ip flag or execute as root.")
                        print("")
                        main()

            if command == "exit":
                break

            elif dconsole == "--clear" or dconsole == "-c":
                subprocess.run("clear")
                main()

            elif dconsole == "--help" or dconsole == "-h":
                show_help()
                
            else:
                print(f"{Colors.LIGHT_RED}[-] {Colors.WHITE}Invalid command.")
                print("")
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