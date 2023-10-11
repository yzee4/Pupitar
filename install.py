# Pupitar by Yzee4
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

def colors():
    global white, cyan, lightred, lightgreen, yellow, lightblue, pink
    white = '\033[0;97m'
    cyan = '\033[0;36m'
    lightred = '\033[0;91m'
    lightgreen = '\033[0;92m'
    yellow = '\033[0;93m'
    lightblue = '\033[0;94m'
    pink = '\033[0;95m'
colors()

def main():
    if os.geteuid() != 0:
        print(f"{lightred}[-] {white}Execute as root mode. Use {lightgreen}'sudo python3 install.py'{white}.")
        exit(1)

    zip_file = "pupitar.zip"
    dest_dir = "/usr/local/bin"
    pupitar_executable = "/usr/local/bin/pupitar"
    pupitar_py_executable = "/usr/local/bin/pupitar.py"

    if os.path.exists(pupitar_executable) and os.path.exists(pupitar_py_executable):
        print(f"{lightgreen}[+] {white}pupitar already installed. Use {lightgreen}'pupitar' {white}to run.")
        exit(0)

    if not os.path.exists(zip_file):
        print(f"{lightred}[-] {white}File not found.")
        exit(1)

    with open(os.devnull, 'w') as nullfile:
        result = subprocess.run(["unzip", zip_file, "-d", dest_dir], stdout=nullfile, stderr=nullfile)

    if result.returncode == 0:
        os.chmod(pupitar_executable, 0o755)
        os.chmod(pupitar_py_executable, 0o755)
        print(f"{lightgreen}[+] {white}Pupitar has been installed. Use {lightgreen}'pupitar' {white}to run.")
        if not os.path.exists(pupitar_py_executable):
            print(f"{lightred}[-] {white}pupitar.py was not found in the package.")
        exit(0)
main()
