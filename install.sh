#!/bin/bash

RED='\033[0;31m'
CYAN='\033[0;36m'
RESET='\033[0m'

printf "$CYAN[INFO] Installing required packages...$RESET\n"
sudo apt update -y
sudo apt install -y libc6-dbg gdb metasploit-framework python3 python3-pip python3-impacket hashcat freerdp2-x11 tesseract-ocr

packagesInstallStatus=$?

if [ $packagesInstallStatus -ne 0 ]; then
  printf "$RED[ERROR] Packages installation encountered an error!$RESET\n"
  exit 1
fi

printf "$CYAN[INFO] Installing required Python libraries...$RESET\n"
pip3 install -r requirements.txt

pythonLibrariesInstallStatus=$?

if [ $pythonLibrariesInstallStatus -ne 0 ]; then
  printf "$RED[ERROR] Python libraries installation encountered an error!$RESET\n"
  exit 1
fi

printf "$CYAN[INFO] Powerkatz installation completed successfully...$RESET\n"