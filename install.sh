#!/bin/bash

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

echo "[*] Checking if python3 is installed"
if ! command_exists python3; then
    echo "Python3 is not installed. Installing Python3..."
    sudo apt-get update
    sudo apt-get install -y python3
else
    echo "Python3 is already installed."
fi

echo "[*] Checking if pip is installed"
if ! command_exists pip3; then
    echo "pip3 is not installed. Installing pip3..."
    sudo apt-get install -y python3-pip
else
    echo "pip3 is already installed."
fi

echo "[*] Checking if PyQt6 is installed"
if ! python3 -c "import PyQt6" >/dev/null 2>&1; then
    echo "PyQt6 is not installed. Installing PyQt6..."
    sudo pip3 install PyQt6
else
    echo "PyQt6 is already installed."
fi

echo "[*] Installing...Please wait..."
PROGRAM_DIR="/usr/share/evillnk"
sudo mkdir -p $PROGRAM_DIR
sudo cp -r ./* $PROGRAM_DIR
sudo chmod +x $PROGRAM_DIR/evillnk.py
sudo rm $PROGRAM_DIR/install.sh

DESKTOP_ENTRY="[Desktop Entry]
Type=Application
Name=evillnk
Exec=/usr/bin/evillnk
Path=/usr/share/evillnk
Icon=$PROGRAM_DIR/img/evillnk.png
Categories=08-exploitation-tools;13-social-engineering-tools;"

echo "$DESKTOP_ENTRY" > /usr/share/applications/evillnk.desktop

sudo ln -sf /usr/share/evillnk/evillnk.py /usr/bin/evillnk
sudo chmod +x /usr/bin/evillnk

echo "[*] Installation complete."
echo "# You can now run the tool using 'evillnk' in the terminal or from applications panel: 08-Exploitation Tools"
echo "# Coded by v1k (Radostin Dimov)"
