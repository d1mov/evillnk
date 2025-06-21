#!/bin/bash

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

echo "[*] Checking if git is installed"
if ! command_exists git; then
    echo "Git is not installed. Installing Git..."
    sudo apt-get update
    sudo apt-get install -y git
else
    echo "Git is already installed."
fi

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
sudo git clone https://github.com/d1mov/evillnk
PROGRAM_DIR="/usr/share/evillnk"
sudo mkdir -p $PROGRAM_DIR
sudo cp -r ./evillnk/* $PROGRAM_DIR
sudo chmod +x $PROGRAM_DIR/evillnk.py
sudo rm $PROGRAM_DIR/install.sh
sudo rm -r evillnk

DESKTOP_ENTRY="[Desktop Entry]
Type=Application
Name=evillnk
Exec=/usr/bin/evillnk
Path=/usr/share/evillnk
Icon=$PROGRAM_DIR/img/evillnk.png
Categories=kali-initial-access;kali-resource-development"

echo "$DESKTOP_ENTRY" > /usr/share/applications/evillnk.desktop

echo -e '#!/bin/bash\nexport QT_LOGGING_RULES="*.debug=false"\ncd /usr/share/evillnk\nexec python3 evillnk.py "$@"' | sudo tee /usr/bin/evillnk > /dev/null
sudo chmod +x /usr/bin/evillnk

echo "[*] Installation complete."
echo "# You can now run the tool using 'evillnk' in the terminal or from applications panel: 03-Initial Access"
echo "# Coded by d1mov (Radostin Dimov)"
