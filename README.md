# Overview
Python GUI based tool to generate lnk files with a payload and decoy files embedded inside. This is NOT an external payload stager! While I have seen many LNK files utilized to download external payloads, evillnk gets around this issue and takes lnk file capabilities to the next level by taking a payload file and decoy file as input, converts them to XOR encrypted bytes and append them at the end of the lnk file. Both files are decrypted and fired on runtime. Should work on any OS with Python3 and PyQt6 installed. However, I did my tests on Kali Linux 2024.1.

To be used for penetration testing or educational purposes only!

Please note that this project is an early state. As such, you might find bugs, flaws or mulfunctions.
Use it at your own risk!

# Features:
- Embeds payload and decoy file inside the lnk file
- Simple and easy to use GUI
- 3 Different Payload Types: Executable, Dynamic-link library (dll), PowerShell Script
- 6 Different display icons: DOC, TXT, JPG, ZIP, MP3, Folder
- XOR Dynamic Encryption
- Spoofs File Description

# Preview
<details>
  <summary>See Screenshot</summary>

![alt text](https://github.com/v1kkz/evillnk/blob/main/img/screenshot.png)
</details>

See below video for a short PoC Demo (Recorded on 25 May 2024):

https://www.youtube.com/watch?v=RfsmGnMS-HE

# Requirements:
- Make sure python3 is installed in Linux or Windows
- PyQt6

Both can be installed with the provided `install.sh` script. Follow the guide in the `Installation` section.

# Installation
You can download the latest version of evillnk by cloning the GitHub repository:
```
git clone https://github.com/d1mov/evillnk
```

If you would like to run `evillnk` from anywhere in your system or access it through the Kali applications panel (08-Exploitation Tools) you can install it with the provided `install.sh` script:
```
cd evillnk
chmod +x install.sh
./install.sh
```

# Notes/Issues
- Most of the files generated by this tool will be detected by Windows Defender and other AV solutions, therefore please don't posting an issue stating "DETECTED!!!". Learn how to hide your payloads, then come back and utilize this tool...
- Some parts of the code are messy, and there are likely many bugs.. Please test everything in advance, and PLEASE provide as much information as possible when opening an issue. Thanks!

**Planned Updates**
- Implement persistence feature
- Add more display icons
- Fix numerous bugs by learning to program better, lol...

# Disclaimer
Usage of evillnk for attacking targets without prior mutual consent is illegal.
It is the end user's responsibility to obey all applicable local, state and federal laws.
I assume NO liability and I am NOT responsible for any misuse or damage caused by this tool.

# Credits:
* [@maddev-engenuity](https://mitre-engenuity.org/) for providing the APT29 lnk exploit emulation scripts.
