# WRANSCAN 🔍  

![WRANSCAN](https://img.shields.io/badge/Wrancorp-WRANSCAN-blue?style=flat-square)
![Version](https://img.shields.io/badge/Version-1.0-blue)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey)
![License](https://img.shields.io/badge/License-MIT-green)

## 🚀 About WRANSCAN
**WRANSCAN** is a powerful **forensic security tool** developed by **WRANCORP** to scan and analyze files for malware threats using **VirusTotal API**. It helps security analysts and incident responders quickly detect suspicious files in **Windows** and **Linux** environments.

### ✨ Features
✔️ **Automatic Malware Detection** via VirusTotal  
✔️ **Multi-Platform Support** (Windows & Linux)  
✔️ **Fast Hash Scanning** with MD5  
✔️ **Real-Time Detection Reports**  
✔️ **CSV Log Export for Analysis**  
✔️ **Customizable File Extensions** to scan  

## 🛠️ Installation
### 🔹 **Clone the Repository**
```bash
git clone https://github.com/YOUR_USERNAME/WRANSCAN.git
cd WRANSCAN
```
### Install Dependencies
```pip install -r requirements.txt
```

### Set Up VirusTotal API Key
#### Edit settings/config.json and add your API key:
```{
    "VT_API_KEY": "YOUR_VIRUSTOTAL_API_KEY",
    "FILE_EXTENSIONS": [".exe", ".dll", ".bat", ".sh", ".ps1"],
    "STARTING_PATH": "/home/user/scans"
}
```

## Usage

```python main.py

```

## 📊 Example Output
```
[ALERT] trojan.exe | 27/64 | Suspicious Behavior, Packed Binary | /home/user/trojan.exe
[CLEAN] safe_file.txt | 0/0 | /home/user/documents/safe_file.txt
```

## ⚠️ Disclaimer
###WRANSCAN is a forensic tool for security analysis & educational purposes only. The developers are not responsible for any misuse.

## 📩 Contact & Support

### 🔹 Twitter/X: @WRANCORP
### 🔹 Homepage: https://www.wrancorp.com
### 🔹 Developer: @iampopg