"""DISCLAIMER

Modification of this script is strictly prohibited unless authorized by WRANCORP or iampopg.

Contact Information:
📧 WRANCORP Email: wrancorp@gmail.com
🔗 Coder Contact (X & Telegram): @iampopg  
"""


import os,concurrent.futures
import hashlib
import requests
import json
import csv
import time
import art
import random
from tqdm import tqdm
from datetime import datetime
from colorama import Fore, Style, init
from sumy.parsers.plaintext import PlaintextParser
from sumy.nlp.tokenizers import Tokenizer
from sumy.summarizers.lsa import LsaSummarizer

# Initialize colorama for colored output
init(autoreset=True)


BLUE = Fore.BLUE
WHITE = Fore.WHITE
GREEN = Fore.GREEN
RED = Fore.RED
YELLOW = Fore.YELLOW

# fonts
fonts = ["doom", "speed", "starwars", "slant", "standard"]
font_ascii = random.choice(fonts)

# Generate ASCII Art
ascii_text = art.text2art("WRANSCAN", font=font_ascii)

# Banner
banner = f"""
{BLUE}[---]{WHITE}       Created by: WRANCORP                       {BLUE}[---]
{BLUE}[---]{WHITE}       Version: 1.0                         {BLUE}[---]
{BLUE}[---]{WHITE}       Follow us on X (Twitter): @WRANCORP        {BLUE}[---]
{BLUE}[---]{WHITE}       Homepage: https://www.wrancorp.com         {BLUE}[---]
{BLUE}[---]{WHITE}       Coder: @iampopg                            {BLUE}[---]
{WHITE}Welcome to WRANSCAN - The Ultimate Security Tool by WRANCORP x VirusTotal.
"""


print(f"{BLUE} + {ascii_text}" + banner)
print()

# Load settings from config.json
def load_settings():
    """Load API key and file extensions from settings/config.json."""
    config_path = "settings/config.json"

    if not os.path.exists(config_path):
        print(f"{RED}[ERROR]{WHITE} Configuration file not found: {config_path}")
        exit(1)

    try:
        with open(config_path, "r") as f:
            settings = json.load(f)

        # Ensure required fields exist
        required_keys = ["VT_API_KEY", "FILE_EXTENSIONS", "STARTING_PATH"]
        for key in required_keys:
            if key not in settings:
                print(f"{RED}[ERROR]{WHITE} Missing key in config.json: {key}")
                exit(1)

        return settings["VT_API_KEY"], set(settings["FILE_EXTENSIONS"]), settings["STARTING_PATH"]

    except json.JSONDecodeError:
        print(f"{RED}[ERROR]{WHITE} Invalid JSON format in config.json")
        exit(1)

# Load configuration
VT_API_KEY, FILE_EXTENSIONS, STARTING_PATH = load_settings()

# Determine scanning directory
START_DIR = STARTING_PATH if STARTING_PATH else ("C:\\" if os.name == "nt" else "/")

# Display scanning directory
print(f"\n{GREEN}[INFO]{WHITE} Scanning directory: {YELLOW}{START_DIR}\n")

# CSV Output file
timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
CSV_FILE = f"wranscan_results_{timestamp}.csv"

def get_md5(file_path):
    """Compute the MD5 hash of a file."""
    try:
        with open(file_path, "rb") as f:
            md5_hash = hashlib.md5()
            while chunk := f.read(8192):
                md5_hash.update(chunk)
        return md5_hash.hexdigest()
    except Exception:
        return None

import textwrap

def summarize_text(text, word_limit=5):
    """Extract first 5 important words from the reason."""
    words = text.split()[:word_limit]
    return " ".join(words) if words else "Unknown Threat"


def check_virustotal(md5_hash):
    """Query VirusTotal API for the given hash."""
    url = f"https://www.virustotal.com/api/v3/files/{md5_hash}"
    headers = {"x-apikey": VT_API_KEY}

    try:
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            data = response.json()
            attributes = data.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            reasons = attributes.get("crowdsourced_yara_results", [])

            detected_count = stats.get("malicious", 0)
            detected_ratio = f"{stats.get('malicious', 0)}/{sum(stats.values())}" if stats else "0/0"
            
            # Extract reasons & summarize
            reason_text = " ".join([r["description"] for r in reasons]) if reasons else "None"
            short_reason = summarize_text(reason_text, word_limit=5)

            return detected_count, detected_ratio, short_reason
        elif response.status_code == 404:
            return 0, "0/0", "Not found"
        elif response.status_code == 429:
            print(f"{Fore.RED}[ERROR]{Fore.WHITE} VirusTotal API rate limit exceeded. Try again later.")
            exit(1)
        else:
            return -1, "Error", f"API Error: {response.status_code}"

    except requests.ConnectionError:
        print(f"{Fore.RED}[ERROR]{Fore.WHITE} Failed to connect to VirusTotal API. Check your internet.")
        exit(1)

def scan_system(start_path):
    """Recursively scan directories and check files on VirusTotal."""
    print(f"{GREEN}[INFO]{WHITE} Scanning system for suspicious files...\n")
    
    file_list = []
    start_time = time.time()

    # Load fetch speed from config.json
    config_path = "settings/config.json"
    try:
        with open(config_path, "r") as f:
            settings = json.load(f)
        FETCH_SPEED = int(settings.get("SPEED", 5))  # Default to 5 threads if not set
    except Exception as e:
        print(f"{RED}[ERROR]{WHITE} Failed to load fetch speed from config.json: {e}")
        FETCH_SPEED = 5

    # Going through directories and collecting matching files
    for root, _, files in os.walk(start_path):
        for file in files:
            if any(file.lower().endswith(ext) for ext in FILE_EXTENSIONS):
                file_list.append(os.path.join(root, file))

    if not file_list:
        print(f"{YELLOW}[WARNING]{WHITE} No matching files found in the target directory.")
        return

    print(f"{GREEN}[INFO]{WHITE} Found {len(file_list)} files. Checking with VirusTotal using {FETCH_SPEED} threads...\n")

    # Prepare CSV file
    with open(CSV_FILE, mode="w", newline="", encoding="utf-8") as csvfile:
        csv_writer = csv.writer(csvfile)
        csv_writer.writerow(["File Name", "Detection Ratio", "Reasons", "File Path"])

        def process_file(file_path):
            file_name = os.path.basename(file_path)
            md5_hash = get_md5(file_path)

            if md5_hash:
                detected, detected_ratio, reasons = check_virustotal(md5_hash)

                if detected > 0:
                    print(f"{RED}[ALERT]{WHITE} {file_name} | {detected_ratio} | {reasons} | {file_path}")
                elif detected_ratio == "Error":
                    print(f"{YELLOW}[ERROR]{WHITE} {file_name} | {detected_ratio} | {file_path}")
                else:
                    print(f"{GREEN}[CLEAN]{WHITE} {file_name} | {detected_ratio} | {file_path}")

                csv_writer.writerow([file_name, detected_ratio, reasons, file_path])
            else:
                print(f"{YELLOW}[SKIPPED]{WHITE} {file_name} | ERROR | Could not compute hash | {file_path}")
                csv_writer.writerow([file_name, "ERROR", "Could not compute hash", file_path])

        # Use ThreadPoolExecutor to speed up VirusTotal queries
        with concurrent.futures.ThreadPoolExecutor(max_workers=FETCH_SPEED) as executor:
            list(tqdm(executor.map(process_file, file_list), total=len(file_list), desc="Checking files", unit="file"))

    scan_duration = round(time.time() - start_time, 2)
    print(f"\n{GREEN}[INFO]{WHITE} Scan complete! Results saved to: {CSV_FILE}")
    print(f"{GREEN}[INFO]{WHITE} Total files scanned: {len(file_list)}")
    print(f"{GREEN}[INFO]{WHITE} Scan duration: {scan_duration} seconds")
# Run
if __name__ == "__main__":
    scan_system(START_DIR)
