#!/usr/bin/env python3
"""
Script to fix corrupt uploaded_files.json
Attempts to recover as much data as possible from corrupt JSON file
"""

import json
import re
import os
from datetime import datetime

UPLOADED_FILES_FILE = "uploaded_files.json"
BACKUP_FILE = f"{UPLOADED_FILES_FILE}.corrupt_backup"
OUTPUT_FILE = f"{UPLOADED_FILES_FILE}.fixed"

def fix_corrupt_json():
    if not os.path.exists(UPLOADED_FILES_FILE):
        print(f"Error: {UPLOADED_FILES_FILE} not found")
        return False

    # Backup the corrupt file
    print(f"Creating backup at {BACKUP_FILE}...")
    with open(UPLOADED_FILES_FILE, 'r') as f:
        corrupt_content = f.read()

    with open(BACKUP_FILE, 'w') as f:
        f.write(corrupt_content)

    print(f"Backed up corrupt file to {BACKUP_FILE}")
    print(f"File size: {len(corrupt_content)} bytes")

    # Try to extract individual file entries using regex
    print("\nAttempting to extract file entries...")

    # Pattern to match individual file entries
    pattern = r'"([^"]+)":\s*{([^}]+(?:{[^}]*}[^}]*)*?)}'

    recovered_files = {}
    matches = re.finditer(pattern, corrupt_content)

    for match in matches:
        filename = match.group(1)
        entry_content = match.group(2)

        try:
            # Try to parse this entry
            entry_json = "{" + entry_content + "}"
            entry_data = json.loads(entry_json)
            recovered_files[filename] = entry_data
            print(f"✓ Recovered: {filename}")
        except:
            print(f"✗ Failed: {filename}")
            continue

    print(f"\nRecovered {len(recovered_files)} out of ? files")

    if recovered_files:
        # Save recovered data
        print(f"\nSaving recovered data to {OUTPUT_FILE}...")
        with open(OUTPUT_FILE, 'w') as f:
            json.dump(recovered_files, f, indent=2)

        print(f"✓ Saved {len(recovered_files)} files to {OUTPUT_FILE}")

        # Validate the output
        print("\nValidating output file...")
        try:
            with open(OUTPUT_FILE, 'r') as f:
                test_load = json.load(f)
            print(f"✓ Output file is valid JSON with {len(test_load)} entries")

            # Ask user if they want to replace original
            print("\n" + "="*60)
            print("Recovery successful!")
            print("="*60)
            print(f"Original (corrupt): {UPLOADED_FILES_FILE}")
            print(f"Backup: {BACKUP_FILE}")
            print(f"Fixed: {OUTPUT_FILE}")
            print("\nTo use the fixed file, run:")
            print(f"  mv {UPLOADED_FILES_FILE} {UPLOADED_FILES_FILE}.old")
            print(f"  mv {OUTPUT_FILE} {UPLOADED_FILES_FILE}")

            return True

        except Exception as e:
            print(f"✗ Error validating output: {e}")
            return False
    else:
        print("\n✗ Could not recover any data")
        print("\nStarting fresh database:")
        print(f"  mv {UPLOADED_FILES_FILE} {UPLOADED_FILES_FILE}.old")
        print(f"  echo '{{}}' > {UPLOADED_FILES_FILE}")
        return False

if __name__ == "__main__":
    print("="*60)
    print("JSON Recovery Tool for CloudShare")
    print("="*60)
    print()

    fix_corrupt_json()
