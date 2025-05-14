# Advanced Encryption Tool

A user-friendly desktop application for secure encryption and decryption using AES-256 and other cryptographic algorithms.

## Features

- AES-256 encryption and decryption
- Support for file encryption/decryption
- Support for text encryption/decryption
- Password-based key derivation
- Activity logging and reporting
- Export reports in multiple formats (CSV, JSON, PDF)
- Modern, intuitive user interface
- Cross-platform compatibility

## Requirements

- Python 3.7+
- Dependencies listed in requirements.txt

## Installation

1. Clone or download this repository
2. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

## Usage

Run the application:
```
python encryption_app_tkinter.py
```

### Text Encryption
1. Go to the "Text Encryption" tab
2. Enter your password
3. Type or paste the text you want to encrypt
4. Click "Encrypt"
5. Copy the encrypted result with the "Copy to Clipboard" button

### File Encryption
1. Go to the "File Encryption" tab
2. Select "Encrypt" operation
3. Enter your password
4. Browse for the input file you want to encrypt
5. Choose where to save the encrypted file
6. Click "Process File"

### Reports
1. Go to the "Reports" tab to view your encryption/decryption activity log
2. Export your activity log in various formats:
   - CSV: For spreadsheet applications
   - JSON: For data processing
   - PDF: For professional reports with formatting
3. Use the "Clear Log" button to reset your activity history

## Security Notes

- This tool uses industry-standard encryption algorithms
- Always remember your password - there is no way to recover encrypted data without it
- For maximum security, use strong, unique passwords
