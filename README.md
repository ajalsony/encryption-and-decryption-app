# 🔐 Encryption and Decryption App

A comprehensive desktop application providing multiple encryption and decryption methods with a user-friendly graphical interface. Built with Python and Tkinter, this tool offers both educational and practical cryptographic capabilities for secure data protection.

![Encryption Tool](https://img.shields.io/badge/Platform-Windows%20%7C%20macOS%20%7C%20Linux-blue)
![Python](https://img.shields.io/badge/Python-3.6%2B-green)
![License](https://img.shields.io/badge/License-MIT-yellow)

## ✨ Features

### 🔒 Multiple Encryption Algorithms
- **RC4**: Fast stream cipher with variable-length keys
- **DES**: Secure block cipher with CBC mode and Triple DES
- **RSA**: Asymmetric encryption with 2048-bit key pairs
- **Caesar Cipher**: Historical cipher for educational purposes

### 🎯 User-Friendly Interface
- **Centered, professional layout** with intuitive controls
- **Real-time key management** for all algorithms
- **Visual feedback** with emojis and color-coded status
- **Responsive design** that adapts to different screen sizes

### 🔑 Advanced Key Management
- **Auto-generate secure keys** with one click
- **Custom key input** for all encryption methods
- **PEM format support** for RSA key pairs
- **Key status display** showing current active keys

### 💾 File Operations
- **Multiple format support**: TXT, ENC, JSON, XML, CSV, LOG
- **Smart file extensions** (.enc for encrypted, .txt for decrypted)
- **Metadata headers** with timestamps and encryption details
- **UTF-8 encoding** for international character support

## 🚀 Quick Start

### Prerequisites
- Python 3.6 or higher
- `cryptography` library

### Installation
```bash
# Clone the repository
git clone https://github.com/yourusername/encryption-tool.git
cd encryption-tool

# Install dependencies
pip install cryptography

# Run the application
python encryption_app.py
