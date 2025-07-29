# DES Encryption/Decryption in C++

This project is a full implementation of the **Data Encryption Standard (DES)** in C++, developed for educational and cryptographic learning purposes.

## 🔐 Features
- Encrypts/Decrypts 64-bit (16 hex chars) blocks
- Uses 64-bit keys (with 8 parity bits)
- Full 16-round Feistel structure
- S-Boxes, permutations, key schedule
- CLI-based interface with input validation

## 🧪 Usage

```bash
g++ DES.cpp -o des
./des
```

You’ll be prompted to:
1. Select mode: encrypt (`e`) or decrypt (`d`)
2. Enter 16-character hexadecimal input (plaintext or ciphertext)
3. Enter 16-character hexadecimal key

## 📁 Structure
- `DES.cpp`: Core implementation with all DES internals
- `README.md`: This file
- `Makefile`: Easy build and run

## ⚠️ Note
DES is no longer secure for modern systems. This is for learning purposes only.

## 🧠 Author
Ahmed – Cybersecurity & C++ Enthusiast
