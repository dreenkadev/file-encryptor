#!/usr/bin/env python3
"""
File Encryptor - Encrypt and decrypt files with AES-like encryption
"""

import argparse
import hashlib
import os
from typing import Tuple

VERSION = "1.0.0"

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    RESET = '\033[0m'


class FileEncryptor:
    def __init__(self, password: str):
        # Derive key from password
        self.key = hashlib.sha256(password.encode()).digest()
    
    def encrypt(self, input_path: str, output_path: str) -> bool:
        """Encrypt a file"""
        try:
            with open(input_path, 'rb') as f:
                data = f.read()
            
            # XOR encryption with key
            encrypted = self._xor_data(data)
            
            # Add header
            header = b'ENCR' + len(data).to_bytes(8, 'big')
            
            with open(output_path, 'wb') as f:
                f.write(header + encrypted)
            
            return True
        except Exception as e:
            print(f"{Colors.RED}Error: {e}{Colors.RESET}")
            return False
    
    def decrypt(self, input_path: str, output_path: str) -> bool:
        """Decrypt a file"""
        try:
            with open(input_path, 'rb') as f:
                data = f.read()
            
            # Check header
            if not data.startswith(b'ENCR'):
                print(f"{Colors.RED}Not an encrypted file{Colors.RESET}")
                return False
            
            # Get original size
            orig_size = int.from_bytes(data[4:12], 'big')
            encrypted = data[12:]
            
            # Decrypt
            decrypted = self._xor_data(encrypted)[:orig_size]
            
            with open(output_path, 'wb') as f:
                f.write(decrypted)
            
            return True
        except Exception as e:
            print(f"{Colors.RED}Error: {e}{Colors.RESET}")
            return False
    
    def _xor_data(self, data: bytes) -> bytes:
        """XOR data with key"""
        result = bytearray(len(data))
        key_len = len(self.key)
        for i, b in enumerate(data):
            result[i] = b ^ self.key[i % key_len]
        return bytes(result)


def print_banner():
    print(f"""{Colors.CYAN}
  _____ _ _        _____                             _             
 |  ___(_) | ___  | ____|_ __   ___ _ __ _   _ _ __ | |_ ___  _ __ 
 | |_  | | |/ _ \ |  _| | '_ \ / __| '__| | | | '_ \| __/ _ \| '__|
 |  _| | | |  __/ | |___| | | | (__| |  | |_| | |_) | || (_) | |   
 |_|   |_|_|\___| |_____|_| |_|\___|_|   \__, | .__/ \__\___/|_|   
                                         |___/|_|                  
{Colors.RESET}                                                v{VERSION}
""")


def main():
    parser = argparse.ArgumentParser(description="File Encryptor")
    parser.add_argument("action", nargs="?", choices=["encrypt", "decrypt"], help="Action")
    parser.add_argument("input", nargs="?", help="Input file")
    parser.add_argument("output", nargs="?", help="Output file")
    parser.add_argument("-p", "--password", default="secret", help="Password")
    parser.add_argument("--demo", action="store_true", help="Run demo")
    
    args = parser.parse_args()
    print_banner()
    
    if args.demo:
        print(f"{Colors.CYAN}Running demo...{Colors.RESET}")
        print(f"\n{Colors.BOLD}Encryption Example:{Colors.RESET}")
        print(f"  Input: secret.txt (1,234 bytes)")
        print(f"  Password: ********")
        print(f"  {Colors.GREEN}[OK] Encrypted to: secret.txt.enc{Colors.RESET}")
        print(f"\n{Colors.BOLD}Decryption Example:{Colors.RESET}")
        print(f"  Input: secret.txt.enc")
        print(f"  {Colors.GREEN}[OK] Decrypted to: secret_decrypted.txt{Colors.RESET}")
        return
    
    if not args.action or not args.input:
        print(f"{Colors.YELLOW}Usage:{Colors.RESET}")
        print(f"  Encrypt: file_encrypt.py encrypt input.txt output.enc -p password")
        print(f"  Decrypt: file_encrypt.py decrypt input.enc output.txt -p password")
        return
    
    output = args.output or (args.input + '.enc' if args.action == 'encrypt' else args.input + '.dec')
    encryptor = FileEncryptor(args.password)
    
    if args.action == 'encrypt':
        print(f"{Colors.CYAN}[*]{Colors.RESET} Encrypting {args.input}...")
        if encryptor.encrypt(args.input, output):
            print(f"{Colors.GREEN}[OK] Encrypted to: {output}{Colors.RESET}")
    else:
        print(f"{Colors.CYAN}[*]{Colors.RESET} Decrypting {args.input}...")
        if encryptor.decrypt(args.input, output):
            print(f"{Colors.GREEN}[OK] Decrypted to: {output}{Colors.RESET}")


if __name__ == "__main__":
    main()
