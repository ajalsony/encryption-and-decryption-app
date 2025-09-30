import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asymmetric_padding
from cryptography.hazmat.backends import default_backend
import os
from datetime import datetime


# ==================== ENCRYPTION ENGINE ====================
class EncryptionEngine:
    """Handles all encryption/decryption operations"""
    
    def __init__(self):
        self.des_key = None
        self.rc4_key = None
        self.rsa_private_key = None
        self.rsa_public_key = None
        self.generate_des_key()
        self.generate_rc4_key()
        self.generate_rsa_keys()
    
    def generate_des_key(self):
        """Generate DES key (8 bytes for DES)"""
        self.des_key = os.urandom(8)  # 64-bit key for DES
    
    def generate_rc4_key(self):
        """Generate RC4 key (typically 5-256 bytes)"""
        self.rc4_key = os.urandom(16)  # 128-bit key for RC4
    
    def generate_rsa_keys(self):
        """Generate RSA public/private key pair"""
        self.rsa_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.rsa_public_key = self.rsa_private_key.public_key()
    
    def set_des_key(self, key_string):
        """Set DES key from user input"""
        try:
            # Try to decode as base64 first
            if len(key_string) % 4 == 0:  # Base64 encoded
                key_bytes = base64.b64decode(key_string)
            else:  # Raw string
                key_bytes = key_string.encode('utf-8')
            
            # DES requires exactly 8 bytes
            if len(key_bytes) != 8:
                # Pad or truncate to 8 bytes
                key_bytes = key_bytes[:8].ljust(8, b'\0')
            
            self.des_key = key_bytes
            return True
        except Exception as e:
            raise Exception(f"Invalid DES key: {str(e)}")
    
    def set_rc4_key(self, key_string):
        """Set RC4 key from user input"""
        try:
            # RC4 can use any length key (typically 5-256 bytes)
            if key_string.strip():
                self.rc4_key = key_string.encode('utf-8')
            else:
                raise Exception("RC4 key cannot be empty")
            return True
        except Exception as e:
            raise Exception(f"Invalid RC4 key: {str(e)}")
    
    def set_rsa_public_key(self, public_key_pem):
        """Set RSA public key from PEM string"""
        try:
            if not public_key_pem.strip():
                raise Exception("Public key cannot be empty")
            
            self.rsa_public_key = serialization.load_pem_public_key(
                public_key_pem.encode('utf-8'),
                backend=default_backend()
            )
            return True
        except Exception as e:
            raise Exception(f"Invalid RSA public key: {str(e)}")
    
    def set_rsa_private_key(self, private_key_pem):
        """Set RSA private key from PEM string"""
        try:
            if not private_key_pem.strip():
                raise Exception("Private key cannot be empty")
            
            self.rsa_private_key = serialization.load_pem_private_key(
                private_key_pem.encode('utf-8'),
                password=None,
                backend=default_backend()
            )
            self.rsa_public_key = self.rsa_private_key.public_key()
            return True
        except Exception as e:
            raise Exception(f"Invalid RSA private key: {str(e)}")
    
    def get_des_key_b64(self):
        """Get DES key as base64 string"""
        return base64.b64encode(self.des_key).decode('utf-8')
    
    def get_rc4_key_hex(self):
        """Get RC4 key as hex string"""
        return self.rc4_key.hex()
    
    def get_rsa_public_key_pem(self):
        """Get RSA public key as PEM string"""
        return self.rsa_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
    
    def get_rsa_private_key_pem(self):
        """Get RSA private key as PEM string"""
        return self.rsa_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
    
    # ---------- DES METHODS ----------
    def des_encrypt(self, text):
        """Encrypt using DES CBC mode"""
        try:
            # Generate random IV
            iv = os.urandom(8)  # 64-bit IV for DES
            
            # Pad the data
            padder = padding.PKCS7(64).padder()
            padded_data = padder.update(text.encode('utf-8')) + padder.finalize()
            
            # Create cipher and encrypt
            cipher = Cipher(algorithms.TripleDES(self.des_key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
            
            # Combine IV and encrypted data
            result = base64.b64encode(iv + encrypted_data).decode('utf-8')
            return result
            
        except Exception as e:
            raise Exception(f"DES encryption failed: {str(e)}")
    
    def des_decrypt(self, text):
        """Decrypt using DES CBC mode"""
        try:
            # Decode from base64
            raw_data = base64.b64decode(text.encode('utf-8'))
            
            # Extract IV and encrypted data
            iv = raw_data[:8]  # First 8 bytes are IV
            encrypted_data = raw_data[8:]  # Rest is encrypted data
            
            # Decrypt
            cipher = Cipher(algorithms.TripleDES(self.des_key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
            
            # Unpad
            unpadder = padding.PKCS7(64).unpadder()
            decrypted_data = unpadder.update(padded_data) + unpadder.finalize()
            
            return decrypted_data.decode('utf-8')
            
        except Exception as e:
            raise Exception(f"DES decryption failed: {str(e)}")
    
    # ---------- RC4 METHODS ----------
    def rc4_encrypt(self, text):
        """Encrypt using RC4 stream cipher"""
        try:
            # Convert text to bytes
            plaintext = text.encode('utf-8')
            
            # RC4 encryption (XOR with keystream)
            encrypted_data = self._rc4_crypt(plaintext)
            
            # Encode as base64 for safe storage
            result = base64.b64encode(encrypted_data).decode('utf-8')
            return result
            
        except Exception as e:
            raise Exception(f"RC4 encryption failed: {str(e)}")
    
    def rc4_decrypt(self, text):
        """Decrypt using RC4 stream cipher"""
        try:
            # Decode from base64
            encrypted_data = base64.b64decode(text.encode('utf-8'))
            
            # RC4 decryption (same as encryption - XOR with keystream)
            decrypted_data = self._rc4_crypt(encrypted_data)
            
            return decrypted_data.decode('utf-8')
            
        except Exception as e:
            raise Exception(f"RC4 decryption failed: {str(e)}")
    
    def _rc4_crypt(self, data):
        """RC4 core algorithm - same for encryption and decryption"""
        # Initialize S-box
        S = list(range(256))
        j = 0
        
        # Key-scheduling algorithm (KSA)
        for i in range(256):
            j = (j + S[i] + self.rc4_key[i % len(self.rc4_key)]) % 256
            S[i], S[j] = S[j], S[i]  # swap
        
        # Pseudo-random generation algorithm (PRGA)
        i = j = 0
        result = bytearray()
        
        for byte in data:
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]  # swap
            k = S[(S[i] + S[j]) % 256]
            result.append(byte ^ k)
        
        return bytes(result)
    
    # ---------- RSA METHODS ----------
    def rsa_encrypt(self, text):
        """Encrypt using RSA OAEP"""
        try:
            if not self.rsa_public_key:
                raise Exception("RSA public key not set")
                
            # RSA can only encrypt small amounts of data
            if len(text.encode('utf-8')) > 190:  # RSA 2048 can encrypt ~190 bytes
                raise Exception("RSA encryption limited to ~190 characters. Use hybrid encryption for larger texts.")
            
            encrypted_data = self.rsa_public_key.encrypt(
                text.encode('utf-8'),
                asymmetric_padding.OAEP(
                    mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return base64.b64encode(encrypted_data).decode('utf-8')
            
        except Exception as e:
            raise Exception(f"RSA encryption failed: {str(e)}")
    
    def rsa_decrypt(self, text):
        """Decrypt using RSA OAEP"""
        try:
            if not self.rsa_private_key:
                raise Exception("RSA private key not set")
                
            encrypted_data = base64.b64decode(text.encode('utf-8'))
            
            decrypted_data = self.rsa_private_key.decrypt(
                encrypted_data,
                asymmetric_padding.OAEP(
                    mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return decrypted_data.decode('utf-8')
            
        except Exception as e:
            raise Exception(f"RSA decryption failed: {str(e)}")
    
    # ---------- CAESAR CIPHER METHODS (keeping for reference) ----------
    def caesar_encrypt(self, text, shift):
        return self._caesar_cipher(text, shift)
    
    def caesar_decrypt(self, text, shift):
        return self._caesar_cipher(text, -shift)
    
    def _caesar_cipher(self, text, shift):
        """Core Caesar cipher algorithm"""
        result = []
        for char in text:
            if char.isupper():
                result.append(chr((ord(char) + shift - 65) % 26 + 65))
            elif char.islower():
                result.append(chr((ord(char) + shift - 97) % 26 + 97))
            else:
                result.append(char)
        return ''.join(result)


# ==================== KEY MANAGEMENT DIALOGS ====================
class KeyManager:
    """Handles key input dialogs"""
    
    @staticmethod
    def show_des_key_dialog(parent, current_key_b64):
        """Show dialog for DES key input"""
        dialog = tk.Toplevel(parent)
        dialog.title("DES Key Configuration")
        dialog.geometry("500x200")
        dialog.transient(parent)
        dialog.grab_set()
        dialog.resizable(False, False)
        
        # Center the dialog
        dialog.update_idletasks()
        x = parent.winfo_rootx() + (parent.winfo_width() - dialog.winfo_width()) // 2
        y = parent.winfo_rooty() + (parent.winfo_height() - dialog.winfo_height()) // 2
        dialog.geometry(f"+{x}+{y}")
        
        main_frame = ttk.Frame(dialog, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(main_frame, text="DES Key (8 bytes):").pack(pady=10)
        
        key_var = tk.StringVar(value=current_key_b64)
        key_entry = ttk.Entry(main_frame, textvariable=key_var, width=50, font=("Courier", 10))
        key_entry.pack(pady=5)
        
        ttk.Label(main_frame, text="Enter 8 characters or base64 encoded 8-byte key", 
                 font=("Arial", 8), foreground="gray").pack()
        
        result = {"key": None}
        
        def on_ok():
            result["key"] = key_var.get().strip()
            dialog.destroy()
        
        def on_cancel():
            dialog.destroy()
        
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(pady=20)
        
        ttk.Button(button_frame, text="OK", command=on_ok).pack(side=tk.LEFT, padx=10)
        ttk.Button(button_frame, text="Cancel", command=on_cancel).pack(side=tk.LEFT, padx=10)
        
        dialog.wait_window()
        return result["key"]
    
    @staticmethod
    def show_rc4_key_dialog(parent, current_key_hex):
        """Show dialog for RC4 key input"""
        dialog = tk.Toplevel(parent)
        dialog.title("RC4 Key Configuration")
        dialog.geometry("500x200")
        dialog.transient(parent)
        dialog.grab_set()
        dialog.resizable(False, False)
        
        # Center the dialog
        dialog.update_idletasks()
        x = parent.winfo_rootx() + (parent.winfo_width() - dialog.winfo_width()) // 2
        y = parent.winfo_rooty() + (parent.winfo_height() - dialog.winfo_height()) // 2
        dialog.geometry(f"+{x}+{y}")
        
        main_frame = ttk.Frame(dialog, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(main_frame, text="RC4 Key (any length):").pack(pady=10)
        
        key_var = tk.StringVar(value=current_key_hex)
        key_entry = ttk.Entry(main_frame, textvariable=key_var, width=50, font=("Courier", 10))
        key_entry.pack(pady=5)
        
        ttk.Label(main_frame, text="Enter any text string as RC4 key", 
                 font=("Arial", 8), foreground="gray").pack()
        
        result = {"key": None}
        
        def on_ok():
            result["key"] = key_var.get().strip()
            dialog.destroy()
        
        def on_cancel():
            dialog.destroy()
        
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(pady=20)
        
        ttk.Button(button_frame, text="OK", command=on_ok).pack(side=tk.LEFT, padx=10)
        ttk.Button(button_frame, text="Cancel", command=on_cancel).pack(side=tk.LEFT, padx=10)
        
        dialog.wait_window()
        return result["key"]
    
    @staticmethod
    def show_rsa_key_dialog(parent, current_public_pem, current_private_pem):
        """Show dialog for RSA key input"""
        dialog = tk.Toplevel(parent)
        dialog.title("RSA Key Configuration")
        dialog.geometry("700x500")
        dialog.transient(parent)
        dialog.grab_set()
        
        # Center the dialog
        dialog.update_idletasks()
        x = parent.winfo_rootx() + (parent.winfo_width() - dialog.winfo_width()) // 2
        y = parent.winfo_rooty() + (parent.winfo_height() - dialog.winfo_height()) // 2
        dialog.geometry(f"+{x}+{y}")
        
        main_frame = ttk.Frame(dialog, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill=tk.BOTH, expand=True)
        
        # Public Key Tab
        public_frame = ttk.Frame(notebook, padding="10")
        notebook.add(public_frame, text="Public Key")
        
        ttk.Label(public_frame, text="RSA Public Key (PEM format):").pack(pady=10)
        
        public_text = scrolledtext.ScrolledText(public_frame, width=80, height=15, font=("Courier", 9))
        public_text.pack(fill=tk.BOTH, expand=True)
        public_text.insert("1.0", current_public_pem)
        
        # Private Key Tab
        private_frame = ttk.Frame(notebook, padding="10")
        notebook.add(private_frame, text="Private Key")
        
        ttk.Label(private_frame, text="RSA Private Key (PEM format):").pack(pady=10)
        
        private_text = scrolledtext.ScrolledText(private_frame, width=80, height=15, font=("Courier", 9))
        private_text.pack(fill=tk.BOTH, expand=True)
        private_text.insert("1.0", current_private_pem)
        
        result = {"public_key": None, "private_key": None}
        
        def on_ok():
            result["public_key"] = public_text.get("1.0", tk.END).strip()
            result["private_key"] = private_text.get("1.0", tk.END).strip()
            dialog.destroy()
        
        def on_cancel():
            dialog.destroy()
        
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(pady=10)
        
        ttk.Button(button_frame, text="OK", command=on_ok).pack(side=tk.LEFT, padx=10)
        ttk.Button(button_frame, text="Cancel", command=on_cancel).pack(side=tk.LEFT, padx=10)
        
        dialog.wait_window()
        return result["public_key"], result["private_key"]


# ==================== FILE MANAGER ====================
class FileManager:
    """Handles file operations for saving and loading encrypted/decrypted data"""
    
    @staticmethod
    def save_file(content, default_extension=".txt"):
        """Save content to file with various format options"""
        try:
            # File type options
            file_types = [
                ("Text files", "*.txt"),
                ("Encrypted files", "*.enc"),
                ("All files", "*.*"),
                ("JSON files", "*.json"),
                ("XML files", "*.xml"),
                ("CSV files", "*.csv"),
                ("Log files", "*.log")
            ]
            
            # Ask user for file location
            filename = filedialog.asksaveasfilename(
                title="Save File As",
                defaultextension=default_extension,
                filetypes=file_types
            )
            
            if not filename:  # User cancelled
                return None
            
            # Write content to file
            with open(filename, 'w', encoding='utf-8') as file:
                file.write(content)
            
            return filename
            
        except Exception as e:
            raise Exception(f"Failed to save file: {str(e)}")
    
    @staticmethod
    def load_file():
        """Load content from file"""
        try:
            file_types = [
                ("Text files", "*.txt"),
                ("Encrypted files", "*.enc"),
                ("All files", "*.*"),
                ("JSON files", "*.json"),
                ("XML files", "*.xml")
            ]
            
            filename = filedialog.askopenfilename(
                title="Open File",
                filetypes=file_types
            )
            
            if not filename:  # User cancelled
                return None, None
            
            # Read content from file
            with open(filename, 'r', encoding='utf-8') as file:
                content = file.read()
            
            return content, filename
            
        except Exception as e:
            raise Exception(f"Failed to load file: {str(e)}")
    
    @staticmethod
    def create_file_header(method, operation, timestamp):
        """Create a header with metadata for saved files"""
        header = f"""
=== Encryption Tool Output ===
Method: {method.upper()}
Operation: {operation}
Timestamp: {timestamp}
================================

"""
        return header


# ==================== USER INTERFACE ====================
class EncryptionUI:
    """Handles all user interface components"""
    
    def __init__(self, root, engine, file_manager):
        self.root = root
        self.engine = engine
        self.file_manager = file_manager
        self.setup_window()
        self.create_widgets()
    
    def setup_window(self):
        """Configure main window properties"""
        self.root.title("DES, RSA & RC4 Encryption App")
        self.root.geometry("800x750")
        self.root.resizable(True, True)
        
        # Center the window on screen
        self.center_window()
    
    def center_window(self):
        """Center the main window on screen"""
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')
    
    def create_widgets(self):
        """Create and arrange all UI elements"""
        self.create_main_frame()
        self.create_title_section()
        self.create_input_section()
        self.create_method_section()
        self.create_parameter_section()
        self.create_key_management_section()
        self.create_button_section()
        self.create_output_section()
        self.create_status_bar()
    
    def create_main_frame(self):
        """Create main container frame"""
        self.main_frame = ttk.Frame(self.root, padding="20")
        self.main_frame.pack(fill=tk.BOTH, expand=True)
    
    def create_title_section(self):
        """Create application title"""
        title_frame = ttk.Frame(self.main_frame)
        title_frame.pack(fill=tk.X, pady=(0, 20))
        
        title_label = ttk.Label(title_frame, 
                               text="DES, RSA & RC4 Encryption Tool", 
                               font=("Arial", 18, "bold"))
        title_label.pack()
        
        subtitle_label = ttk.Label(title_frame,
                                  text="Secure Encryption and Decryption Application",
                                  font=("Arial", 10),
                                  foreground="gray")
        subtitle_label.pack()
    
    def create_input_section(self):
        """Create text input area"""
        input_container = ttk.Frame(self.main_frame)
        input_container.pack(fill=tk.X, pady=(0, 15))
        
        # Input header with label and button
        input_header = ttk.Frame(input_container)
        input_header.pack(fill=tk.X)
        
        input_label = ttk.Label(input_header, text="Input Text:", font=("Arial", 10, "bold"))
        input_label.pack(side=tk.LEFT)
        
        self.load_input_btn = ttk.Button(input_header, text="Load from File", width=15)
        self.load_input_btn.pack(side=tk.RIGHT)
        
        self.input_text = scrolledtext.ScrolledText(input_container, 
                                                   width=80, height=6,
                                                   font=("Consolas", 10))
        self.input_text.pack(fill=tk.BOTH, expand=True, pady=(5, 0))
    
    def create_method_section(self):
        """Create encryption method selection"""
        method_container = ttk.LabelFrame(self.main_frame, text="Encryption Method", padding="15")
        method_container.pack(fill=tk.X, pady=(0, 15))
        
        # Center the radio buttons
        radio_frame = ttk.Frame(method_container)
        radio_frame.pack()
        
        self.method_var = tk.StringVar(value="rc4")
        methods = [
            ("RC4 (Stream Cipher)", "rc4"),
            ("DES (Symmetric)", "des"), 
            ("RSA (Asymmetric)", "rsa"), 
            ("Caesar Cipher", "caesar")
        ]
        
        for i, (text, value) in enumerate(methods):
            ttk.Radiobutton(radio_frame, text=text, 
                           variable=self.method_var, value=value,
                           command=self.on_method_change
                           ).grid(row=0, column=i, padx=15)
    
    def create_parameter_section(self):
        """Create parameter inputs for specific methods"""
        self.param_container = ttk.Frame(self.main_frame)
        self.param_container.pack(fill=tk.X, pady=(0, 15))
        
        # Caesar cipher parameters
        self.caesar_frame = ttk.Frame(self.param_container)
        
        shift_label = ttk.Label(self.caesar_frame, text="Shift amount:")
        shift_label.pack(side=tk.LEFT, padx=(0, 5))
        
        self.shift_var = tk.StringVar(value="3")
        self.shift_entry = ttk.Entry(self.caesar_frame, 
                                    textvariable=self.shift_var, width=5)
        self.shift_entry.pack(side=tk.LEFT)
        
        # RSA info label
        self.rsa_info_label = ttk.Label(self.param_container, 
                                       text="⚠️ RSA encryption limited to ~190 characters",
                                       foreground="orange",
                                       font=("Arial", 9))
        
        # RC4 info label
        self.rc4_info_label = ttk.Label(self.param_container, 
                                       text="🔒 RC4: Fast stream cipher - same key for encryption/decryption",
                                       foreground="green",
                                       font=("Arial", 9))
    
    def create_key_management_section(self):
        """Create key management buttons"""
        key_container = ttk.LabelFrame(self.main_frame, text="Key Management", padding="15")
        key_container.pack(fill=tk.X, pady=(0, 15))
        
        # Center the key management buttons
        key_button_frame = ttk.Frame(key_container)
        key_button_frame.pack()
        
        self.manage_rc4_btn = ttk.Button(key_button_frame, text="Manage RC4 Key", width=18)
        self.manage_rc4_btn.grid(row=0, column=0, padx=8)
        
        self.manage_des_btn = ttk.Button(key_button_frame, text="Manage DES Key", width=18)
        self.manage_des_btn.grid(row=0, column=1, padx=8)
        
        self.manage_rsa_btn = ttk.Button(key_button_frame, text="Manage RSA Keys", width=18)
        self.manage_rsa_btn.grid(row=0, column=2, padx=8)
        
        self.generate_keys_btn = ttk.Button(key_button_frame, text="Generate New Keys", width=18)
        self.generate_keys_btn.grid(row=0, column=3, padx=8)
        
        # Current key status - centered
        key_status_frame = ttk.Frame(key_container)
        key_status_frame.pack(fill=tk.X, pady=(10, 0))
        
        self.key_status_var = tk.StringVar(value="Using auto-generated keys")
        key_status_label = ttk.Label(key_status_frame, textvariable=self.key_status_var, 
                                   font=("Arial", 9), foreground="blue")
        key_status_label.pack()
    
    def create_button_section(self):
        """Create action buttons"""
        button_container = ttk.Frame(self.main_frame)
        button_container.pack(fill=tk.X, pady=(0, 15))
        
        # Center the operation buttons
        button_frame = ttk.Frame(button_container)
        button_frame.pack()
        
        self.encrypt_btn = ttk.Button(button_frame, text="🔒 Encrypt", width=15)
        self.encrypt_btn.grid(row=0, column=0, padx=10)
        
        self.decrypt_btn = ttk.Button(button_frame, text="🔓 Decrypt", width=15)  
        self.decrypt_btn.grid(row=0, column=1, padx=10)
        
        self.clear_btn = ttk.Button(button_frame, text="🗑️ Clear", width=15)
        self.clear_btn.grid(row=0, column=2, padx=10)
    
    def create_output_section(self):
        """Create result output area"""
        output_container = ttk.Frame(self.main_frame)
        output_container.pack(fill=tk.BOTH, expand=True, pady=(0, 15))
        
        # Output header with label and button
        output_header = ttk.Frame(output_container)
        output_header.pack(fill=tk.X)
        
        output_label = ttk.Label(output_header, text="Result:", font=("Arial", 10, "bold"))
        output_label.pack(side=tk.LEFT)
        
        button_frame = ttk.Frame(output_header)
        button_frame.pack(side=tk.RIGHT)
        
        self.copy_btn = ttk.Button(button_frame, text="📋 Copy", width=12)
        self.copy_btn.pack(side=tk.LEFT, padx=(0, 5))
        
        self.save_output_btn = ttk.Button(button_frame, text="💾 Save to File", width=15)
        self.save_output_btn.pack(side=tk.LEFT)
        
        self.output_text = scrolledtext.ScrolledText(output_container, 
                                                    width=80, height=6,
                                                    font=("Consolas", 10))
        self.output_text.pack(fill=tk.BOTH, expand=True, pady=(5, 0))
    
    def create_status_bar(self):
        """Create status bar at bottom"""
        status_container = ttk.Frame(self.main_frame)
        status_container.pack(fill=tk.X, pady=(10, 0))
        
        self.status_var = tk.StringVar(value="Ready - DES, RC4, and RSA keys generated")
        status_bar = ttk.Label(status_container, textvariable=self.status_var, 
                              relief=tk.SUNKEN, padding="5",
                              font=("Arial", 9))
        status_bar.pack(fill=tk.X)
    
    def on_method_change(self):
        """Handle method selection change"""
        self.update_parameters_display()
        method = self.method_var.get()
        self.update_key_status(method)
    
    def update_parameters_display(self):
        """Update which parameters are visible based on selected method"""
        # Hide all parameter frames first
        for widget in self.param_container.winfo_children():
            widget.pack_forget()
        
        method = self.method_var.get()
        
        if method == "caesar":
            self.caesar_frame.pack()
        elif method == "rsa":
            self.rsa_info_label.pack()
        elif method == "rc4":
            self.rc4_info_label.pack()
    
    def update_key_status(self, method):
        """Update key status display"""
        if method == "rc4":
            key_hex = self.engine.get_rc4_key_hex()
            self.key_status_var.set(f"🔑 RC4 Key: {key_hex[:16]}... (Hex)")
        elif method == "des":
            key_b64 = self.engine.get_des_key_b64()
            self.key_status_var.set(f"🔑 DES Key: {key_b64} (Base64)")
        elif method == "rsa":
            self.key_status_var.set("🔑 RSA: Using current key pair")


# ==================== MAIN CONTROLLER ====================
class EncryptionApp:
    """Main controller that connects UI and Engine"""
    
    def __init__(self, root):
        self.root = root
        self.engine = EncryptionEngine()
        self.file_manager = FileManager()
        self.key_manager = KeyManager()
        self.ui = EncryptionUI(root, self.engine, self.file_manager)
        
        self.bind_events()
        self.ui.update_parameters_display()
        self.ui.update_key_status("rc4")
    
    def bind_events(self):
        """Connect UI events to controller methods"""
        self.ui.encrypt_btn.config(command=self.encrypt)
        self.ui.decrypt_btn.config(command=self.decrypt) 
        self.ui.clear_btn.config(command=self.clear)
        self.ui.copy_btn.config(command=self.copy_result)
        self.ui.generate_keys_btn.config(command=self.generate_new_keys)
        self.ui.save_output_btn.config(command=self.save_output)
        self.ui.load_input_btn.config(command=self.load_input)
        self.ui.manage_rc4_btn.config(command=self.manage_rc4_key)
        self.ui.manage_des_btn.config(command=self.manage_des_key)
        self.ui.manage_rsa_btn.config(command=self.manage_rsa_keys)
    
    def manage_rc4_key(self):
        """Manage RC4 key"""
        try:
            current_key = self.engine.get_rc4_key_hex()
            new_key = self.key_manager.show_rc4_key_dialog(self.root, current_key)
            
            if new_key:
                self.engine.set_rc4_key(new_key)
                self.ui.update_key_status("rc4")
                self.ui.status_var.set("RC4 key updated successfully")
                messagebox.showinfo("Success", "RC4 key updated successfully!")
                
        except Exception as e:
            self.handle_error("RC4 key configuration failed", e)
    
    def manage_des_key(self):
        """Manage DES key"""
        try:
            current_key = self.engine.get_des_key_b64()
            new_key = self.key_manager.show_des_key_dialog(self.root, current_key)
            
            if new_key:
                self.engine.set_des_key(new_key)
                self.ui.update_key_status("des")
                self.ui.status_var.set("DES key updated successfully")
                messagebox.showinfo("Success", "DES key updated successfully!")
                
        except Exception as e:
            self.handle_error("DES key configuration failed", e)
    
    def manage_rsa_keys(self):
        """Manage RSA keys"""
        try:
            current_public = self.engine.get_rsa_public_key_pem()
            current_private = self.engine.get_rsa_private_key_pem()
            
            public_key, private_key = self.key_manager.show_rsa_key_dialog(
                self.root, current_public, current_private
            )
            
            if public_key and private_key:
                self.engine.set_rsa_public_key(public_key)
                self.engine.set_rsa_private_key(private_key)
                self.ui.update_key_status("rsa")
                self.ui.status_var.set("RSA keys updated successfully")
                messagebox.showinfo("Success", "RSA keys updated successfully!")
            elif public_key:
                self.engine.set_rsa_public_key(public_key)
                self.ui.update_key_status("rsa")
                self.ui.status_var.set("RSA public key updated successfully")
                messagebox.showinfo("Success", "RSA public key updated successfully!")
            elif private_key:
                self.engine.set_rsa_private_key(private_key)
                self.ui.update_key_status("rsa")
                self.ui.status_var.set("RSA private key updated successfully")
                messagebox.showinfo("Success", "RSA private key updated successfully!")
                
        except Exception as e:
            self.handle_error("RSA key configuration failed", e)
    
    def encrypt(self):
        """Handle encrypt button click"""
        try:
            # Get input data
            input_data = self.ui.input_text.get("1.0", tk.END).strip()
            if not input_data:
                messagebox.showwarning("Warning", "Please enter text to encrypt")
                return
            
            # Route to appropriate encryption method
            method = self.ui.method_var.get()
            result = self.route_encryption(method, input_data)
            
            # Display result
            self.display_result(result)
            self.ui.status_var.set(f"✅ Text encrypted successfully using {method.upper()}")
            
        except Exception as e:
            self.handle_error("Encryption failed", e)
    
    def decrypt(self):
        """Handle decrypt button click"""
        try:
            # Get input data
            input_data = self.ui.input_text.get("1.0", tk.END).strip()
            if not input_data:
                messagebox.showwarning("Warning", "Please enter text to decrypt")
                return
            
            # Route to appropriate decryption method
            method = self.ui.method_var.get()
            result = self.route_decryption(method, input_data)
            
            # Display result
            self.display_result(result)
            self.ui.status_var.set(f"✅ Text decrypted successfully using {method.upper()}")
            
        except Exception as e:
            self.handle_error("Decryption failed", e)
    
    def route_encryption(self, method, text):
        """Route to correct encryption method"""
        if method == "des":
            return self.engine.des_encrypt(text)
        elif method == "rc4":
            return self.engine.rc4_encrypt(text)
        elif method == "rsa":
            return self.engine.rsa_encrypt(text)
        elif method == "caesar":
            shift = int(self.ui.shift_var.get())
            return self.engine.caesar_encrypt(text, shift)
    
    def route_decryption(self, method, text):
        """Route to correct decryption method"""
        if method == "des":
            return self.engine.des_decrypt(text)
        elif method == "rc4":
            return self.engine.rc4_decrypt(text)
        elif method == "rsa":
            return self.engine.rsa_decrypt(text)
        elif method == "caesar":
            shift = int(self.ui.shift_var.get())
            return self.engine.caesar_decrypt(text, shift)
    
    def generate_new_keys(self):
        """Generate new encryption keys"""
        try:
            self.engine.generate_des_key()
            self.engine.generate_rc4_key()
            self.engine.generate_rsa_keys()
            self.ui.update_key_status(self.ui.method_var.get())
            self.ui.status_var.set("🔄 New DES, RC4, and RSA keys generated successfully")
            messagebox.showinfo("Success", "New encryption keys generated!")
        except Exception as e:
            self.handle_error("Key generation failed", e)
    
    def save_output(self):
        """Save output result to file"""
        try:
            result = self.ui.output_text.get("1.0", tk.END).strip()
            if not result:
                messagebox.showwarning("Warning", "No result to save")
                return
            
            # Create file content with header
            method = self.ui.method_var.get()
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            operation = "Encryption" if any(word in self.ui.status_var.get().lower() for word in ['encrypt', 'encrypted']) else "Decryption"
            
            header = self.file_manager.create_file_header(method, operation, timestamp)
            full_content = header + result
            
            # Choose file extension based on content type
            default_extension = ".enc" if operation == "Encryption" else ".txt"
            
            # Save file
            filename = self.file_manager.save_file(full_content, default_extension)
            
            if filename:
                self.ui.status_var.set(f"💾 Result saved to: {filename}")
                messagebox.showinfo("Success", f"File saved successfully!\n{filename}")
            
        except Exception as e:
            self.handle_error("Save failed", e)
    
    def load_input(self):
        """Load content from file into input area"""
        try:
            content, filename = self.file_manager.load_file()
            
            if content and filename:
                self.ui.input_text.delete("1.0", tk.END)
                self.ui.input_text.insert("1.0", content)
                self.ui.status_var.set(f"📂 File loaded: {filename}")
                
        except Exception as e:
            self.handle_error("Load failed", e)
    
    def display_result(self, result):
        """Display result in output area"""
        self.ui.output_text.delete("1.0", tk.END)
        self.ui.output_text.insert("1.0", result)
    
    def clear(self):
        """Clear all fields"""
        self.ui.input_text.delete("1.0", tk.END)
        self.ui.output_text.delete("1.0", tk.END)
        self.ui.status_var.set("🗑️ Cleared - Keys remain active")
    
    def copy_result(self):
        """Copy result to clipboard"""
        result = self.ui.output_text.get("1.0", tk.END).strip()
        if result:
            self.root.clipboard_clear()
            self.root.clipboard_append(result)
            self.ui.status_var.set("📋 Result copied to clipboard")
        else:
            messagebox.showwarning("Warning", "No result to copy")
    
    def handle_error(self, message, exception):
        """Handle and display errors"""
        messagebox.showerror("Error", f"{message}: {str(exception)}")
        self.ui.status_var.set(f"❌ {message}")


# ==================== APPLICATION ENTRY POINT ====================
def main():
    """Initialize and run the application"""
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()