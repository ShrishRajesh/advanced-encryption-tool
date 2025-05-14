import os
import sys
import base64
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
import datetime
import json
import csv
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import secrets

class EncryptionWorker(threading.Thread):
    """Worker thread to handle encryption/decryption operations"""
    
    def __init__(self, mode, algorithm, password, input_data, input_type, callback, error_callback, output_path=None):
        super().__init__()
        self.mode = mode  # 'encrypt' or 'decrypt'
        self.algorithm = algorithm
        self.password = password
        self.input_data = input_data
        self.input_type = input_type  # 'text' or 'file'
        self.output_path = output_path
        self.callback = callback
        self.error_callback = error_callback
        
    def run(self):
        try:
            if self.input_type == 'file':
                if self.mode == 'encrypt':
                    result = self.encrypt_file(self.input_data, self.output_path, self.password, self.algorithm)
                    self.callback(f"File encrypted successfully: {result}")
                else:
                    result = self.decrypt_file(self.input_data, self.output_path, self.password, self.algorithm)
                    self.callback(f"File decrypted successfully: {result}")
            else:  # text
                if self.mode == 'encrypt':
                    result = self.encrypt_text(self.input_data, self.password, self.algorithm)
                    self.callback(result)
                else:
                    result = self.decrypt_text(self.input_data, self.password, self.algorithm)
                    self.callback(result)
        except Exception as e:
            self.error_callback(f"Error: {str(e)}")
    
    def derive_key(self, password, salt, algorithm):
        """Derive a key from password using PBKDF2"""
        key_length = 32  # 256 bits for AES-256
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=key_length,
            salt=salt,
            iterations=100000,
        )
        
        return kdf.derive(password.encode())
    
    def encrypt_text(self, plaintext, password, algorithm):
        """Encrypt text using the selected algorithm"""
        # Generate a random salt
        salt = os.urandom(16)
        
        # Generate a random IV (Initialization Vector)
        iv = os.urandom(16)
        
        # Derive key from password
        key = self.derive_key(password, salt, algorithm)
        
        # Pad the plaintext
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext.encode()) + padder.finalize()
        
        # Encrypt the padded plaintext
        if algorithm == 'AES-256':
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        else:
            # Default to AES-256
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
            
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        # Combine salt, IV, and ciphertext, then encode as base64
        result = base64.b64encode(salt + iv + ciphertext).decode('utf-8')
        
        return result
    
    def decrypt_text(self, ciphertext, password, algorithm):
        """Decrypt text using the selected algorithm"""
        # Decode the base64 ciphertext
        try:
            decoded = base64.b64decode(ciphertext)
        except:
            raise ValueError("Invalid encrypted data format")
        
        # Extract salt, IV, and ciphertext
        salt = decoded[:16]
        iv = decoded[16:32]
        actual_ciphertext = decoded[32:]
        
        # Derive key from password and salt
        key = self.derive_key(password, salt, algorithm)
        
        # Decrypt the ciphertext
        if algorithm == 'AES-256':
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        else:
            # Default to AES-256
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
            
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(actual_ciphertext) + decryptor.finalize()
        
        # Unpad the plaintext
        unpadder = padding.PKCS7(128).unpadder()
        try:
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
            return plaintext.decode('utf-8')
        except Exception as e:
            raise ValueError(f"Decryption failed. Incorrect password or corrupted data. Error: {str(e)}")
    
    def encrypt_file(self, input_file, output_file, password, algorithm):
        """Encrypt a file using the selected algorithm"""
        # Generate a random salt
        salt = os.urandom(16)
        
        # Generate a random IV (Initialization Vector)
        iv = os.urandom(16)
        
        # Derive key from password
        key = self.derive_key(password, salt, algorithm)
        
        # Read the input file
        with open(input_file, 'rb') as f:
            plaintext = f.read()
        
        # Pad the plaintext
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext) + padder.finalize()
        
        # Encrypt the padded plaintext
        if algorithm == 'AES-256':
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        else:
            # Default to AES-256
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
            
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        # Write salt, IV, and ciphertext to the output file
        with open(output_file, 'wb') as f:
            f.write(salt + iv + ciphertext)
        
        return output_file
    
    def decrypt_file(self, input_file, output_file, password, algorithm):
        """Decrypt a file using the selected algorithm"""
        # Read the input file
        with open(input_file, 'rb') as f:
            data = f.read()
        
        # Extract salt, IV, and ciphertext
        salt = data[:16]
        iv = data[16:32]
        ciphertext = data[32:]
        
        # Derive key from password and salt
        key = self.derive_key(password, salt, algorithm)
        
        # Decrypt the ciphertext
        if algorithm == 'AES-256':
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        else:
            # Default to AES-256
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
            
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Unpad the plaintext
        unpadder = padding.PKCS7(128).unpadder()
        try:
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
            
            # Write the plaintext to the output file
            with open(output_file, 'wb') as f:
                f.write(plaintext)
                
            return output_file
        except Exception as e:
            raise ValueError(f"Decryption failed. Incorrect password or corrupted data. Error: {str(e)}")


class EncryptionApp:
    """Main application window"""
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Encryption Tool")
        self.root.geometry("800x600")
        self.root.minsize(800, 600)
        
        # Initialize activity log
        self.activity_log = []
        self.log_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "encryption_activity.log")
        self.load_activity_log()
        
        # Set up the main notebook (tabs)
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create tabs
        self.text_tab = ttk.Frame(self.notebook)
        self.file_tab = ttk.Frame(self.notebook)
        self.report_tab = ttk.Frame(self.notebook)
        
        self.notebook.add(self.text_tab, text="Text Encryption")
        self.notebook.add(self.file_tab, text="File Encryption")
        self.notebook.add(self.report_tab, text="Reports")
        
        # Set up the text encryption tab
        self.setup_text_tab()
        
        # Set up the file encryption tab
        self.setup_file_tab()
        
        # Set up the reports tab
        self.setup_report_tab()
        
        # Set up the status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        self.status_bar = ttk.Label(root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def setup_text_tab(self):
        """Set up the text encryption tab"""
        # Algorithm selection
        algo_frame = ttk.LabelFrame(self.text_tab, text="Encryption Algorithm")
        algo_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.text_algorithm = ttk.Combobox(algo_frame, values=["AES-256"], state="readonly")
        self.text_algorithm.current(0)
        self.text_algorithm.pack(fill=tk.X, padx=10, pady=5)
        
        # Password input
        password_frame = ttk.LabelFrame(self.text_tab, text="Password")
        password_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.text_password = ttk.Entry(password_frame, show="*")
        self.text_password.pack(fill=tk.X, padx=10, pady=5)
        
        # Text input
        input_frame = ttk.LabelFrame(self.text_tab, text="Input Text")
        input_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.text_input = scrolledtext.ScrolledText(input_frame)
        self.text_input.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Operation buttons
        button_frame = ttk.Frame(self.text_tab)
        button_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.encrypt_text_button = ttk.Button(button_frame, text="Encrypt", command=self.encrypt_text)
        self.encrypt_text_button.pack(side=tk.LEFT, padx=5, pady=5)
        
        self.decrypt_text_button = ttk.Button(button_frame, text="Decrypt", command=self.decrypt_text)
        self.decrypt_text_button.pack(side=tk.LEFT, padx=5, pady=5)
        
        # Output
        output_frame = ttk.LabelFrame(self.text_tab, text="Output")
        output_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.text_output = scrolledtext.ScrolledText(output_frame)
        self.text_output.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Copy button
        self.copy_text_button = ttk.Button(self.text_tab, text="Copy to Clipboard", command=self.copy_text_to_clipboard)
        self.copy_text_button.pack(padx=10, pady=5)
    
    def setup_file_tab(self):
        """Set up the file encryption tab"""
        # Algorithm selection
        algo_frame = ttk.LabelFrame(self.file_tab, text="Encryption Algorithm")
        algo_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.file_algorithm = ttk.Combobox(algo_frame, values=["AES-256"], state="readonly")
        self.file_algorithm.current(0)
        self.file_algorithm.pack(fill=tk.X, padx=10, pady=5)
        
        # Password input
        password_frame = ttk.LabelFrame(self.file_tab, text="Password")
        password_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.file_password = ttk.Entry(password_frame, show="*")
        self.file_password.pack(fill=tk.X, padx=10, pady=5)
        
        # Operation mode
        mode_frame = ttk.LabelFrame(self.file_tab, text="Operation")
        mode_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.operation_var = tk.StringVar(value="encrypt")
        self.encrypt_radio = ttk.Radiobutton(mode_frame, text="Encrypt", variable=self.operation_var, value="encrypt")
        self.decrypt_radio = ttk.Radiobutton(mode_frame, text="Decrypt", variable=self.operation_var, value="decrypt")
        self.encrypt_radio.pack(side=tk.LEFT, padx=10, pady=5)
        self.decrypt_radio.pack(side=tk.LEFT, padx=10, pady=5)
        
        # File selection
        file_frame = ttk.LabelFrame(self.file_tab, text="File Selection")
        file_frame.pack(fill=tk.X, padx=10, pady=5)
        
        input_frame = ttk.Frame(file_frame)
        input_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(input_frame, text="Input File:").pack(side=tk.LEFT, padx=5)
        self.input_file_var = tk.StringVar()
        self.input_file_entry = ttk.Entry(input_frame, textvariable=self.input_file_var, state="readonly", width=50)
        self.input_file_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.browse_input_button = ttk.Button(input_frame, text="Browse...", command=self.browse_input_file)
        self.browse_input_button.pack(side=tk.LEFT, padx=5)
        
        output_frame = ttk.Frame(file_frame)
        output_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(output_frame, text="Output File:").pack(side=tk.LEFT, padx=5)
        self.output_file_var = tk.StringVar()
        self.output_file_entry = ttk.Entry(output_frame, textvariable=self.output_file_var, state="readonly", width=50)
        self.output_file_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.browse_output_button = ttk.Button(output_frame, text="Browse...", command=self.browse_output_file)
        self.browse_output_button.pack(side=tk.LEFT, padx=5)
        
        # Progress bar
        progress_frame = ttk.LabelFrame(self.file_tab, text="Progress")
        progress_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(progress_frame, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(fill=tk.X, padx=10, pady=5)
        
        # Process button
        self.process_file_button = ttk.Button(self.file_tab, text="Process File", command=self.process_file)
        self.process_file_button.pack(padx=10, pady=10)
    
    def encrypt_text(self):
        """Encrypt the text in the input field"""
        plaintext = self.text_input.get("1.0", tk.END).strip()
        password = self.text_password.get()
        algorithm = self.text_algorithm.get()
        
        if not plaintext:
            messagebox.showwarning("Warning", "Please enter text to encrypt")
            return
        
        if not password:
            messagebox.showwarning("Warning", "Please enter a password")
            return
        
        self.status_var.set("Encrypting...")
        
        # Create a worker thread to perform the encryption
        worker = EncryptionWorker(
            'encrypt', 
            algorithm, 
            password, 
            plaintext, 
            'text', 
            self.handle_text_result, 
            self.handle_error
        )
        worker.start()
    
    def decrypt_text(self):
        """Decrypt the text in the input field"""
        ciphertext = self.text_input.get("1.0", tk.END).strip()
        password = self.text_password.get()
        algorithm = self.text_algorithm.get()
        
        if not ciphertext:
            messagebox.showwarning("Warning", "Please enter text to decrypt")
            return
        
        if not password:
            messagebox.showwarning("Warning", "Please enter a password")
            return
        
        self.status_var.set("Decrypting...")
        
        # Create a worker thread to perform the decryption
        worker = EncryptionWorker(
            'decrypt', 
            algorithm, 
            password, 
            ciphertext, 
            'text', 
            self.handle_text_result, 
            self.handle_error
        )
        worker.start()
    
    def handle_text_result(self, result):
        """Handle the result of a text encryption/decryption operation"""
        self.text_output.delete("1.0", tk.END)
        self.text_output.insert("1.0", result)
        self.status_var.set("Operation completed successfully")
        
        # Log the activity
        operation = "Text Encryption" if len(result) > len(self.text_input.get("1.0", tk.END).strip()) else "Text Decryption"
        self.log_activity(operation, "text", None, None)
    
    def copy_text_to_clipboard(self):
        """Copy the output text to the clipboard"""
        text = self.text_output.get("1.0", tk.END).strip()
        if text:
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            self.status_var.set("Copied to clipboard")
        else:
            messagebox.showwarning("Warning", "No output to copy")
    
    def browse_input_file(self):
        """Open a file dialog to select an input file"""
        if self.operation_var.get() == "encrypt":
            file_path = filedialog.askopenfilename(title="Select File to Encrypt")
        else:
            file_path = filedialog.askopenfilename(title="Select File to Decrypt", 
                                                 filetypes=[("Encrypted Files", "*.enc"), ("All Files", "*.*")])
        
        if file_path:
            self.input_file_var.set(file_path)
            
            # Suggest an output file path
            if self.operation_var.get() == "encrypt":
                suggested_output = file_path + ".enc"
            else:
                if file_path.endswith(".enc"):
                    suggested_output = file_path[:-4]  # Remove .enc extension
                else:
                    suggested_output = file_path + ".dec"
            
            self.output_file_var.set(suggested_output)
    
    def browse_output_file(self):
        """Open a file dialog to select an output file"""
        if self.operation_var.get() == "encrypt":
            file_path = filedialog.asksaveasfilename(title="Save Encrypted File", 
                                                   defaultextension=".enc",
                                                   filetypes=[("Encrypted Files", "*.enc"), ("All Files", "*.*")])
        else:
            file_path = filedialog.asksaveasfilename(title="Save Decrypted File")
        
        if file_path:
            self.output_file_var.set(file_path)
    
    def process_file(self):
        """Process (encrypt/decrypt) the selected file"""
        input_file = self.input_file_var.get()
        output_file = self.output_file_var.get()
        password = self.file_password.get()
        algorithm = self.file_algorithm.get()
        mode = self.operation_var.get()
        
        if not input_file:
            messagebox.showwarning("Warning", "Please select an input file")
            return
        
        if not output_file:
            messagebox.showwarning("Warning", "Please select an output file")
            return
        
        if not password:
            messagebox.showwarning("Warning", "Please enter a password")
            return
        
        # Check if output file exists
        if os.path.exists(output_file):
            if not messagebox.askyesno("File Exists", 
                                     f"The file {output_file} already exists. Do you want to overwrite it?"):
                return
        
        self.progress_var.set(0)
        self.status_var.set(f"{'Encrypting' if mode == 'encrypt' else 'Decrypting'} file...")
        
        # Create a worker thread to perform the operation
        worker = EncryptionWorker(
            mode, 
            algorithm, 
            password, 
            input_file, 
            'file', 
            self.handle_file_result, 
            self.handle_error,
            output_file
        )
        worker.start()
    
    def handle_file_result(self, result):
        """Handle the result of a file encryption/decryption operation"""
        messagebox.showinfo("Success", result)
        self.status_var.set("Operation completed successfully")
        self.progress_var.set(100)
        
        # Log the activity
        operation = "File Encryption" if self.operation_var.get() == "encrypt" else "File Decryption"
        input_file = self.input_file_var.get()
        output_file = self.output_file_var.get()
        self.log_activity(operation, "file", input_file, output_file)
    
    def setup_report_tab(self):
        """Set up the reports tab"""
        # Main frame
        main_frame = ttk.Frame(self.report_tab)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Activity log display
        log_frame = ttk.LabelFrame(main_frame, text="Activity Log")
        log_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create a treeview to display the activity log
        columns = ("timestamp", "operation", "type", "input_file", "output_file")
        self.log_tree = ttk.Treeview(log_frame, columns=columns, show="headings")
        
        # Define column headings
        self.log_tree.heading("timestamp", text="Timestamp")
        self.log_tree.heading("operation", text="Operation")
        self.log_tree.heading("type", text="Type")
        self.log_tree.heading("input_file", text="Input File")
        self.log_tree.heading("output_file", text="Output File")
        
        # Define column widths
        self.log_tree.column("timestamp", width=150)
        self.log_tree.column("operation", width=100)
        self.log_tree.column("type", width=50)
        self.log_tree.column("input_file", width=200)
        self.log_tree.column("output_file", width=200)
        
        # Add a scrollbar
        scrollbar = ttk.Scrollbar(log_frame, orient=tk.VERTICAL, command=self.log_tree.yview)
        self.log_tree.configure(yscroll=scrollbar.set)
        
        # Pack the treeview and scrollbar
        self.log_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Populate the treeview with activity log data
        self.update_activity_log_display()
        
        # Export buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(button_frame, text="Export as CSV", command=self.export_csv).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Export as JSON", command=self.export_json).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Generate PDF Report", command=self.generate_pdf_report).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Clear Log", command=self.clear_log).pack(side=tk.RIGHT, padx=5)
        ttk.Button(button_frame, text="Refresh", command=self.update_activity_log_display).pack(side=tk.RIGHT, padx=5)
    
    def log_activity(self, operation, data_type, input_file, output_file):
        """Log an encryption/decryption activity"""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        activity = {
            "timestamp": timestamp,
            "operation": operation,
            "type": data_type,
            "input_file": input_file if input_file else "N/A",
            "output_file": output_file if output_file else "N/A"
        }
        
        self.activity_log.append(activity)
        self.save_activity_log()
        
        # Update the activity log display if the reports tab is active
        if self.notebook.index(self.notebook.select()) == 2:  # Reports tab
            self.update_activity_log_display()
    
    def load_activity_log(self):
        """Load the activity log from file"""
        if os.path.exists(self.log_file):
            try:
                with open(self.log_file, 'r') as f:
                    self.activity_log = json.load(f)
            except (json.JSONDecodeError, FileNotFoundError):
                self.activity_log = []
        else:
            self.activity_log = []
    
    def save_activity_log(self):
        """Save the activity log to file"""
        try:
            with open(self.log_file, 'w') as f:
                json.dump(self.activity_log, f, indent=2)
        except Exception as e:
            print(f"Error saving activity log: {str(e)}")
    
    def update_activity_log_display(self):
        """Update the activity log display in the reports tab"""
        # Clear the treeview
        for item in self.log_tree.get_children():
            self.log_tree.delete(item)
        
        # Add activity log entries to the treeview
        for activity in self.activity_log:
            self.log_tree.insert("", tk.END, values=(
                activity["timestamp"],
                activity["operation"],
                activity["type"],
                activity["input_file"],
                activity["output_file"]
            ))
    
    def export_csv(self):
        """Export the activity log as a CSV file"""
        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            title="Export Activity Log as CSV"
        )
        
        if file_path:
            try:
                with open(file_path, 'w', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=["timestamp", "operation", "type", "input_file", "output_file"])
                    writer.writeheader()
                    writer.writerows(self.activity_log)
                
                messagebox.showinfo("Export Successful", f"Activity log exported to {file_path}")
            except Exception as e:
                messagebox.showerror("Export Error", f"Error exporting activity log: {str(e)}")
    
    def export_json(self):
        """Export the activity log as a JSON file"""
        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            title="Export Activity Log as JSON"
        )
        
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    json.dump(self.activity_log, f, indent=2)
                
                messagebox.showinfo("Export Successful", f"Activity log exported to {file_path}")
            except Exception as e:
                messagebox.showerror("Export Error", f"Error exporting activity log: {str(e)}")
    
    def generate_pdf_report(self):
        """Generate a PDF report of the activity log"""
        try:
            # Check if reportlab is installed
            import importlib.util
            if importlib.util.find_spec("reportlab") is None:
                if messagebox.askyesno("Missing Dependency", 
                                      "The reportlab package is required to generate PDF reports. Would you like to install it now?"):
                    self.status_var.set("Installing reportlab package...")
                    self.root.update()
                    
                    import subprocess
                    subprocess.check_call([sys.executable, "-m", "pip", "install", "reportlab"])
                    self.status_var.set("Ready")
                else:
                    return
            
            from reportlab.lib.pagesizes import letter
            from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
            from reportlab.lib.styles import getSampleStyleSheet
            from reportlab.lib import colors
            
            file_path = filedialog.asksaveasfilename(
                defaultextension=".pdf",
                filetypes=[("PDF files", "*.pdf"), ("All files", "*.*")],
                title="Save PDF Report"
            )
            
            if not file_path:
                return
            
            # Create the PDF document
            doc = SimpleDocTemplate(file_path, pagesize=letter)
            styles = getSampleStyleSheet()
            
            # Create the content for the PDF
            content = []
            
            # Add a title
            title = Paragraph("Encryption Activity Report", styles["Title"])
            content.append(title)
            content.append(Spacer(1, 20))
            
            # Add a subtitle with the date
            date_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            subtitle = Paragraph(f"Generated on: {date_str}", styles["Heading2"])
            content.append(subtitle)
            content.append(Spacer(1, 20))
            
            # Add the activity log as a table
            data = [["Timestamp", "Operation", "Type", "Input File", "Output File"]]
            for activity in self.activity_log:
                data.append([
                    activity["timestamp"],
                    activity["operation"],
                    activity["type"],
                    activity["input_file"],
                    activity["output_file"]
                ])
            
            table = Table(data, repeatRows=1)
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            
            content.append(table)
            
            # Build the PDF
            doc.build(content)
            
            messagebox.showinfo("Report Generated", f"PDF report saved to {file_path}")
            
        except Exception as e:
            messagebox.showerror("Report Generation Error", f"Error generating PDF report: {str(e)}")
    
    def clear_log(self):
        """Clear the activity log"""
        if messagebox.askyesno("Clear Log", "Are you sure you want to clear the activity log? This action cannot be undone."):
            self.activity_log = []
            self.save_activity_log()
            self.update_activity_log_display()
            messagebox.showinfo("Log Cleared", "Activity log has been cleared.")
    
    def handle_error(self, error_message):
        """Handle errors from the worker thread"""
        messagebox.showerror("Error", error_message)
        self.status_var.set("Operation failed")


if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()
