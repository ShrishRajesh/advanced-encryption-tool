import os
import sys
import base64
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                           QLabel, QLineEdit, QTextEdit, QPushButton, QFileDialog, 
                           QComboBox, QTabWidget, QMessageBox, QGroupBox, QRadioButton,
                           QProgressBar, QSpacerItem, QSizePolicy)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont, QIcon
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import secrets

class EncryptionWorker(QThread):
    """Worker thread to handle encryption/decryption operations"""
    progress_update = pyqtSignal(int)
    operation_complete = pyqtSignal(str)
    operation_error = pyqtSignal(str)
    
    def __init__(self, mode, algorithm, password, input_data, input_type, output_path=None):
        super().__init__()
        self.mode = mode  # 'encrypt' or 'decrypt'
        self.algorithm = algorithm
        self.password = password
        self.input_data = input_data
        self.input_type = input_type  # 'text' or 'file'
        self.output_path = output_path
        
    def run(self):
        try:
            if self.input_type == 'file':
                if self.mode == 'encrypt':
                    result = self.encrypt_file(self.input_data, self.output_path, self.password, self.algorithm)
                    self.operation_complete.emit(f"File encrypted successfully: {result}")
                else:
                    result = self.decrypt_file(self.input_data, self.output_path, self.password, self.algorithm)
                    self.operation_complete.emit(f"File decrypted successfully: {result}")
            else:  # text
                if self.mode == 'encrypt':
                    result = self.encrypt_text(self.input_data, self.password, self.algorithm)
                    self.operation_complete.emit(result)
                else:
                    result = self.decrypt_text(self.input_data, self.password, self.algorithm)
                    self.operation_complete.emit(result)
        except Exception as e:
            self.operation_error.emit(f"Error: {str(e)}")
    
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


class EncryptionApp(QMainWindow):
    """Main application window"""
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Advanced Encryption Tool")
        self.setMinimumSize(800, 600)
        
        # Set up the central widget and main layout
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.main_layout = QVBoxLayout(self.central_widget)
        
        # Create tabs for different encryption modes
        self.tabs = QTabWidget()
        self.text_tab = QWidget()
        self.file_tab = QWidget()
        
        self.tabs.addTab(self.text_tab, "Text Encryption")
        self.tabs.addTab(self.file_tab, "File Encryption")
        
        # Set up the text encryption tab
        self.setup_text_tab()
        
        # Set up the file encryption tab
        self.setup_file_tab()
        
        # Add the tabs to the main layout
        self.main_layout.addWidget(self.tabs)
        
        # Set up the status bar
        self.statusBar().showMessage("Ready")
        
        # Show the window
        self.show()
    
    def setup_text_tab(self):
        """Set up the text encryption tab"""
        layout = QVBoxLayout(self.text_tab)
        
        # Algorithm selection
        algo_group = QGroupBox("Encryption Algorithm")
        algo_layout = QVBoxLayout()
        self.text_algorithm = QComboBox()
        self.text_algorithm.addItem("AES-256")
        # Can add more algorithms in the future
        algo_layout.addWidget(self.text_algorithm)
        algo_group.setLayout(algo_layout)
        layout.addWidget(algo_group)
        
        # Password input
        password_group = QGroupBox("Password")
        password_layout = QVBoxLayout()
        self.text_password = QLineEdit()
        self.text_password.setEchoMode(QLineEdit.EchoMode.Password)
        self.text_password.setPlaceholderText("Enter your encryption/decryption password")
        password_layout.addWidget(self.text_password)
        password_group.setLayout(password_layout)
        layout.addWidget(password_group)
        
        # Text input
        input_group = QGroupBox("Input Text")
        input_layout = QVBoxLayout()
        self.text_input = QTextEdit()
        self.text_input.setPlaceholderText("Enter text to encrypt or encrypted text to decrypt")
        input_layout.addWidget(self.text_input)
        input_group.setLayout(input_layout)
        layout.addWidget(input_group)
        
        # Operation buttons
        button_layout = QHBoxLayout()
        self.encrypt_text_button = QPushButton("Encrypt")
        self.encrypt_text_button.clicked.connect(self.encrypt_text)
        self.decrypt_text_button = QPushButton("Decrypt")
        self.decrypt_text_button.clicked.connect(self.decrypt_text)
        button_layout.addWidget(self.encrypt_text_button)
        button_layout.addWidget(self.decrypt_text_button)
        layout.addLayout(button_layout)
        
        # Output
        output_group = QGroupBox("Output")
        output_layout = QVBoxLayout()
        self.text_output = QTextEdit()
        self.text_output.setReadOnly(True)
        self.text_output.setPlaceholderText("Encryption/decryption result will appear here")
        output_layout.addWidget(self.text_output)
        output_group.setLayout(output_layout)
        layout.addWidget(output_group)
        
        # Copy button
        self.copy_text_button = QPushButton("Copy to Clipboard")
        self.copy_text_button.clicked.connect(self.copy_text_to_clipboard)
        layout.addWidget(self.copy_text_button)
    
    def setup_file_tab(self):
        """Set up the file encryption tab"""
        layout = QVBoxLayout(self.file_tab)
        
        # Algorithm selection
        algo_group = QGroupBox("Encryption Algorithm")
        algo_layout = QVBoxLayout()
        self.file_algorithm = QComboBox()
        self.file_algorithm.addItem("AES-256")
        # Can add more algorithms in the future
        algo_layout.addWidget(self.file_algorithm)
        algo_group.setLayout(algo_layout)
        layout.addWidget(algo_group)
        
        # Password input
        password_group = QGroupBox("Password")
        password_layout = QVBoxLayout()
        self.file_password = QLineEdit()
        self.file_password.setEchoMode(QLineEdit.EchoMode.Password)
        self.file_password.setPlaceholderText("Enter your encryption/decryption password")
        password_layout.addWidget(self.file_password)
        password_group.setLayout(password_layout)
        layout.addWidget(password_group)
        
        # Operation mode
        mode_group = QGroupBox("Operation")
        mode_layout = QHBoxLayout()
        self.encrypt_radio = QRadioButton("Encrypt")
        self.decrypt_radio = QRadioButton("Decrypt")
        self.encrypt_radio.setChecked(True)
        mode_layout.addWidget(self.encrypt_radio)
        mode_layout.addWidget(self.decrypt_radio)
        mode_group.setLayout(mode_layout)
        layout.addWidget(mode_group)
        
        # File selection
        file_group = QGroupBox("File Selection")
        file_layout = QVBoxLayout()
        
        input_layout = QHBoxLayout()
        self.input_file_path = QLineEdit()
        self.input_file_path.setReadOnly(True)
        self.input_file_path.setPlaceholderText("Select input file")
        self.browse_input_button = QPushButton("Browse...")
        self.browse_input_button.clicked.connect(self.browse_input_file)
        input_layout.addWidget(self.input_file_path)
        input_layout.addWidget(self.browse_input_button)
        file_layout.addLayout(input_layout)
        
        output_layout = QHBoxLayout()
        self.output_file_path = QLineEdit()
        self.output_file_path.setReadOnly(True)
        self.output_file_path.setPlaceholderText("Select output file")
        self.browse_output_button = QPushButton("Browse...")
        self.browse_output_button.clicked.connect(self.browse_output_file)
        output_layout.addWidget(self.output_file_path)
        output_layout.addWidget(self.browse_output_button)
        file_layout.addLayout(output_layout)
        
        file_group.setLayout(file_layout)
        layout.addWidget(file_group)
        
        # Progress bar
        progress_group = QGroupBox("Progress")
        progress_layout = QVBoxLayout()
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        progress_layout.addWidget(self.progress_bar)
        progress_group.setLayout(progress_layout)
        layout.addWidget(progress_group)
        
        # Process button
        self.process_file_button = QPushButton("Process File")
        self.process_file_button.clicked.connect(self.process_file)
        layout.addWidget(self.process_file_button)
        
        # Add spacer
        layout.addItem(QSpacerItem(20, 40, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding))
    
    def encrypt_text(self):
        """Encrypt the text in the input field"""
        plaintext = self.text_input.toPlainText()
        password = self.text_password.text()
        algorithm = self.text_algorithm.currentText()
        
        if not plaintext:
            QMessageBox.warning(self, "Warning", "Please enter text to encrypt")
            return
        
        if not password:
            QMessageBox.warning(self, "Warning", "Please enter a password")
            return
        
        # Create a worker thread to perform the encryption
        self.worker = EncryptionWorker('encrypt', algorithm, password, plaintext, 'text')
        self.worker.operation_complete.connect(self.handle_text_result)
        self.worker.operation_error.connect(self.handle_error)
        self.worker.start()
        
        self.statusBar().showMessage("Encrypting...")
    
    def decrypt_text(self):
        """Decrypt the text in the input field"""
        ciphertext = self.text_input.toPlainText()
        password = self.text_password.text()
        algorithm = self.text_algorithm.currentText()
        
        if not ciphertext:
            QMessageBox.warning(self, "Warning", "Please enter text to decrypt")
            return
        
        if not password:
            QMessageBox.warning(self, "Warning", "Please enter a password")
            return
        
        # Create a worker thread to perform the decryption
        self.worker = EncryptionWorker('decrypt', algorithm, password, ciphertext, 'text')
        self.worker.operation_complete.connect(self.handle_text_result)
        self.worker.operation_error.connect(self.handle_error)
        self.worker.start()
        
        self.statusBar().showMessage("Decrypting...")
    
    def handle_text_result(self, result):
        """Handle the result of a text encryption/decryption operation"""
        self.text_output.setText(result)
        self.statusBar().showMessage("Operation completed successfully")
    
    def copy_text_to_clipboard(self):
        """Copy the output text to the clipboard"""
        text = self.text_output.toPlainText()
        if text:
            clipboard = QApplication.clipboard()
            clipboard.setText(text)
            self.statusBar().showMessage("Copied to clipboard")
        else:
            QMessageBox.warning(self, "Warning", "No output to copy")
    
    def browse_input_file(self):
        """Open a file dialog to select an input file"""
        options = QFileDialog.Option.ReadOnly
        if self.encrypt_radio.isChecked():
            file_path, _ = QFileDialog.getOpenFileName(self, "Select File to Encrypt", "", "All Files (*)", options=options)
        else:
            file_path, _ = QFileDialog.getOpenFileName(self, "Select File to Decrypt", "", "Encrypted Files (*.enc);;All Files (*)", options=options)
        
        if file_path:
            self.input_file_path.setText(file_path)
            
            # Suggest an output file path
            if self.encrypt_radio.isChecked():
                suggested_output = file_path + ".enc"
            else:
                if file_path.endswith(".enc"):
                    suggested_output = file_path[:-4]  # Remove .enc extension
                else:
                    suggested_output = file_path + ".dec"
            
            self.output_file_path.setText(suggested_output)
    
    def browse_output_file(self):
        """Open a file dialog to select an output file"""
        options = QFileDialog.Option.ReadOnly
        if self.encrypt_radio.isChecked():
            file_path, _ = QFileDialog.getSaveFileName(self, "Save Encrypted File", "", "Encrypted Files (*.enc);;All Files (*)", options=options)
        else:
            file_path, _ = QFileDialog.getSaveFileName(self, "Save Decrypted File", "", "All Files (*)", options=options)
        
        if file_path:
            self.output_file_path.setText(file_path)
    
    def process_file(self):
        """Process (encrypt/decrypt) the selected file"""
        input_file = self.input_file_path.text()
        output_file = self.output_file_path.text()
        password = self.file_password.text()
        algorithm = self.file_algorithm.currentText()
        
        if not input_file:
            QMessageBox.warning(self, "Warning", "Please select an input file")
            return
        
        if not output_file:
            QMessageBox.warning(self, "Warning", "Please select an output file")
            return
        
        if not password:
            QMessageBox.warning(self, "Warning", "Please enter a password")
            return
        
        # Check if output file exists
        if os.path.exists(output_file):
            reply = QMessageBox.question(self, "File Exists", 
                                         f"The file {output_file} already exists. Do you want to overwrite it?",
                                         QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            if reply == QMessageBox.StandardButton.No:
                return
        
        # Create a worker thread to perform the operation
        mode = 'encrypt' if self.encrypt_radio.isChecked() else 'decrypt'
        self.worker = EncryptionWorker(mode, algorithm, password, input_file, 'file', output_file)
        self.worker.operation_complete.connect(self.handle_file_result)
        self.worker.operation_error.connect(self.handle_error)
        self.worker.start()
        
        self.statusBar().showMessage(f"{'Encrypting' if mode == 'encrypt' else 'Decrypting'} file...")
    
    def handle_file_result(self, result):
        """Handle the result of a file encryption/decryption operation"""
        QMessageBox.information(self, "Success", result)
        self.statusBar().showMessage("Operation completed successfully")
        self.progress_bar.setValue(100)
    
    def handle_error(self, error_message):
        """Handle errors from the worker thread"""
        QMessageBox.critical(self, "Error", error_message)
        self.statusBar().showMessage("Operation failed")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    
    # Set application style
    app.setStyle("Fusion")
    
    # Create and show the main window
    window = EncryptionApp()
    
    sys.exit(app.exec())
