import os
import sys
import secrets
import base64
from PyQt5.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                             QLabel, QLineEdit, QPushButton, QComboBox,
                             QFileDialog, QMessageBox, QGroupBox, QCheckBox)
from PyQt5.QtCore import Qt

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from file_encryptor.file_encryptor import FileEncryptor


class FileEncryptionWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("File Encryption Utility")
        self.setGeometry(100, 100, 600, 550)
        self._setup_ui()

    def _setup_ui(self):
        central_widget = QWidget()
        main_layout = QVBoxLayout()
        central_widget.setLayout(main_layout)
        self.setCentralWidget(central_widget)

        self.setStyleSheet("""
            QMainWindow {
                background-color: #f0f0f0;
            }
            QLabel {
                color: #333;
                font-weight: bold;
            }
            QLineEdit, QComboBox {
                padding: 8px;
                border: 1px solid #ccc;
                border-radius: 4px;
            }
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border: none;
                padding: 10px;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
            QPushButton:pressed {
                background-color: #3d8b40;
            }
            QCheckBox {
                spacing: 10px;
            }
        """)

        key_group = QGroupBox("Encryption Key & IV")
        key_layout = QVBoxLayout()

        self.randomize_check = QCheckBox("Generate Random Key and IV")
        self.randomize_check.stateChanged.connect(self._toggle_randomization)
        key_layout.addWidget(self.randomize_check)

        key_input_layout = QHBoxLayout()
        key_label = QLabel("Key:")
        self.key_input = QLineEdit()
        self.key_input.setPlaceholderText("Enter encryption key")
        key_generate_button = QPushButton("🎲")
        key_generate_button.setToolTip("Generate Random Key")
        key_generate_button.clicked.connect(self._generate_random_key)
        key_input_layout.addWidget(key_label)
        key_input_layout.addWidget(self.key_input)
        key_input_layout.addWidget(key_generate_button)
        key_layout.addLayout(key_input_layout)

        iv_input_layout = QHBoxLayout()
        iv_label = QLabel("IV:")
        self.iv_input = QLineEdit()
        self.iv_input.setPlaceholderText("Enter initialization vector")
        iv_generate_button = QPushButton("🎲")
        iv_generate_button.setToolTip("Generate Random IV")
        iv_generate_button.clicked.connect(self._generate_random_iv)
        iv_input_layout.addWidget(iv_label)
        iv_input_layout.addWidget(self.iv_input)
        iv_input_layout.addWidget(iv_generate_button)
        key_layout.addLayout(iv_input_layout)

        key_group.setLayout(key_layout)
        main_layout.addWidget(key_group)

        file_group = QGroupBox("File Operations")
        file_layout = QVBoxLayout()

        input_file_layout = QHBoxLayout()
        self.input_file_path = QLineEdit()
        self.input_file_path.setPlaceholderText("Input file")
        input_file_button = QPushButton("Browse")
        input_file_button.clicked.connect(self._select_input_file)
        input_file_layout.addWidget(self.input_file_path)
        input_file_layout.addWidget(input_file_button)
        file_layout.addLayout(input_file_layout)

        output_file_layout = QHBoxLayout()
        self.output_file_path = QLineEdit()
        self.output_file_path.setPlaceholderText(
            "Output:For e/d,use an empty file(.txt). For verifiing, enter the file path.")
        output_file_button = QPushButton("Browse")
        output_file_button.clicked.connect(self._select_output_file)
        output_file_layout.addWidget(self.output_file_path)
        output_file_layout.addWidget(output_file_button)
        file_layout.addLayout(output_file_layout)

        mode_layout = QHBoxLayout()
        mode_label = QLabel("Encryption Mode:")
        self.mode_combo = QComboBox()
        self.mode_combo.addItems(["ECB", "CBC"])
        mode_layout.addWidget(mode_label)
        mode_layout.addWidget(self.mode_combo)
        file_layout.addLayout(mode_layout)

        file_group.setLayout(file_layout)
        main_layout.addWidget(file_group)

        action_layout = QHBoxLayout()
        encrypt_button = QPushButton("Encrypt File")
        decrypt_button = QPushButton("Decrypt File")
        verify_button = QPushButton("Verify Integrity")

        encrypt_button.clicked.connect(self._encrypt_file)
        decrypt_button.clicked.connect(self._decrypt_file)
        verify_button.clicked.connect(self._verify_integrity)

        action_layout.addWidget(encrypt_button)
        action_layout.addWidget(decrypt_button)
        action_layout.addWidget(verify_button)
        main_layout.addLayout(action_layout)

        self.status_label = QLabel("Ready")
        self.status_label.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(self.status_label)

    def _toggle_randomization(self, state):
        """Enable/disable key and IV inputs based on randomization checkbox"""
        is_checked = state == Qt.Checked
        self.key_input.setEnabled(not is_checked)
        self.iv_input.setEnabled(not is_checked)

        if is_checked:
            self._generate_random_key()
            self._generate_random_iv()

    def _generate_random_key(self):
        random_key = secrets.token_bytes(32)
        base64_key = base64.b64encode(random_key).decode('utf-8')
        self.key_input.setText(base64_key)
        return base64_key

    def _generate_random_iv(self):
        random_iv = secrets.token_bytes(16)
        base64_iv = base64.b64encode(random_iv).decode('utf-8')
        self.iv_input.setText(base64_iv)
        return base64_iv

    def _select_input_file(self):
        filename, _ = QFileDialog.getOpenFileName(self, "Select Input File")
        if filename:
            self.input_file_path.setText(filename)

    def _select_output_file(self):
        filename, _ = QFileDialog.getSaveFileName(self, "Select Output File")
        if filename:
            self.output_file_path.setText(filename)

    def _encrypt_file(self):
        try:
            if self.randomize_check.isChecked():
                if not self.key_input.text() or not self.iv_input.text():
                    self._generate_random_key()
                    self._generate_random_iv()

            key = self.key_input.text()
            iv = self.iv_input.text()
            input_file = self.input_file_path.text()
            output_file = self.output_file_path.text()
            mode = self.mode_combo.currentText().lower()

            if not all([key, iv, input_file, output_file]):
                raise ValueError("All fields must be filled")

            encryptor = FileEncryptor(key, iv)
            encryptor.encrypt_file(input_file, output_file, mode)

            if self.randomize_check.isChecked():
                message = (f"File encrypted successfully: {output_file}\n\n"
                           f"Key (IMPORTANT - SAVE THIS): {key}\n"
                           f"IV (IMPORTANT - SAVE THIS): {iv}")
                QMessageBox.information(self, "Encryption Successful", message)

            self.status_label.setText(
                f"File encrypted successfully: {output_file}")
            self.status_label.setStyleSheet("color: green;")
        except Exception as e:
            self._show_error(str(e))

    def _decrypt_file(self):
        try:
            key = self.key_input.text()
            iv = self.iv_input.text()
            input_file = self.input_file_path.text()
            output_file = self.output_file_path.text()
            mode = self.mode_combo.currentText().lower()

            if not all([key, iv, input_file, output_file]):
                raise ValueError("All fields must be filled")

            encryptor = FileEncryptor(key, iv)
            encryptor.decrypt_file(input_file, output_file, mode)

            self.status_label.setText(
                f"File decrypted successfully: {output_file}")
            self.status_label.setStyleSheet("color: green;")
        except Exception as e:
            self._show_error(str(e))

    def _verify_integrity(self):
        try:
            input_file = self.input_file_path.text()
            output_file = self.output_file_path.text()

            if not all([input_file, output_file]):
                raise ValueError(
                    "Both input and output file paths must be selected")

            is_intact = FileEncryptor.verify_file_integrity(
                input_file, output_file)

            if is_intact:
                self.status_label.setText(
                    "File integrity verified: No changes detected")
                self.status_label.setStyleSheet("color: green;")
            else:
                self.status_label.setText(
                    "File integrity check failed: Files are different")
                self.status_label.setStyleSheet("color: red;")
        except Exception as e:
            self._show_error(str(e))

    def _show_error(self, message):
        QMessageBox.critical(self, "Error", message)
        self.status_label.setText(f"Error: {message}")
        self.status_label.setStyleSheet("color: red;")
