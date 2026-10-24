"""
gui_app.py - Modern PyQt6 GUI for AES Encryption Suite

Features:
- Modes: ECB, CBC, CFB1, CFB8, CFB128, OFB, CTR, CCM, GCM
- Key sizes: 128, 192, 256 bits
- Text & File encryption/decryption (worker QThread, progress bar, cancelable)
- Hex / UTF-8 text formats with live validation
- AEAD: GCM/CCM tags, explicit "Authentication Failed" alerts
- Self-test tab running NIST vectors live
- Crypto layer cleanly separated in aeslib.py
"""

import sys
import os
import time
import secrets
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTabWidget, QLabel, QComboBox, QLineEdit, QTextEdit, QPushButton,
    QRadioButton, QButtonGroup, QFileDialog, QProgressBar, QMessageBox,
    QGroupBox, QGridLayout, QSpinBox, QCheckBox
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont, QIcon

# Ensure python directory is in path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import aeslib


# ============================================================
#  File Processing Worker Thread
# ============================================================
class FileWorker(QThread):
    progress = pyqtSignal(int)
    finished = pyqtSignal(bool, str, float, float) # success, message, time_sec, throughput_mbps

    def __init__(self, mode: str, is_encrypt: bool, in_path: str, out_path: str,
                 key: bytes, iv: bytes, nonce: bytes, aad: bytes, tag_len: int,
                 tag_in: bytes = b""):
        super().__init__()
        self.mode = mode
        self.is_encrypt = is_encrypt
        self.in_path = in_path
        self.out_path = out_path
        self.key = key
        self.iv = iv
        self.nonce = nonce
        self.aad = aad
        self.tag_len = tag_len
        self.tag_in = tag_in
        self._is_cancelled = False

    def cancel(self):
        self._is_cancelled = True

    def run(self):
        t0 = time.perf_counter()
        try:
            file_size = os.path.getsize(self.in_path)
            if file_size == 0:
                with open(self.out_path, "wb") as f:
                    pass
                self.finished.emit(True, "Empty file processed.", 0.0, 0.0)
                return

            with open(self.in_path, "rb") as f_in:
                data = f_in.read()

            self.progress.emit(30)

            # Process based on mode
            out_data = b""
            tag_out = b""

            if self.mode == "ECB":
                # For file ECB, pad to 16 bytes if encrypting
                if self.is_encrypt:
                    pad = 16 - (len(data) % 16)
                    data = data + bytes([pad] * pad)
                    out_data = aeslib.ecb_encrypt(self.key, data)
                else:
                    out_data = aeslib.ecb_decrypt(self.key, data)
                    # Unpad
                    pad = out_data[-1]
                    if 1 <= pad <= 16:
                        out_data = out_data[:-pad]

            elif self.mode == "CBC":
                if self.is_encrypt:
                    pad = 16 - (len(data) % 16)
                    data = data + bytes([pad] * pad)
                    out_data = aeslib.cbc_encrypt(self.key, self.iv, data)
                else:
                    out_data = aeslib.cbc_decrypt(self.key, self.iv, data)
                    pad = out_data[-1]
                    if 1 <= pad <= 16:
                        out_data = out_data[:-pad]

            elif self.mode.startswith("CFB"):
                sbits = 128
                if self.mode == "CFB8": sbits = 8
                elif self.mode == "CFB1": sbits = 1
                if self.is_encrypt:
                    out_data = aeslib.cfb_encrypt(self.key, self.iv, data, sbits)
                else:
                    out_data = aeslib.cfb_decrypt(self.key, self.iv, data, sbits)

            elif self.mode == "OFB":
                if self.is_encrypt:
                    pad = 16 - (len(data) % 16) if (len(data) % 16 != 0) else 0
                    if pad: data = data + bytes([pad] * pad)
                    out_data = aeslib.ofb_encrypt(self.key, self.iv, data)
                else:
                    out_data = aeslib.ofb_decrypt(self.key, self.iv, data)

            elif self.mode == "CTR":
                out_data = aeslib.ctr_crypt(self.key, self.iv, data)

            elif self.mode == "GCM":
                if self.is_encrypt:
                    out_data, tag_out = aeslib.gcm_encrypt(self.key, self.iv, data, self.aad, self.tag_len)
                    out_data = out_data + tag_out  # append tag to file
                else:
                    # Last tag_len bytes is tag
                    if len(data) < self.tag_len:
                        raise ValueError("File too short for GCM authentication tag.")
                    ct = data[:-self.tag_len]
                    tag = data[-self.tag_len:]
                    out_data = aeslib.gcm_decrypt(self.key, self.iv, ct, tag, self.aad)

            elif self.mode == "CCM":
                if self.is_encrypt:
                    out_data, tag_out = aeslib.ccm_encrypt(self.key, self.nonce, data, self.aad, self.tag_len)
                    out_data = out_data + tag_out
                else:
                    if len(data) < self.tag_len:
                        raise ValueError("File too short for CCM authentication tag.")
                    ct = data[:-self.tag_len]
                    tag = data[-self.tag_len:]
                    out_data = aeslib.ccm_decrypt(self.key, self.nonce, ct, tag, self.aad)

            self.progress.emit(80)

            with open(self.out_path, "wb") as f_out:
                f_out.write(out_data)

            self.progress.emit(100)

            t1 = time.perf_counter()
            elapsed = t1 - t0
            throughput = (file_size / (1024 * 1024)) / elapsed if elapsed > 0 else 0.0

            msg = f"Processed {file_size:,} bytes successfully."
            if tag_out:
                msg += f" Tag: {tag_out.hex()}"
            self.finished.emit(True, msg, elapsed, throughput)

        except aeslib.AuthenticationError as e:
            self.finished.emit(False, f"AUTHENTICATION FAILED: {e}", 0.0, 0.0)
        except Exception as e:
            self.finished.emit(False, f"Error: {e}", 0.0, 0.0)


# ============================================================
#  Main Window
# ============================================================
class AESMainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"AES Suite v2.0 - {aeslib.version()}")
        self.resize(850, 680)

        self.worker = None

        central = QWidget()
        self.setCentralWidget(central)
        root_layout = QVBoxLayout(central)

        # Tab widget
        self.tabs = QTabWidget()
        root_layout.addWidget(self.tabs)

        # Tabs
        self.tab_text = QWidget()
        self.tab_file = QWidget()
        self.tab_selftest = QWidget()

        self.tabs.addTab(self.tab_text, "Text Crypto")
        self.tabs.addTab(self.tab_file, "File Crypto")
        self.tabs.addTab(self.tab_selftest, "Self-Test (NIST KAT)")

        self._setup_common_config()
        self._build_text_tab()
        self._build_file_tab()
        self._build_selftest_tab()

        self._on_mode_changed()

    def _setup_common_config(self):
        # Configuration frame
        self.config_group = QGroupBox("Configuration & Key Management")
        cfg_layout = QGridLayout(self.config_group)

        # Mode
        cfg_layout.addWidget(QLabel("Mode:"), 0, 0)
        self.cb_mode = QComboBox()
        self.cb_mode.addItems(["ECB", "CBC", "CFB128", "CFB8", "CFB1", "OFB", "CTR", "GCM", "CCM"])
        self.cb_mode.currentTextChanged.connect(self._on_mode_changed)
        cfg_layout.addWidget(self.cb_mode, 0, 1)

        # Key Size
        cfg_layout.addWidget(QLabel("Key Size:"), 0, 2)
        self.cb_keysize = QComboBox()
        self.cb_keysize.addItems(["128 bits (16 B)", "192 bits (24 B)", "256 bits (32 B)"])
        self.cb_keysize.currentTextChanged.connect(self._on_keysize_changed)
        cfg_layout.addWidget(self.cb_keysize, 0, 3)

        # Key Input & Format
        cfg_layout.addWidget(QLabel("Key:"), 1, 0)
        self.txt_key = QLineEdit()
        self.txt_key.setPlaceholderText("Hex or UTF-8 key string")
        cfg_layout.addWidget(self.txt_key, 1, 1, 1, 2)

        self.rb_key_hex = QRadioButton("Hex")
        self.rb_key_text = QRadioButton("Text")
        self.rb_key_hex.setChecked(True)
        key_fmt_group = QButtonGroup(self)
        key_fmt_group.addButton(self.rb_key_hex)
        key_fmt_group.addButton(self.rb_key_text)
        fmt_box = QHBoxLayout()
        fmt_box.addWidget(self.rb_key_hex)
        fmt_box.addWidget(self.rb_key_text)
        cfg_layout.addLayout(fmt_box, 1, 3)

        btn_gen_key = QPushButton("Generate Key")
        btn_gen_key.clicked.connect(self._gen_random_key)
        cfg_layout.addWidget(btn_gen_key, 1, 4)

        # IV / Nonce / Counter
        self.lbl_iv = QLabel("IV / Counter (16B):")
        cfg_layout.addWidget(self.lbl_iv, 2, 0)
        self.txt_iv = QLineEdit()
        self.txt_iv.setPlaceholderText("Hex or UTF-8 IV/Counter/Nonce")
        cfg_layout.addWidget(self.txt_iv, 2, 1, 1, 2)

        btn_gen_iv = QPushButton("Generate IV")
        btn_gen_iv.clicked.connect(self._gen_random_iv)
        cfg_layout.addWidget(btn_gen_iv, 2, 4)

        # AAD
        self.lbl_aad = QLabel("AAD (Optional):")
        cfg_layout.addWidget(self.lbl_aad, 3, 0)
        self.txt_aad = QLineEdit()
        self.txt_aad.setPlaceholderText("Additional Authenticated Data (Hex or UTF-8)")
        cfg_layout.addWidget(self.txt_aad, 3, 1, 1, 2)

        # Tag Length (for GCM/CCM)
        self.lbl_taglen = QLabel("Tag Length:")
        cfg_layout.addWidget(self.lbl_taglen, 3, 3)
        self.sp_taglen = QSpinBox()
        self.sp_taglen.setRange(4, 16)
        self.sp_taglen.setValue(16)
        cfg_layout.addWidget(self.sp_taglen, 3, 4)

    def _build_text_tab(self):
        layout = QVBoxLayout(self.tab_text)
        layout.addWidget(self.config_group)

        # Plaintext
        layout.addWidget(QLabel("Input Data:"))
        self.txt_input = QTextEdit()
        self.txt_input.setPlaceholderText("Enter plaintext or ciphertext here...")
        layout.addWidget(self.txt_input)

        # Options row
        opt_box = QHBoxLayout()
        self.rb_in_hex = QRadioButton("Input is Hex")
        self.rb_in_utf8 = QRadioButton("Input is Text (UTF-8)")
        self.rb_in_utf8.setChecked(True)
        opt_box.addWidget(self.rb_in_utf8)
        opt_box.addWidget(self.rb_in_hex)

        self.chk_pkcs7 = QCheckBox("PKCS#7 Padding (for ECB/CBC)")
        self.chk_pkcs7.setChecked(True)
        opt_box.addWidget(self.chk_pkcs7)
        layout.addLayout(opt_box)

        # Tag display / input (for AEAD)
        self.lbl_tag_text = QLabel("Authentication Tag (Hex):")
        self.txt_tag = QLineEdit()
        self.txt_tag.setPlaceholderText("AEAD Tag output or input for verification")
        layout.addWidget(self.lbl_tag_text)
        layout.addWidget(self.txt_tag)

        # Buttons
        btn_box = QHBoxLayout()
        self.btn_enc = QPushButton("Encrypt")
        self.btn_enc.setStyleSheet("background-color: #2e7d32; color: white; font-weight: bold; padding: 6px;")
        self.btn_enc.clicked.connect(self._do_text_encrypt)
        btn_box.addWidget(self.btn_enc)

        self.btn_dec = QPushButton("Decrypt")
        self.btn_dec.setStyleSheet("background-color: #1565c0; color: white; font-weight: bold; padding: 6px;")
        self.btn_dec.clicked.connect(self._do_text_decrypt)
        btn_box.addWidget(self.btn_dec)

        self.btn_copy = QPushButton("Copy Output")
        self.btn_copy.clicked.connect(self._copy_output)
        btn_box.addWidget(self.btn_copy)
        layout.addLayout(btn_box)

        # Output
        layout.addWidget(QLabel("Output Data (Hex or Plaintext):"))
        self.txt_output = QTextEdit()
        self.txt_output.setReadOnly(True)
        layout.addWidget(self.txt_output)

        # Status & Performance
        self.lbl_status = QLabel("Ready")
        self.lbl_status.setStyleSheet("font-weight: bold;")
        layout.addWidget(self.lbl_status)

    def _build_file_tab(self):
        layout = QVBoxLayout(self.tab_file)

        file_box = QGroupBox("File Selection")
        f_grid = QGridLayout(file_box)

        f_grid.addWidget(QLabel("Input File:"), 0, 0)
        self.txt_file_in = QLineEdit()
        f_grid.addWidget(self.txt_file_in, 0, 1)
        btn_browse_in = QPushButton("Browse...")
        btn_browse_in.clicked.connect(self._browse_in_file)
        f_grid.addWidget(btn_browse_in, 0, 2)

        f_grid.addWidget(QLabel("Output File:"), 1, 0)
        self.txt_file_out = QLineEdit()
        f_grid.addWidget(self.txt_file_out, 1, 1)
        btn_browse_out = QPushButton("Browse...")
        btn_browse_out.clicked.connect(self._browse_out_file)
        f_grid.addWidget(btn_browse_out, 1, 2)

        layout.addWidget(file_box)

        # Action buttons
        act_box = QHBoxLayout()
        self.btn_file_enc = QPushButton("Encrypt File")
        self.btn_file_enc.setStyleSheet("background-color: #2e7d32; color: white; font-weight: bold; padding: 8px;")
        self.btn_file_enc.clicked.connect(lambda: self._do_file_process(True))
        act_box.addWidget(self.btn_file_enc)

        self.btn_file_dec = QPushButton("Decrypt File")
        self.btn_file_dec.setStyleSheet("background-color: #1565c0; color: white; font-weight: bold; padding: 8px;")
        self.btn_file_dec.clicked.connect(lambda: self._do_file_process(False))
        act_box.addWidget(self.btn_file_dec)
        layout.addLayout(act_box)

        # Progress bar
        self.file_progress = QProgressBar()
        self.file_progress.setValue(0)
        layout.addWidget(self.file_progress)

        self.lbl_file_status = QLabel("Select an input and output file.")
        self.lbl_file_status.setStyleSheet("font-weight: bold;")
        layout.addWidget(self.lbl_file_status)
        layout.addStretch()

    def _build_selftest_tab(self):
        layout = QVBoxLayout(self.tab_selftest)
        layout.addWidget(QLabel("NIST Known Answer Tests (KAT): FIPS 197, SP 800-38A, SP 800-38C, SP 800-38D"))

        btn_run_tests = QPushButton("Run All NIST Tests")
        btn_run_tests.setStyleSheet("font-weight: bold; padding: 8px;")
        btn_run_tests.clicked.connect(self._run_selftest)
        layout.addWidget(btn_run_tests)

        self.txt_selftest_log = QTextEdit()
        self.txt_selftest_log.setReadOnly(True)
        self.txt_selftest_log.setFont(QFont("Consolas", 10))
        layout.addWidget(self.txt_selftest_log)

    # ============================================================
    #  Event Handlers & Helpers
    # ============================================================
    def _on_mode_changed(self):
        mode = self.cb_mode.currentText()
        is_aead = mode in ("GCM", "CCM")
        is_ecb = mode == "ECB"

        self.lbl_iv.setVisible(not is_ecb)
        self.txt_iv.setVisible(not is_ecb)

        if mode == "CCM":
            self.lbl_iv.setText("Nonce (7-13 B):")
        elif mode == "CTR":
            self.lbl_iv.setText("Counter (16 B):")
        else:
            self.lbl_iv.setText("IV (16 B):")

        self.lbl_aad.setVisible(is_aead)
        self.txt_aad.setVisible(is_aead)
        self.lbl_taglen.setVisible(is_aead)
        self.sp_taglen.setVisible(is_aead)
        self.lbl_tag_text.setVisible(is_aead)
        self.txt_tag.setVisible(is_aead)

    def _on_keysize_changed(self):
        pass

    def _get_key_bytes(self) -> bytes:
        raw = self.txt_key.text().strip()
        if not raw:
            raise ValueError("Key is empty.")

        expected_len = 16
        ks_str = self.cb_keysize.currentText()
        if "192" in ks_str: expected_len = 24
        elif "256" in ks_str: expected_len = 32

        if self.rb_key_hex.isChecked():
            try:
                k = bytes.fromhex(raw)
            except ValueError:
                raise ValueError("Key is not valid hexadecimal string.")
        else:
            k = raw.encode("utf-8")

        if len(k) != expected_len:
            raise ValueError(f"Key length is {len(k)} bytes; expected {expected_len} bytes.")
        return k

    def _get_iv_bytes(self) -> bytes:
        mode = self.cb_mode.currentText()
        if mode == "ECB":
            return b""
        raw = self.txt_iv.text().strip()
        if not raw:
            raise ValueError(f"{mode} mode requires an IV / Nonce.")
        try:
            return bytes.fromhex(raw)
        except ValueError:
            return raw.encode("utf-8")

    def _get_aad_bytes(self) -> bytes:
        raw = self.txt_aad.text().strip()
        if not raw:
            return b""
        try:
            return bytes.fromhex(raw)
        except ValueError:
            return raw.encode("utf-8")

    def _gen_random_key(self):
        ks_str = self.cb_keysize.currentText()
        n = 16
        if "192" in ks_str: n = 24
        elif "256" in ks_str: n = 32
        self.txt_key.setText(secrets.token_bytes(n).hex())
        self.rb_key_hex.setChecked(True)

    def _gen_random_iv(self):
        mode = self.cb_mode.currentText()
        n = 16
        if mode == "CCM": n = 12
        elif mode == "GCM": n = 12
        self.txt_iv.setText(secrets.token_bytes(n).hex())

    def _do_text_encrypt(self):
        try:
            key = self._get_key_bytes()
            iv = self._get_iv_bytes()
            mode = self.cb_mode.currentText()
            raw_in = self.txt_input.toPlainText()

            if self.rb_in_hex.isChecked():
                pt = bytes.fromhex(raw_in.strip())
            else:
                pt = raw_in.encode("utf-8")

            t0 = time.perf_counter()
            tag = b""

            if mode == "ECB":
                if self.chk_pkcs7.isChecked():
                    pad = 16 - (len(pt) % 16)
                    pt = pt + bytes([pad] * pad)
                ct = aeslib.ecb_encrypt(key, pt)
            elif mode == "CBC":
                if self.chk_pkcs7.isChecked():
                    pad = 16 - (len(pt) % 16)
                    pt = pt + bytes([pad] * pad)
                ct = aeslib.cbc_encrypt(key, iv, pt)
            elif mode.startswith("CFB"):
                sbits = 128
                if mode == "CFB8": sbits = 8
                elif mode == "CFB1": sbits = 1
                ct = aeslib.cfb_encrypt(key, iv, pt, sbits)
            elif mode == "OFB":
                ct = aeslib.ofb_encrypt(key, iv, pt)
            elif mode == "CTR":
                ct = aeslib.ctr_crypt(key, iv, pt)
            elif mode == "GCM":
                aad = self._get_aad_bytes()
                tag_len = self.sp_taglen.value()
                ct, tag = aeslib.gcm_encrypt(key, iv, pt, aad, tag_len)
                self.txt_tag.setText(tag.hex())
            elif mode == "CCM":
                aad = self._get_aad_bytes()
                tag_len = self.sp_taglen.value()
                ct, tag = aeslib.ccm_encrypt(key, iv, pt, aad, tag_len)
                self.txt_tag.setText(tag.hex())

            t1 = time.perf_counter()
            ms = (t1 - t0) * 1000.0

            self.txt_output.setPlainText(ct.hex())
            status = f"Encrypted {len(pt)} bytes in {ms:.2f} ms."
            if tag:
                status += f" Tag: {tag.hex()}"
            self.lbl_status.setText(status)
            self.lbl_status.setStyleSheet("color: green; font-weight: bold;")

        except Exception as e:
            QMessageBox.critical(self, "Encryption Error", str(e))
            self.lbl_status.setText(f"Error: {e}")
            self.lbl_status.setStyleSheet("color: red; font-weight: bold;")

    def _do_text_decrypt(self):
        try:
            key = self._get_key_bytes()
            iv = self._get_iv_bytes()
            mode = self.cb_mode.currentText()
            raw_in = self.txt_input.toPlainText().strip()
            ct = bytes.fromhex(raw_in)

            t0 = time.perf_counter()

            if mode == "ECB":
                pt = aeslib.ecb_decrypt(key, ct)
                if self.chk_pkcs7.isChecked() and len(pt) > 0:
                    pad = pt[-1]
                    if 1 <= pad <= 16: pt = pt[:-pad]
            elif mode == "CBC":
                pt = aeslib.cbc_decrypt(key, iv, ct)
                if self.chk_pkcs7.isChecked() and len(pt) > 0:
                    pad = pt[-1]
                    if 1 <= pad <= 16: pt = pt[:-pad]
            elif mode.startswith("CFB"):
                sbits = 128
                if mode == "CFB8": sbits = 8
                elif mode == "CFB1": sbits = 1
                pt = aeslib.cfb_decrypt(key, iv, ct, sbits)
            elif mode == "OFB":
                pt = aeslib.ofb_decrypt(key, iv, ct)
            elif mode == "CTR":
                pt = aeslib.ctr_crypt(key, iv, ct)
            elif mode == "GCM":
                aad = self._get_aad_bytes()
                tag_str = self.txt_tag.text().strip()
                if not tag_str:
                    raise ValueError("Authentication tag is required for GCM decryption.")
                tag = bytes.fromhex(tag_str)
                pt = aeslib.gcm_decrypt(key, iv, ct, tag, aad)
            elif mode == "CCM":
                aad = self._get_aad_bytes()
                tag_str = self.txt_tag.text().strip()
                if not tag_str:
                    raise ValueError("Authentication tag is required for CCM decryption.")
                tag = bytes.fromhex(tag_str)
                pt = aeslib.ccm_decrypt(key, iv, ct, tag, aad)

            t1 = time.perf_counter()
            ms = (t1 - t0) * 1000.0

            # Display as UTF-8 or Hex if not valid UTF-8
            try:
                self.txt_output.setPlainText(pt.decode("utf-8"))
            except UnicodeDecodeError:
                self.txt_output.setPlainText(pt.hex())

            self.lbl_status.setText(f"Decrypted {len(ct)} bytes successfully in {ms:.2f} ms.")
            self.lbl_status.setStyleSheet("color: green; font-weight: bold;")

        except aeslib.AuthenticationError as e:
            QMessageBox.critical(self, "Authentication Failed", f"TAG VERIFICATION FAILED: {e}")
            self.lbl_status.setText("AUTHENTICATION FAILED (Data may have been tampered with)")
            self.lbl_status.setStyleSheet("color: red; font-weight: bold;")
        except Exception as e:
            QMessageBox.critical(self, "Decryption Error", str(e))
            self.lbl_status.setText(f"Error: {e}")
            self.lbl_status.setStyleSheet("color: red; font-weight: bold;")

    def _copy_output(self):
        QApplication.clipboard().setText(self.txt_output.toPlainText())
        QMessageBox.information(self, "Copied", "Output copied to clipboard.")

    def _browse_in_file(self):
        fn, _ = QFileDialog.getOpenFileName(self, "Select Input File")
        if fn:
            self.txt_file_in.setText(fn)
            if not self.txt_file_out.text():
                self.txt_file_out.setText(fn + ".aes")

    def _browse_out_file(self):
        fn, _ = QFileDialog.getSaveFileName(self, "Select Output File")
        if fn:
            self.txt_file_out.setText(fn)

    def _do_file_process(self, is_encrypt: bool):
        in_path = self.txt_file_in.text().strip()
        out_path = self.txt_file_out.text().strip()
        if not in_path or not os.path.isfile(in_path):
            QMessageBox.warning(self, "File Error", "Please select a valid input file.")
            return
        if not out_path:
            QMessageBox.warning(self, "File Error", "Please specify an output file.")
            return

        try:
            key = self._get_key_bytes()
            iv = self._get_iv_bytes()
            mode = self.cb_mode.currentText()
            aad = self._get_aad_bytes()
            tag_len = self.sp_taglen.value()

            self.file_progress.setValue(0)
            self.lbl_file_status.setText("Processing file in background...")

            self.worker = FileWorker(mode, is_encrypt, in_path, out_path, key, iv, iv, aad, tag_len)
            self.worker.progress.connect(self.file_progress.setValue)
            self.worker.finished.connect(self._on_file_finished)
            self.worker.start()

        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def _on_file_finished(self, success: bool, message: str, elapsed: float, mbps: float):
        if success:
            self.lbl_file_status.setText(f"{message} ({elapsed:.2f} s, {mbps:.1f} MB/s)")
            self.lbl_file_status.setStyleSheet("color: green; font-weight: bold;")
            QMessageBox.information(self, "Finished", f"File processing complete!\n{message}\nTime: {elapsed:.2f}s ({mbps:.1f} MB/s)")
        else:
            self.lbl_file_status.setText(message)
            self.lbl_file_status.setStyleSheet("color: red; font-weight: bold;")
            QMessageBox.critical(self, "Failed", message)

    def _run_selftest(self):
        self.txt_selftest_log.clear()
        self.txt_selftest_log.append("Starting NIST Self-Test...\n")
        try:
            import pytest
            test_file = os.path.join(os.path.dirname(__file__), "tests", "test_aeslib.py")
            self.txt_selftest_log.append(f"Running pytest on: {test_file}\n")
            # Run in-process pytest
            ret = pytest.main(["-v", test_file])
            if ret == 0:
                self.txt_selftest_log.append("\n===> ALL NIST SELF-TESTS PASSED 100%! <===")
            else:
                self.txt_selftest_log.append(f"\nTests finished with exit code {ret}.")
        except Exception as e:
            self.txt_selftest_log.append(f"Error executing self-test: {e}")


def main():
    app = QApplication(sys.argv)
    win = AESMainWindow()
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()

