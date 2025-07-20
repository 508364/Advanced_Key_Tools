import os
import sys
import time
import uuid
import psutil
import hashlib
import secrets
import binascii
import logging
import threading
import struct
import zipfile
import shutil
import tempfile
import subprocess
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64
import io
import imghdr
from PIL import Image, ImageQt
from PyQt5.QtWidgets import (QApplication, QMainWindow, QTabWidget, QWidget, QVBoxLayout, QHBoxLayout, 
                            QPushButton, QTextEdit, QLineEdit, QLabel, QFileDialog, QGroupBox, 
                            QScrollArea, QMessageBox, QSizePolicy, QProgressBar, QCheckBox,
                            QGridLayout, QComboBox)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QPixmap, QImage, QFont

# 自定义符号集 (ASCII可打印特殊字符)
SYMBOLS = r"""!@#$%^&*()_+~`-=[];'\,./{}:"|<>?"""

# 设置日志记录
logging.basicConfig(filename='key_tool.log', level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

class KeyLogger:
    """记录每一步密钥生成过程"""
    def __init__(self):
        self.log = {}
        self.counter = 1
    
    def add(self, name, value):
        """添加密钥记录"""
        self.log[f"{self.counter:02d}_{name}"] = value
        self.counter += 1
        return value
    
    def hexify(self, data):
        """转换为十六进制表示"""
        return binascii.hexlify(data).decode()
    
    def display(self):
        """显示所有记录的密钥"""
        log_text = ""
        for name, value in self.log.items():
            step_id = name.split("_")[0]
            step_name = name.split("_", 1)[1]
            if isinstance(value, bytes):
                value_str = f"{self.hexify(value[:8])}...{self.hexify(value[-8:])}"
            elif isinstance(value, tuple):
                value_str = f"公钥:\n{value[0]}\n\n私钥:\n{value[1]}"
            else:
                value_str = str(value)
                
            log_text += f"[Step {step_id}] {step_name:14} : {value_str}\n"
        return log_text

class KeyGeneratorThread(QThread):
    """密钥生成线程"""
    progress = pyqtSignal(int, str)
    completed = pyqtSignal(str, str, str, str, str)
    error = pyqtSignal(str)
    
    def run(self):
        try:
            # 1. 收集熵源
            self.progress.emit(10, "收集系统熵源...")
            entropy = self.generate_entropy()
            
            # 2. 创建密钥记录器
            logger = KeyLogger()
            logger.add("原始熵源", entropy)
            
            # 3. 密钥派生链
            self.progress.emit(30, "执行一级密钥派生 (SHA512)...")
            k1, salt1 = self.derive_key(entropy, None, logger=logger, dklen=64)
            
            self.progress.emit(45, "执行二级密钥派生 (SHA3-512)...")
            k2, salt2 = self.derive_key(k1, salt1, logger=logger, algo='sha3_512', dklen=64)
            
            self.progress.emit(60, "执行三级密钥派生 (BLAKE2s)...")
            k3, salt3 = self.derive_key(k2, salt2, logger=logger, algo='blake2s', dklen=64)
            
            # 4. 生成RSA密钥对
            self.progress.emit(75, "生成RSA-2048密钥对...")
            rsa_seed = k3[:32]  # 使用前256位作为种子
            public_key, private_key = self.generate_rsa_keypair(rsa_seed)
            logger.add("RSA_2048密钥对", (public_key, private_key))
            
            # 5. 创建密钥ID
            hex_key = binascii.hexlify(k3).decode()
            key_id = f"KEY-{time.strftime('%Y%m%d-%H%M%S')}-{hex_key[:6].upper()}"
            
            # 6. 格式化密钥
            self.progress.emit(90, "格式化密钥...")
            formatted_key = self.format_key(hex_key)
            
            # 7. 完成并发送结果
            self.progress.emit(100, "密钥生成完成!")
            log_text = logger.display()
            self.completed.emit(formatted_key, hex_key, public_key, private_key, key_id)
            
        except Exception as e:
            logging.exception("密钥生成失败!")
            self.error.emit(str(e))
    
    def collect_network_data(self, duration=10):
        """收集网络数据"""
        def _collect(result):
            try:
                initial = psutil.net_io_counters()
                time.sleep(duration)
                final = psutil.net_io_counters()
                net_data = struct.pack(
                    'QQQQQQQQQ',
                    final.bytes_recv - initial.bytes_recv,
                    final.bytes_sent - initial.bytes_sent,
                    final.packets_recv - initial.packets_recv,
                    final.packets_sent - initial.packets_sent,
                    time.perf_counter_ns(),
                    os.getpid(),
                    os.getppid(),
                    len(threading.enumerate()),
                    time.monotonic_ns()
                )
                result.append(net_data)
            except Exception as e:
                logging.error(f"网络数据收集失败: {e}")
                result.append(os.urandom(64))

        result = []
        thread = threading.Thread(target=_collect, args=(result,))
        thread.start()
        return result, thread
    
    def generate_entropy(self):
        """生成熵源数据"""
        # 1. 启动网络数据收集线程
        net_result, net_thread = self.collect_network_data()
        
        # 2. 主线程生成其他熵源
        timestamp = struct.pack('d', time.time())
        uuids = [uuid.UUID(bytes=os.urandom(16), version=4) for _ in range(5)]
        uuids_bytes = b''.join(u.bytes for u in uuids)
        randoms = [os.urandom(4) for _ in range(5)]
        
        # 3. 等待网络线程完成
        net_thread.join()
        net_data = net_result[0]
        
        # 4. 组合所有熵源
        entropy = timestamp + uuids_bytes + net_data + b''.join(randoms)
        return entropy
    
    def derive_key(self, seed, prev_salt, iterations=100000, dklen=64, algo='sha512', logger=None):
        """派生密钥"""
        new_salt = hashlib.shake_128(prev_salt + seed).digest(32) if prev_salt else os.urandom(32)
        derived = hashlib.pbkdf2_hmac(
            algo, 
            seed, 
            new_salt, 
            iterations, 
            dklen=dklen
        )
        if logger:
            logger.add(f"PBKDF2-HMAC-{algo}", derived)
            logger.add(f"SALT_{algo}", new_salt)
        return derived, new_salt
    
    def generate_rsa_keypair(self, seed):
        """生成RSA密钥对"""
        class SeedRandom:
            def __init__(self, seed):
                self.position = 0
                self.seed = seed
                
            def __call__(self, size):
                result = b""
                while len(result) < size:
                    start = self.position % len(self.seed)
                    end = min(len(self.seed), start + size - len(result))
                    result += self.seed[start:end]
                    self.position = end
                    if self.position >= len(self.seed):
                        self.seed = hashlib.sha256(self.seed).digest()
                        self.position = 0
                return result
        
        rsa_gen = RSA.generate(2048, randfunc=SeedRandom(seed))
        private_key = rsa_gen.export_key().decode()
        public_key = rsa_gen.publickey().export_key().decode()
        return public_key, private_key
    
    def format_key(self, hex_key):
        """格式化密钥"""
        group_size = secrets.choice([4, 5, 6, 7, 8])
        groups = [hex_key[i:i+group_size] for i in range(0, len(hex_key), group_size)]
        separators = [secrets.choice(SYMBOLS) for _ in groups[1:]]
        formatted = groups[0]
        for i, sep in enumerate(separators, 1):
            formatted += sep + groups[i]
        return formatted

class KeyToolsGUI(QMainWindow):
    """高级密钥工具GUI"""
    def __init__(self):
        super().__init__()
        self.setWindowTitle("高级密钥工具 v2.0")
        self.setGeometry(100, 100, 900, 700)
        
        # 主界面布局
        self.main_widget = QWidget()
        self.setCentralWidget(self.main_widget)
        
        self.main_layout = QVBoxLayout(self.main_widget)
        
        # 创建选项卡
        self.tabs = QTabWidget()
        self.main_layout.addWidget(self.tabs)
        
        # 创建各个功能标签页
        self.setup_keygen_tab()
        self.setup_rsa_crypto_tab()
        self.setup_image_steganography_tab()
        
        # 初始化生成密钥
        self.current_public_key = ""
        self.current_private_key = ""
        self.current_key_id = ""
        self.current_image_path = ""
        
        # 状态栏
        self.statusBar().showMessage("准备就绪")
    
    def setup_keygen_tab(self):
        """设置密钥生成标签页"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # 密钥生成控制组
        group = QGroupBox("密钥生成")
        group_layout = QVBoxLayout(group)
        
        # 生成密钥按钮
        self.btn_generate = QPushButton("生成高级密钥")
        self.btn_generate.setStyleSheet("background-color: #4CAF50; color: white; font-weight: bold;")
        self.btn_generate.clicked.connect(self.generate_keys)
        group_layout.addWidget(self.btn_generate)
        
        # 进度条
        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        group_layout.addWidget(self.progress)
        
        # 状态标签
        self.status_label = QLabel("准备生成密钥...")
        group_layout.addWidget(self.status_label)
        
        # 保存选项
        self.chk_save_files = QCheckBox("生成后保存密钥文件")
        self.chk_save_files.setChecked(True)
        group_layout.addWidget(self.chk_save_files)
        
        # 密钥显示区域
        self.key_result = QTextEdit()
        self.key_result.setReadOnly(True)
        self.key_result.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Expanding)
        self.key_result.setFont(QFont("Consolas", 10))
        group_layout.addWidget(self.key_result)
        
        layout.addWidget(group)
        
        # 添加标签页
        self.tabs.addTab(tab, "密钥生成")
    
    def setup_rsa_crypto_tab(self):
        """设置RSA加解密标签页"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # 公钥区域
        group_pub = QGroupBox("公钥")
        group_pub_layout = QVBoxLayout(group_pub)
        self.pub_key_text = QTextEdit()
        self.pub_key_text.setPlaceholderText("在此粘贴或导入公钥")
        self.pub_key_text.setFixedHeight(120)
        self.pub_key_text.setFont(QFont("Consolas", 9))
        group_pub_layout.addWidget(self.pub_key_text)
        
        # 使用当前公钥按钮
        self.btn_use_current_pub = QPushButton("使用当前生成密钥的公钥")
        self.btn_use_current_pub.clicked.connect(self.use_current_pub_key)
        group_pub_layout.addWidget(self.btn_use_current_pub)
        
        # 私钥区域
        group_priv = QGroupBox("私钥")
        group_priv_layout = QVBoxLayout(group_priv)
        self.priv_key_text = QTextEdit()
        self.priv_key_text.setPlaceholderText("在此粘贴或导入私钥")
        self.priv_key_text.setFixedHeight(120)
        self.priv_key_text.setFont(QFont("Consolas", 9))
        group_priv_layout.addWidget(self.priv_key_text)
        
        # 使用当前私钥按钮
        self.btn_use_current_priv = QPushButton("使用当前生成密钥的私钥")
        self.btn_use_current_priv.clicked.connect(self.use_current_priv_key)
        group_priv_layout.addWidget(self.btn_use_current_priv)
        
        layout.addWidget(group_pub)
        layout.addWidget(group_priv)
        
        # 输入区域
        group_input = QGroupBox("加解密操作")
        group_input_layout = QVBoxLayout(group_input)
        
        # 明文区域
        self.input_text = QTextEdit()
        self.input_text.setPlaceholderText("输入要加密的文本或解密的Base64密文")
        self.input_text.setFont(QFont("Consolas", 10))
        group_input_layout.addWidget(self.input_text)
        
        # 加密按钮
        self.btn_encrypt = QPushButton("加密")
        self.btn_encrypt.setStyleSheet("background-color: #2196F3; color: white;")
        self.btn_encrypt.clicked.connect(self.encrypt_text)
        group_input_layout.addWidget(self.btn_encrypt)
        
        # 解密按钮
        self.btn_decrypt = QPushButton("解密")
        self.btn_decrypt.setStyleSheet("background-color: #FF9800; color: white;")
        self.btn_decrypt.clicked.connect(self.decrypt_text)
        group_input_layout.addWidget(self.btn_decrypt)
        
        layout.addWidget(group_input)
        
        # 结果区域
        group_result = QGroupBox("结果")
        group_result_layout = QVBoxLayout(group_result)
        self.result_text = QTextEdit()
        self.result_text.setReadOnly(True)
        self.result_text.setFont(QFont("Consolas", 10))
        group_result_layout.addWidget(self.result_text)
        
        layout.addWidget(group_result)
        self.tabs.addTab(tab, "RSA加解密")
    
    def setup_image_steganography_tab(self):
        """设置图种制作标签页"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # 图片选择
        group_image = QGroupBox("选择图片")
        group_image_layout = QVBoxLayout(group_image)
        
        self.image_path = QLineEdit()
        self.image_path.setReadOnly(True)
        group_image_layout.addWidget(self.image_path)
        
        h_layout = QHBoxLayout()
        self.btn_browse_image = QPushButton("浏览图片")
        self.btn_browse_image.clicked.connect(self.browse_image)
        h_layout.addWidget(self.btn_browse_image)
        
        self.btn_preview_image = QPushButton("预览图片")
        self.btn_preview_image.clicked.connect(self.preview_image)
        h_layout.addWidget(self.btn_preview_image)
        
        group_image_layout.addLayout(h_layout)
        
        # 图片预览
        self.image_preview = QLabel()
        self.image_preview.setAlignment(Qt.AlignCenter)
        self.image_preview.setMinimumHeight(200)
        self.image_preview.setStyleSheet("background-color: #f0f0f0; border: 1px solid #cccccc;")
        self.image_preview.setText("图片预览")
        group_image_layout.addWidget(self.image_preview)
        
        layout.addWidget(group_image)
        
        # 文件嵌入
        group_embed = QGroupBox("嵌入文件")
        group_embed_layout = QVBoxLayout(group_embed)
        
        self.file_path = QLineEdit()
        self.file_path.setReadOnly(True)
        group_embed_layout.addWidget(self.file_path)
        
        h_layout = QHBoxLayout()
        self.btn_browse_file = QPushButton("浏览文件")
        self.btn_browse_file.clicked.connect(self.browse_file)
        h_layout.addWidget(self.btn_browse_file)
        
        self.btn_create_stego = QPushButton("创建图种")
        self.btn_create_stego.setStyleSheet("background-color: #9C27B0; color: white; font-weight: bold;")
        self.btn_create_stego.clicked.connect(self.create_stego_image)
        h_layout.addWidget(self.btn_create_stego)
        
        group_embed_layout.addLayout(h_layout)
        
        # 保存位置选项
        h_layout = QHBoxLayout()
        self.save_location = QLineEdit()
        self.save_location.setPlaceholderText("选择保存位置...")
        self.save_location.setReadOnly(True)
        h_layout.addWidget(self.save_location)
        
        self.btn_browse_save = QPushButton("浏览位置")
        self.btn_browse_save.clicked.connect(self.browse_save_location)
        h_layout.addWidget(self.btn_browse_save)
        
        group_embed_layout.addLayout(h_layout)
        
        # 提取图种
        group_extract = QGroupBox("提取隐藏文件")
        group_extract_layout = QVBoxLayout(group_extract)
        
        h_layout = QHBoxLayout()
        self.btn_extract_stego = QPushButton("提取文件")
        self.btn_extract_stego.setStyleSheet("background-color: #E91E63; color: white;")
        self.btn_extract_stego.clicked.connect(self.extract_from_stego)
        h_layout.addWidget(self.btn_extract_stego)
        
        self.btn_test_stego = QPushButton("测试图种")
        self.btn_test_stego.setStyleSheet("background-color: #607D8B; color: white;")
        self.btn_test_stego.clicked.connect(self.test_stego_image)
        h_layout.addWidget(self.btn_test_stego)
        
        group_extract_layout.addLayout(h_layout)
        
        # 状态信息
        self.stego_status = QLabel("请先选择图片和要隐藏的文件")
        group_extract_layout.addWidget(self.stego_status)
        
        layout.addWidget(group_embed)
        layout.addWidget(group_extract)
        
        self.tabs.addTab(tab, "图种制作器")
    
    def generate_keys(self):
        """启动密钥生成"""
        self.btn_generate.setEnabled(False)
        self.status_label.setText("密钥生成中，请稍候...")
        self.progress.setValue(0)
        
        self.worker = KeyGeneratorThread()
        self.worker.progress.connect(self.update_progress)
        self.worker.completed.connect(self.key_generated)
        self.worker.error.connect(self.key_error)
        self.worker.start()
    
    def update_progress(self, value, message):
        """更新进度"""
        self.progress.setValue(value)
        self.status_label.setText(message)
        self.statusBar().showMessage(message)
    
    def key_generated(self, formatted_key, hex_key, public_key, private_key, key_id):
        """密钥生成完成处理"""
        self.current_public_key = public_key
        self.current_private_key = private_key
        self.current_key_id = key_id
        
        result = f"""===== 高级密钥生成结果 =====

密钥ID: {key_id}
生成时间: {time.strftime('%Y-%m-%d %H:%M:%S')}

===== 格式化密钥 =====
{formatted_key}

===== 完整十六进制 =====
{hex_key}

===== 公钥 =====
{public_key}

===== 私钥 =====
{private_key}
"""
        self.key_result.setText(result)
        self.status_label.setText("密钥生成成功!")
        self.btn_generate.setEnabled(True)
        self.statusBar().showMessage("密钥生成成功!")
        
        # 自动保存文件
        if self.chk_save_files.isChecked():
            self.save_key_files(formatted_key, hex_key, public_key, private_key, key_id)
    
    def key_error(self, error_msg):
        """密钥生成错误处理"""
        QMessageBox.critical(self, "密钥生成错误", f"生成密钥时出错:\n{error_msg}")
        self.status_label.setText(f"错误: {error_msg}")
        self.btn_generate.setEnabled(True)
        self.statusBar().showMessage("密钥生成失败!")
    
    def save_key_files(self, formatted_key, hex_key, public_key, private_key, key_id):
        """保存密钥文件为ZIP包"""
        try:
            temp_dir = tempfile.mkdtemp(prefix="keygen_")
            
            # 保存格式化密钥
            txt_path = os.path.join(temp_dir, "key.txt")
            with open(txt_path, "w", encoding="utf-8") as f:
                f.write(f"密钥ID: {key_id}\n")
                f.write(f"生成时间: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                f.write("===== 格式化密钥 =====\n")
                f.write(formatted_key)
                f.write("\n\n===== 完整十六进制 =====\n")
                f.write(hex_key)
            
            # 保存公钥
            pem_path = os.path.join(temp_dir, "key.pem")
            with open(pem_path, "w", encoding="utf-8") as f:
                f.write(public_key)
            
            # 保存私钥
            key_path = os.path.join(temp_dir, "key.key")
            with open(key_path, "w", encoding="utf-8") as f:
                f.write(private_key)
            
            # 选择保存位置
            options = QFileDialog.Options()
            save_path, _ = QFileDialog.getSaveFileName(
                self, "保存密钥文件", 
                os.path.join(os.path.expanduser("~"), "Desktop", f"密钥包_{time.strftime('%Y%m%d')}.zip"),
                "ZIP文件 (*.zip)", 
                options=options
            )
            
            if not save_path:
                return  # 用户取消
                
            # 创建ZIP文件
            with zipfile.ZipFile(save_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for file in [txt_path, pem_path, key_path]:
                    zipf.write(file, os.path.basename(file))
                
                zipf.setpassword(key_id.encode('utf-8'))
            
            # 清理临时文件
            shutil.rmtree(temp_dir)
            
            # 显示成功消息
            self.statusBar().showMessage(f"密钥文件已保存到: {save_path}")
            QMessageBox.information(self, "文件保存成功", 
                                  f"密钥文件已保存到:\n{save_path}\n"
                                  f"解压密码: {key_id}")
        except Exception as e:
            logging.error(f"保存密钥文件失败: {e}")
            QMessageBox.warning(self, "保存失败", f"保存密钥文件时出错:\n{str(e)}")
    
    # RSA加解密功能
    def use_current_pub_key(self):
        """使用当前生成的公钥"""
        if self.current_public_key:
            self.pub_key_text.setPlainText(self.current_public_key)
            self.statusBar().showMessage("当前公钥已加载!")
        else:
            QMessageBox.warning(self, "无公钥", "请先生成密钥对!")
    
    def use_current_priv_key(self):
        """使用当前生成的私钥"""
        if self.current_private_key:
            self.priv_key_text.setPlainText(self.current_private_key)
            self.statusBar().showMessage("当前私钥已加载!")
        else:
            QMessageBox.warning(self, "无私钥", "请先生成密钥对!")
    
    def encrypt_text(self):
        """加密文本"""
        public_key = self.pub_key_text.toPlainText().strip()
        text = self.input_text.toPlainText().strip()
        
        if not public_key:
            QMessageBox.warning(self, "缺少公钥", "请输入或选择公钥!")
            return
            
        if not text:
            QMessageBox.warning(self, "缺少明文", "请输入要加密的文本!")
            return
        
        try:
            # 导入公钥
            rsa_key = RSA.import_key(public_key)
            cipher = PKCS1_OAEP.new(rsa_key)
            
            # 加密文本
            encrypted = cipher.encrypt(text.encode())
            
            # Base64编码
            encrypted_b64 = base64.b64encode(encrypted).decode()
            
            # 显示结果
            self.result_text.setPlainText(encrypted_b64)
            self.statusBar().showMessage("加密成功!")
        except Exception as e:
            QMessageBox.critical(self, "加密错误", f"加密过程中出错:\n{str(e)}")
    
    def decrypt_text(self):
        """解密文本"""
        private_key = self.priv_key_text.toPlainText().strip()
        encrypted_b64 = self.input_text.toPlainText().strip()
        
        if not private_key:
            QMessageBox.warning(self, "缺少私钥", "请输入或选择私钥!")
            return
            
        if not encrypted_b64:
            QMessageBox.warning(self, "缺少密文", "请输入要解密的Base64密文!")
            return
        
        try:
            # Base64解码
            encrypted = base64.b64decode(encrypted_b64)
            
            # 导入私钥
            rsa_key = RSA.import_key(private_key)
            cipher = PKCS1_OAEP.new(rsa_key)
            
            # 解密
            decrypted = cipher.decrypt(encrypted).decode()
            
            # 显示结果
            self.result_text.setPlainText(decrypted)
            self.statusBar().showMessage("解密成功!")
        except Exception as e:
            QMessageBox.critical(self, "解密错误", f"解密过程中出错:\n{str(e)}")
    
    # 图种制作器功能
    def browse_image(self):
        """浏览图片"""
        options = QFileDialog.Options()
        file, _ = QFileDialog.getOpenFileName(self, "选择图片", "", 
                                             "图片文件 (*.png *.jpg *.jpeg *.bmp);;所有文件 (*.*)", 
                                             options=options)
        if file:
            self.image_path.setText(file)
            self.current_image_path = file
            self.stego_status.setText("图片已选择")
    
    def browse_file(self):
        """浏览文件"""
        options = QFileDialog.Options()
        file, _ = QFileDialog.getOpenFileName(self, "选择要隐藏的文件", "", 
                                             "所有文件 (*.*)", 
                                             options=options)
        if file:
            self.file_path.setText(file)
            self.stego_status.setText("文件已选择")
    
    def browse_save_location(self):
        """浏览保存位置"""
        options = QFileDialog.Options()
        save_dir = QFileDialog.getExistingDirectory(self, "选择保存位置", 
                                                   os.path.expanduser("~"), 
                                                   options=options)
        if save_dir:
            self.save_location.setText(save_dir)
    
    def preview_image(self):
        """预览图片"""
        if not self.current_image_path:
            QMessageBox.warning(self, "无图片", "请先选择一张图片!")
            return
        
        try:
            # 使用PIL打开图片
            img = Image.open(self.current_image_path)
            
            # 调整大小用于预览
            max_size = (600, 400)
            if img.width > max_size[0] or img.height > max_size[1]:
                img.thumbnail(max_size, Image.LANCZOS)
            
            # 转换为Qt格式
            qim = ImageQt.ImageQt(img)
            pixmap = QPixmap.fromImage(qim)
            
            # 设置预览
            self.image_preview.setPixmap(pixmap)
            self.image_preview.setScaledContents(True)
            
        except Exception as e:
            QMessageBox.critical(self, "预览错误", f"图片预览失败:\n{str(e)}")
    
    def create_stego_image(self):
        """创建图种"""
        image_path = self.image_path.text().strip()
        file_path = self.file_path.text().strip()
        save_dir = self.save_location.text().strip()
        
        if not image_path:
            QMessageBox.warning(self, "无图片", "请先选择一张图片!")
            return
            
        if not file_path:
            QMessageBox.warning(self, "无文件", "请先选择要隐藏的文件!")
            return
            
        # 设置默认保存位置
        if not save_dir:
            save_dir = os.path.dirname(image_path)
        
        try:
            # 读取图片
            with open(image_path, "rb") as img_file:
                image_data = img_file.read()
            
            # 读取文件
            with open(file_path, "rb") as file_file:
                file_data = file_file.read()
            
            # 创建图种
            stego_data = image_data + file_data
            
            # 保存图种
            base_name = os.path.basename(image_path)
            name, ext = os.path.splitext(base_name)
            save_path = os.path.join(save_dir, f"{name}_stego{ext}")
            
            with open(save_path, "wb") as stego_file:
                stego_file.write(stego_data)
            
            self.stego_status.setText(f"图种创建成功: {os.path.basename(save_path)}")
            self.statusBar().showMessage(f"图种已保存到: {save_path}")
            QMessageBox.information(self, "创建成功", 
                                  f"图种创建成功!\n保存位置: {save_path}\n\n"
                                  "使用说明:\n"
                                  "1. 修改扩展名为.png查看图片\n"
                                  "2. 修改扩展名为.zip解压文件")
        except Exception as e:
            logging.error(f"创建图种失败: {str(e)}")
            QMessageBox.critical(self, "创建失败", f"创建图种时出错:\n{str(e)}")
    
    def extract_from_stego(self):
        """从图种中提取文件"""
        if not self.current_image_path:
            QMessageBox.warning(self, "无图片", "请先选择一张包含隐藏文件的图片!")
            return
        
        try:
            # 读取文件
            with open(self.current_image_path, "rb") as stego_file:
                stego_data = stego_file.read()
            
            # 检测图片类型
            image_type = imghdr.what(io.BytesIO(stego_data))
            if not image_type:
                QMessageBox.critical(self, "无效图片", "无法识别图片格式!")
                return
            
            # 查找图片结束位置
            if image_type == "png":
                # PNG文件以IEND块结束
                iend_pos = stego_data.rfind(b'IEND\xaeB`\x82')
                if iend_pos == -1:
                    QMessageBox.critical(self, "提取失败", "无法找到PNG结束标记!")
                    return
                image_end = iend_pos + 8  # IEND块总长12字节
            elif image_type == "jpeg":
                # JPEG文件以FF D9结束
                jpeg_end = stego_data.rfind(b'\xFF\xD9')
                if jpeg_end == -1:
                    QMessageBox.critical(self, "提取失败", "无法找到JPEG结束标记!")
                    return
                image_end = jpeg_end + 2
            else:
                # 对于其他格式，尝试查找常见结束标记
                if b'\xFF\xD9' in stego_data:  # JPEG
                    image_end = stego_data.rfind(b'\xFF\xD9') + 2
                elif b'IEND\xaeB`\x82' in stego_data:  # PNG
                    image_end = stego_data.rfind(b'IEND\xaeB`\x82') + 8
                else:
                    # 尝试使用文件大小估计
                    img = Image.open(io.BytesIO(stego_data))
                    img.load()  # 确保完整读取图像数据
                    image_end = len(img.fp.read())
            
            # 提取隐藏文件
            file_data = stego_data[image_end:]
            
            if not file_data:
                QMessageBox.critical(self, "提取失败", "没有找到隐藏文件!")
                return
                
            # 保存文件
            save_dir = self.save_location.text().strip()
            if not save_dir:
                save_dir = os.path.dirname(self.current_image_path)
            
            save_path, _ = QFileDialog.getSaveFileName(
                self, "保存隐藏文件", 
                os.path.join(save_dir, "extracted_file"),
                "所有文件 (*.*)"
            )
            
            if save_path:
                with open(save_path, "wb") as extracted_file:
                    extracted_file.write(file_data)
                
                self.statusBar().showMessage(f"文件已提取到: {save_path}")
                QMessageBox.information(self, "提取成功", f"文件已提取到:\n{save_path}")
        except Exception as e:
            logging.error(f"提取文件失败: {str(e)}")
            QMessageBox.critical(self, "提取失败", f"提取文件时出错:\n{str(e)}")
    
    def test_stego_image(self):
        """测试图种文件"""
        if not self.current_image_path:
            QMessageBox.warning(self, "无图片", "请先选择一张图片进行测试!")
            return
        
        try:
            # 读取文件
            with open(self.current_image_path, "rb") as stego_file:
                stego_data = stego_file.read()
            
            # 检测图片类型
            image_type = imghdr.what(io.BytesIO(stego_data))
            if not image_type:
                QMessageBox.critical(self, "无效图片", "无法识别图片格式!")
                return
            
            # 获取图片大小
            stego_size = os.path.getsize(self.current_image_path)
            
            # 查找图片结束位置
            if image_type == "png":
                # PNG文件以IEND块结束
                iend_pos = stego_data.rfind(b'IEND\xaeB`\x82')
                if iend_pos == -1:
                    image_end = stego_size
                else:
                    image_end = iend_pos + 8
            elif image_type == "jpeg":
                # JPEG文件以FF D9结束
                jpeg_end = stego_data.rfind(b'\xFF\xD9')
                if jpeg_end == -1:
                    image_end = stego_size
                else:
                    image_end = jpeg_end + 2
            else:
                # 尝试使用文件大小估计
                try:
                    img = Image.open(io.BytesIO(stego_data))
                    img.load()
                    image_end = len(img.fp.read())
                except:
                    image_end = stego_size
            
            # 计算隐藏文件大小
            hidden_size = stego_size - image_end
            
            # 获取图片分辨率
            try:
                img = Image.open(self.current_image_path)
                width, height = img.size
                resolution = f"{width}×{height}"
            except:
                resolution = "未知"
            
            # 显示信息
            info = f"""
图片信息:
  文件路径: {self.current_image_path}
  文件大小: {stego_size:,} 字节
  图片类型: {image_type.upper()}
  图片分辨率: {resolution}
  图片数据大小: {image_end:,} 字节
  隐藏文件大小: {hidden_size:,} 字节
"""
            if hidden_size > 0:
                info += f"""
提示:
  此文件包含隐藏数据!
  请使用本工具的"提取文件"功能获取隐藏内容。
  或修改文件扩展名为.zip尝试解压。
"""
            else:
                info += "\n未检测到隐藏数据。"
                
            QMessageBox.information(self, "图种分析", info)
        except Exception as e:
            logging.error(f"测试图种失败: {str(e)}")
            QMessageBox.critical(self, "测试失败", f"分析图种时出错:\n{str(e)}")

def main():
    """主函数"""
    app = QApplication(sys.argv)
    
    # 设置应用样式
    app.setStyle("Fusion")
    app.setStyleSheet("""
        QGroupBox {
            font-weight: bold;
            border: 1px solid #cccccc;
            border-radius: 5px;
            margin-top: 1ex;
            padding-top: 10px;
        }
        QGroupBox::title {
            subcontrol-origin: margin;
            subcontrol-position: top left;
            padding: 0 3px;
            background-color: palette(base);
        }
        QTextEdit {
            font-family: "Consolas", "Courier New", monospace;
        }
        QProgressBar {
            text-align: center;
        }
        QLabel {
            font-size: 10pt;
        }
    """)
    
    # 创建主窗口
    window = KeyToolsGUI()
    window.show()
    
    # 主循环
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
