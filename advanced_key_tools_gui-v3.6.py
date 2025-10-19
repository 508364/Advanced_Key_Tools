"""
高级密钥工具 GUI v3.6
增强的密钥生成、RSA加密和图种制作工具
新增：鼠标晃动获取随机数功能
"""

import os
import sys
import time
import datetime
import uuid
import random
import math
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
import json
import base64
import io
import argparse
import urllib.request
from typing import Optional, Tuple, Dict, Any, List
from dataclasses import dataclass
from enum import Enum

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from PIL import Image, ImageQt

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QTabWidget, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QTextEdit, QLineEdit, QLabel, QFileDialog, QGroupBox,
    QScrollArea, QMessageBox, QSizePolicy, QProgressBar, QCheckBox,
    QGridLayout, QComboBox, QSplitter, QFrame, QStatusBar, QMenuBar, QMenu,
    QAction, QToolBar, QToolButton, QInputDialog, QTableWidget, QTableWidgetItem,
    QHeaderView, QStyle, QStackedWidget, QListWidget, QListWidgetItem,
    QTreeWidget, QTreeWidgetItem, QDialog
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer, QSettings, QUrl, QSize
from PyQt5.QtGui import QPixmap, QImage, QFont, QIcon, QPalette, QColor, QDesktopServices


# 自定义符号集
SYMBOLS = r"""!@#$%^&*()_+~`-=[];\',./{}:"|<>?"""

# API配置
API_CONFIG = {}

# 密钥类型枚举
class KeyType(Enum):
    SYMMETRIC = "symmetric"
    RSA_PUBLIC = "rsa_public"
    RSA_PRIVATE = "rsa_private"
    COMPOSITE = "composite"

# 密钥信息数据类
@dataclass
class KeyInfo:
    key_id: str
    formatted_key: str
    hex_key: str
    public_key: str
    private_key: str
    creation_time: str
    entropy_sources: Dict[str, Any]


class KeyLogger:
    """密钥生成日志记录器"""
    def __init__(self):
        self.log = {}
        self.counter = 1
    
    def add(self, name: str, value: Any) -> Any:
        """添加密钥记录"""
        self.log[f"{self.counter:02d}_{name}"] = value
        self.counter += 1
        return value
    
    def hexify(self, data: bytes) -> str:
        """转换为十六进制表示"""
        return binascii.hexlify(data).decode()
    
    def display(self) -> str:
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


class SecureKeyLogger:
    """密钥生成日志记录"""
    def __init__(self):
        self.log = {}
        self.counter = 1
    
    def add(self, name: str, value: Any = None) -> Any:
        """添加操作记录（不记录密钥值）"""
        self.log[f"{self.counter:02d}_{name}"] = f"步骤 {self.counter} 已完成"
        self.counter += 1
        return value if value is not None else None
    
    def display(self) -> str:
        """显示所有记录的操作步骤"""
        log_text = ""
        for name, value in self.log.items():
            step_id = name.split("_")[0]
            step_name = name.split("_", 1)[1]
            log_text += f"[Step {step_id}] {step_name:14} : {value}\n"
        return log_text


class ImageDownloadThread(QThread):
    """图片下载线程"""
    progress = pyqtSignal(int, str)
    completed = pyqtSignal(str, bytes)
    error = pyqtSignal(str)
    
    def __init__(self, width=200, height=300):
        super().__init__()
        self.width = width
        self.height = height
    
    def run(self):
        try:
            self.progress.emit(10, "连接Lorem Picsum服务器...")
            
            # 构建URL
            url = f"https://picsum.photos/{self.width}/{self.height}"
            
            self.progress.emit(30, "下载随机图片...")
            # 下载图片
            with urllib.request.urlopen(url) as response:
                image_data = response.read()
            
            # 保存临时文件
            temp_file = tempfile.mktemp(suffix=".jpg")
            with open(temp_file, "wb") as f:
                f.write(image_data)
            
            self.progress.emit(100, "图片下载完成!")
            self.completed.emit(temp_file, image_data)
        except Exception as e:
            logging.error(f"下载随机图片失败: {str(e)}")
            self.error.emit(f"下载随机图片失败: {str(e)}")

class MouseEntropyDialog(QDialog):
    """鼠标熵收集对话框"""
    entropy_collected = pyqtSignal(bytes)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        # 设置为全屏模式，不显示标题栏
        self.setWindowFlags(Qt.Window | Qt.CustomizeWindowHint | Qt.FramelessWindowHint)
        # 获取主屏幕信息并设置窗口大小
        screen = QApplication.primaryScreen()
        screen_geometry = screen.geometry()
        self.setGeometry(screen_geometry)
        self.showFullScreen()
        
        # 设置背景色为黑色
        palette = self.palette()
        palette.setColor(QPalette.Window, Qt.black)
        self.setPalette(palette)
        
        # 鼠标轨迹数据
        self.mouse_data = []
        # 鼠标按键数据
        self.mouse_button_data = []
        # 鼠标滚轮数据
        self.mouse_wheel_data = []
        
        # 历史数据用于计算额外特征
        self.previous_position = None
        self.previous_time = None
        
        # 累计距离和方向变化
        self.total_distance = 0
        self.direction_changes = 0
        
        # 使用随机数据点数量，范围在500-1000之间
        self.target_data_points = random.randint(500, 1000)
        
        # 初始化UI
        self.init_ui()
        
        # 捕获鼠标事件
        self.setMouseTracking(True)
    
    def init_ui(self):
        """初始化UI"""
        layout = QVBoxLayout(self)
        
        # 提示标签
        self.instruction_label = QLabel(f"请在窗口内快速晃动鼠标，需要收集 {self.target_data_points} 个数据点...")
        self.instruction_label.setStyleSheet("color: #4CAF50; font-size: 16pt; font-weight: bold;")
        self.instruction_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.instruction_label)
        
        # 进度条
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setStyleSheet(
            "QProgressBar {background-color: #333333; border: 1px solid #555555; border-radius: 5px; text-align: center;}"
            "QProgressBar::chunk {background-color: #4CAF50;}"
        )
        layout.addWidget(self.progress_bar)
        
        # 计数器标签
        self.count_label = QLabel(f"已收集的数据点: 0 / {self.target_data_points}")
        self.count_label.setStyleSheet("color: white;")
        self.count_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.count_label)
    
    def mouseMoveEvent(self, event):
        """捕获鼠标移动事件"""
        current_time = time.time()
        current_timestamp = time.perf_counter_ns()
        
        # 计算额外特征
        distance = 0
        acceleration = 0
        direction_change = 0
        velocity_x, velocity_y = 0, 0
        
        if self.previous_position and self.previous_time:
            # 计算距离
            dx = event.x() - self.previous_position[0]
            dy = event.y() - self.previous_position[1]
            distance = math.sqrt(dx*dx + dy*dy)
            self.total_distance += distance
            
            # 计算时间差
            time_diff = current_time - self.previous_time
            if time_diff > 0:
                # 计算速度
                velocity_x = dx / time_diff
                velocity_y = dy / time_diff
            
            # 检测方向变化
            if len(self.mouse_data) > 1:
                prev_point = self.mouse_data[-1]
                if 'dx' in prev_point and 'dy' in prev_point:
                    # 计算前一向量和当前向量的角度
                    prev_vector = (prev_point['dx'], prev_point['dy'])
                    current_vector = (dx, dy)
                    
                    # 计算向量点积和夹角
                    dot_product = prev_vector[0]*current_vector[0] + prev_vector[1]*current_vector[1]
                    prev_magnitude = math.sqrt(prev_vector[0]**2 + prev_vector[1]**2)
                    current_magnitude = distance
                    
                    if prev_magnitude > 0 and current_magnitude > 0:
                        cos_theta = dot_product / (prev_magnitude * current_magnitude)
                        # 限制在有效范围内
                        cos_theta = max(-1, min(1, cos_theta))
                        theta = math.acos(cos_theta)
                        
                        # 如果角度变化大于30度，认为是方向变化
                        if theta > math.radians(30):
                            direction_change = 1
                            self.direction_changes += 1
        
        # 收集鼠标数据（包含更多特征）
        data_point = {
            "x": event.x(),
            "y": event.y(),
            "time": current_time,
            "timestamp": current_timestamp,
            "distance": distance,
            "velocity_x": velocity_x,
            "velocity_y": velocity_y,
            "acceleration": acceleration,
            "direction_change": direction_change,
            "button_state": event.buttons()  # 捕获当前按键状态
        }
        
        # 如果有历史位置，计算相对坐标
        if self.previous_position:
            data_point['dx'] = event.x() - self.previous_position[0]
            data_point['dy'] = event.y() - self.previous_position[1]
        
        self.mouse_data.append(data_point)
        
        # 更新历史数据
        self.previous_position = (event.x(), event.y())
        self.previous_time = current_time
        
        # 更新进度
        self.update_progress()
    
    def mousePressEvent(self, event):
        """捕获鼠标按键按下事件"""
        button_data = {
            "button": event.button(),
            "x": event.x(),
            "y": event.y(),
            "time": time.time(),
            "timestamp": time.perf_counter_ns()
        }
        self.mouse_button_data.append(button_data)
        
    def mouseReleaseEvent(self, event):
        """捕获鼠标按键释放事件"""
        button_data = {
            "button": event.button(),
            "type": "release",
            "x": event.x(),
            "y": event.y(),
            "time": time.time(),
            "timestamp": time.perf_counter_ns()
        }
        self.mouse_button_data.append(button_data)
    
    def wheelEvent(self, event):
        """捕获鼠标滚轮事件"""
        wheel_data = {
            "delta": event.angleDelta().y(),
            "x": event.x(),
            "y": event.y(),
            "time": time.time(),
            "timestamp": time.perf_counter_ns()
        }
        self.mouse_wheel_data.append(wheel_data)
    
    def update_progress(self):
        """更新收集进度"""
        # 使用鼠标移动数据点数量作为进度指标
        count = len(self.mouse_data)
        self.count_label.setText(f"已收集的数据点: {count} / {self.target_data_points}")
        
        # 计算进度
        progress = min(100, int((count / self.target_data_points) * 100))
        self.progress_bar.setValue(progress)
        
        # 检查是否达到目标数据点数量
        if count >= self.target_data_points:
            self.process_mouse_data()
    

    
    def process_mouse_data(self):
        """处理收集到的鼠标数据"""
        if not self.mouse_data:
            # 如果没有收集到数据，使用随机数据
            mouse_entropy = os.urandom(64)
        else:
            # 处理鼠标移动数据，收集更多特征
            processed_data = []
            
            # 1. 处理鼠标移动数据
            for point in self.mouse_data:
                # 基本特征
                processed_data.append(point["x"])
                processed_data.append(point["y"])
                processed_data.append(int(point["timestamp"] % 1000000))  # 使用时间戳的一部分
                
                # 高级特征
                processed_data.append(int(point["distance"] * 100))  # 距离特征
                processed_data.append(int(point["velocity_x"]))  # X轴速度
                processed_data.append(int(point["velocity_y"]))  # Y轴速度
                processed_data.append(point["direction_change"])  # 方向变化标志
                processed_data.append(int(point["button_state"]))  # 按键状态
                
                # 相对坐标特征（如果存在）
                if 'dx' in point and 'dy' in point:
                    processed_data.append(point['dx'])
                    processed_data.append(point['dy'])
            
            # 2. 处理鼠标按键数据
            for button_event in self.mouse_button_data:
                processed_data.append(button_event["button"])
                processed_data.append(button_event["x"])
                processed_data.append(button_event["y"])
                processed_data.append(int(button_event["timestamp"] % 100000))
                if "type" in button_event and button_event["type"] == "release":
                    processed_data.append(1)  # 释放标志
                else:
                    processed_data.append(0)  # 按下标志
            
            # 3. 处理鼠标滚轮数据
            for wheel_event in self.mouse_wheel_data:
                processed_data.append(wheel_event["delta"])
                processed_data.append(wheel_event["x"])
                processed_data.append(wheel_event["y"])
                processed_data.append(int(wheel_event["timestamp"] % 100000))
            
            # 4. 添加统计特征
            processed_data.append(int(self.total_distance))  # 总移动距离
            processed_data.append(self.direction_changes)  # 方向变化次数
            processed_data.append(len(self.mouse_data))  # 移动事件总数
            processed_data.append(len(self.mouse_button_data))  # 按键事件总数
            processed_data.append(len(self.mouse_wheel_data))  # 滚轮事件总数
            
            # 5. 确保数据量不会太大（限制在10000个整数以内）
            if len(processed_data) > 10000:
                # 采样数据以减少数据量
                step = len(processed_data) // 10000
                processed_data = processed_data[::step]
            
            # 转换为字节并哈希
            data_bytes = struct.pack(f">{len(processed_data)}i", *processed_data)
            mouse_entropy = hashlib.sha512(data_bytes).digest()
        
        # 发送熵数据并关闭窗口
        self.entropy_collected.emit(mouse_entropy)
        self.accept()


class EnhancedKeyGeneratorThread(QThread):
    """增强的密钥生成线程"""
    progress = pyqtSignal(int, str)
    completed = pyqtSignal(KeyInfo)
    error = pyqtSignal(str)
    
    def __init__(self, use_mouse_entropy: bool = False, parent=None):
        super().__init__(parent)
        self.use_mouse_entropy = use_mouse_entropy
        self.mouse_entropy = None
    
    def set_mouse_entropy(self, entropy: bytes):
        """设置鼠标熵数据"""
        self.mouse_entropy = entropy
    
    def run(self):
        """执行密钥生成过程"""
        try:
            # 1. 收集熵源
            self.progress.emit(10, "收集系统熵源...")
            entropy = self.generate_entropy()
            
            # 2. 创建密钥记录器
            logger = SecureKeyLogger()
            logger.add("原始熵源", entropy)
            
            # 3. 密钥派生链
            self.progress.emit(30, "执行一级密钥派生 (SHA512)...")
            k1, salt1 = self.derive_key(entropy, None, logger=logger, dklen=64)
            
            self.progress.emit(45, "执行二级密钥派生 (SHA3-512)...")
            k2, salt2 = self.derive_key(k1, salt1, logger=logger, algo='sha3_512', dklen=64)
            
            self.progress.emit(60, "执行三级密钥派生 (BLAKE2s)...")
            k3, salt3 = self.derive_key(k2, salt2, logger=logger, algo='blake2s', dklen=64)
            
            # 4. 生成RSA密钥对
            self.progress.emit(75, "生成RSA-4096密钥对...")
            rsa_seed = k3[:32]  # 使用前256位作为种子
            public_key, private_key = self.generate_rsa_keypair(rsa_seed, key_size=4096)
            logger.add("RSA_4096密钥对", (public_key, private_key))
            
            # 5. 创建密钥ID
            hex_key = binascii.hexlify(k3).decode()
            key_id = f"KEY-{time.strftime('%Y%m%d-%H%M%S')}-{hex_key[:8].upper()}"
            
            # 6. 格式化密钥
            self.progress.emit(90, "格式化密钥...")
            formatted_key = self.format_key(hex_key)
            
            # 7. 创建密钥信息对象
            key_info = KeyInfo(
                key_id=key_id,
                formatted_key=formatted_key,
                hex_key=hex_key,
                public_key=public_key,
                private_key=private_key,
                creation_time=time.strftime('%Y-%m-%d %H:%M:%S'),
                entropy_sources=logger.log
            )
            
            # 如果使用了鼠标熵，添加到熵源字典
            if self.use_mouse_entropy and self.mouse_entropy:
                key_info.entropy_sources["增强鼠标数据"] = "已使用（包含坐标、速度、距离、方向变化、按键和滚轮事件）"
            
            # 8. 完成并发送结果
            self.progress.emit(100, "密钥生成完成!")
            self.completed.emit(key_info)
            
        except Exception as e:
            logging.exception("密钥生成失败!")
            self.error.emit(str(e))
    
    def collect_network_data(self, duration: int = 10) -> Tuple[list, threading.Thread]:
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
    
    def generate_entropy(self) -> bytes:
        """生成熵源数据"""
        # 1. 启动网络数据收集线程
        net_result, net_thread = self.collect_network_data()
        
        # 2. 主线程生成其他熵源
        timestamp = struct.pack('d', time.time())
        uuids = [uuid.UUID(bytes=os.urandom(16), version=4) for _ in range(10)]
        uuids_bytes = b''.join(u.bytes for u in uuids)
        randoms = [os.urandom(8) for _ in range(10)]
        
        # 3. 等待网络线程完成
        net_thread.join()
        net_data = net_result[0]
        
        # 4. 组合所有熵源
        base_entropy = timestamp + uuids_bytes + net_data + b''.join(randoms)
        
        # 5. 如果使用鼠标熵，将其作为盐值
        if self.use_mouse_entropy and self.mouse_entropy:
            # 使用鼠标熵作为盐进行哈希处理
            combined_entropy = hashlib.pbkdf2_hmac(
                'sha512',
                base_entropy,
                self.mouse_entropy,
                100000,
                dklen=64
            )
            return combined_entropy
        
        return base_entropy
    
    def derive_key(self, seed: bytes, prev_salt: Optional[bytes], iterations: int = 200000, 
                   dklen: int = 64, algo: str = 'sha512', logger: Optional[KeyLogger] = None) -> Tuple[bytes, bytes]:
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
    
    def generate_rsa_keypair(self, seed: bytes, key_size: int = 4096) -> Tuple[str, str]:
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
        
        rsa_gen = RSA.generate(key_size, randfunc=SeedRandom(seed))
        private_key = rsa_gen.export_key().decode()
        public_key = rsa_gen.publickey().export_key().decode()
        
        return public_key, private_key
    
    def format_key(self, hex_key: str) -> str:
        """格式化密钥"""
        # 使用更复杂的分组和分隔符策略
        group_sizes = [4, 5, 6, 7, 8, 9, 10]
        group_size = secrets.choice(group_sizes)
        groups = [hex_key[i:i+group_size] for i in range(0, len(hex_key), group_size)]
        
        # 为每个分组选择不同的分隔符
        separators = [secrets.choice(SYMBOLS) for _ in groups[1:]]
        
        formatted = groups[0]
        for i, sep in enumerate(separators, 1):
            formatted += sep + groups[i]
        return formatted
    
    def generate_key_sync(self) -> Optional[KeyInfo]:
        """同步生成密钥"""
        try:
            # 1. 收集熵源
            entropy = self.generate_entropy()
            
            # 2. 创建密钥记录器
            logger = SecureKeyLogger()
            logger.add("原始熵源", entropy)
            
            # 3. 密钥派生链
            k1, salt1 = self.derive_key(entropy, None, logger=logger, dklen=64)
            k2, salt2 = self.derive_key(k1, salt1, logger=logger, algo='sha3_512', dklen=64)
            k3, salt3 = self.derive_key(k2, salt2, logger=logger, algo='blake2s', dklen=64)
            
            # 4. 生成RSA密钥对
            rsa_seed = k3[:32]  # 使用前256位作为种子
            public_key, private_key = self.generate_rsa_keypair(rsa_seed, key_size=4096)
            logger.add("RSA_4096密钥对", (public_key, private_key))
            
            # 5. 创建密钥ID
            hex_key = binascii.hexlify(k3).decode()
            key_id = f"KEY-{time.strftime('%Y%m%d-%H%M%S')}-{hex_key[:8].upper()}"
            
            # 6. 格式化密钥
            formatted_key = self.format_key(hex_key)
            
            # 7. 创建密钥信息对象
            key_info = KeyInfo(
                key_id=key_id,
                formatted_key=formatted_key,
                hex_key=hex_key,
                public_key=public_key,
                private_key=private_key,
                creation_time=time.strftime('%Y-%m-%d %H:%M:%S'),
                entropy_sources=logger.log
            )
            
            return key_info
            
        except Exception as e:
            logging.exception("同步密钥生成失败!")
            return None


class AdvancedKeyToolsGUI(QMainWindow):
    """高级密钥工具GUI v3.6"""
    def __init__(self):
        super().__init__()
        self.setWindowTitle("高级密钥工具 v3.6")
        self.setGeometry(100, 100, 1200, 800)
        
        # 应用设置
        self.settings = QSettings("AdvancedKeyTools", "GUI_v3.6")
        
        # 当前密钥信息
        self.current_key_info: Optional[KeyInfo] = None
        self.current_image_path = ""
        
        # 初始化UI
        self.init_ui()
        
        # 应用样式
        self.apply_styles()
        
        # 状态栏
        self.statusBar().showMessage("准备就绪")
    
    def init_ui(self):
        """初始化用户界面"""
        # 创建菜单栏
        self.create_menu_bar()
        
        # 创建工具栏
        self.create_toolbar()
        
        # 创建主窗口部件
        self.main_widget = QWidget()
        self.setCentralWidget(self.main_widget)
        
        # 主布局
        self.main_layout = QVBoxLayout(self.main_widget)
        
        # 创建选项卡
        self.tabs = QTabWidget()
        self.main_layout.addWidget(self.tabs)
        
        # 创建各个功能标签页
        self.setup_keygen_tab()
        self.setup_rsa_crypto_tab()
        self.setup_image_steganography_tab()
        self.setup_file_crypto_tab()
        
        # 添加标签页
        self.tabs.addTab(self.keygen_tab, "密钥生成")
        self.tabs.addTab(self.rsa_crypto_tab, "RSA加解密")
        self.tabs.addTab(self.image_stego_tab, "图种制作器")
        self.tabs.addTab(self.file_crypto_tab, "文件加解密")
        
        # 启用拖放功能
        self.setAcceptDrops(True)
    
    def closeEvent(self, event):
        """窗口关闭事件 - 在退出时提示保存密钥"""
        # 检查是否有未保存的密钥
        if hasattr(self, 'current_key_info') and self.current_key_info:
            reply = QMessageBox.question(
                self, '提示', 
                '检测到有生成的密钥，是否保存后再退出？',
                QMessageBox.Yes | QMessageBox.No | QMessageBox.Cancel,
                QMessageBox.Yes
            )
            
            if reply == QMessageBox.Cancel:
                event.ignore()
                return
            elif reply == QMessageBox.Yes:
                # 打开保存对话框选择路径
                save_path = QFileDialog.getExistingDirectory(self, "选择保存路径", os.path.expanduser("~"))
                if not save_path:
                    # 如果用户取消选择路径，再次询问是否直接退出
                    again_reply = QMessageBox.question(
                        self, '提示',
                        '未选择保存路径，确定要直接退出吗？',
                        QMessageBox.Yes | QMessageBox.No,
                        QMessageBox.No
                    )
                    if again_reply == QMessageBox.No:
                        event.ignore()
                        return
                else:
                    # 保存密钥到指定路径
                    try:
                        # 临时修改设置中的保存路径
                        old_save_path = self.settings.value("default_save_path", os.path.expanduser("~"))
                        self.settings.setValue("default_save_path", save_path)
                        zip_path = self.save_key_files(self.current_key_info)
                        # 恢复原保存路径
                        self.settings.setValue("default_save_path", old_save_path)
                    except Exception as e:
                        QMessageBox.critical(self, "保存失败", f"保存密钥时出错: {str(e)}")
                        # 询问是否仍要退出
                        exit_reply = QMessageBox.question(
                            self, '提示',
                            '保存失败，是否仍要退出？',
                            QMessageBox.Yes | QMessageBox.No,
                            QMessageBox.Yes
                        )
                        if exit_reply == QMessageBox.No:
                            event.ignore()
                            return
        
        # 执行清理工作
        event.accept()
    
    def create_menu_bar(self):
        """创建菜单栏"""
        menubar = self.menuBar()
        
        # 文件菜单
        file_menu = menubar.addMenu("文件")
        
        # 保存密钥
        save_action = QAction("保存密钥", self)
        save_action.triggered.connect(self.save_current_keys)
        file_menu.addAction(save_action)
        
        # 导入密钥
        import_action = QAction("导入密钥", self)
        import_action.triggered.connect(self.load_keys)
        file_menu.addAction(import_action)
        
        file_menu.addSeparator()
        
        # 退出
        exit_action = QAction("退出", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # 工具菜单
        tools_menu = menubar.addMenu("工具")
        
        # 生成密钥
        generate_action = QAction("生成密钥", self)
        generate_action.triggered.connect(self.generate_keys)
        tools_menu.addAction(generate_action)
        
        # 图种工具
        stego_action = QAction("图种工具", self)
        stego_action.triggered.connect(lambda: self.tabs.setCurrentIndex(2))
        tools_menu.addAction(stego_action)
        
        # 帮助菜单
        help_menu = menubar.addMenu("帮助")
        
        # 关于
        about_action = QAction("关于", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)
    
    def dragEnterEvent(self, event):
        """拖放进入事件"""
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
    
    def dropEvent(self, event):
        """拖放释放事件"""
        for url in event.mimeData().urls():
            file_path = url.toLocalFile()
            if file_path.lower().endswith('.zip'):
                self.load_key_package(file_path)
                return
    
    def create_toolbar(self):
        """创建工具栏"""
        toolbar = self.addToolBar("主工具栏")
        toolbar.setMovable(False)
        toolbar.setFloatable(False)
        
        # 读取密钥包按钮
        load_btn = QToolButton()
        load_btn.setText("读取密钥包")
        load_btn.setIcon(self.style().standardIcon(QStyle.SP_DialogOpenButton))
        load_btn.clicked.connect(self.load_keys)
        load_btn.setToolTip("从ZIP文件中加载密钥包")
        toolbar.addWidget(load_btn)
        
        # 使用当前密钥按钮
        use_key_btn = QToolButton()
        use_key_btn.setText("使用当前密钥")
        use_key_btn.setIcon(self.style().standardIcon(QStyle.SP_DialogApplyButton))
        use_key_btn.clicked.connect(self.use_current_keys)
        use_key_btn.setToolTip("将当前生成的密钥应用到其他功能模块")
        toolbar.addWidget(use_key_btn)
        
        toolbar.addSeparator()
        
        # 保存密钥按钮
        save_btn = QToolButton()
        save_btn.setText("保存密钥")
        save_btn.setIcon(self.style().standardIcon(QStyle.SP_DialogSaveButton))
        save_btn.clicked.connect(self.save_current_keys)
        save_btn.setToolTip("将当前密钥保存为ZIP文件")
        toolbar.addWidget(save_btn)
    
    def apply_styles(self):
        """应用样式"""
        # 设置全局样式表
        self.setStyleSheet(""
            "QMainWindow {background-color: #f5f5f5;}"
            "QWidget {background-color: #ffffff;}"
            "QGroupBox {border: 1px solid #cccccc; border-radius: 5px; margin-top: 10px;}"
            "QGroupBox::title {subcontrol-origin: margin; subcontrol-position: top left; left: 10px; padding: 0 3px 0 3px;}"
            "QPushButton {border: 1px solid #cccccc; border-radius: 3px; padding: 5px 10px; background-color: #e1e1e1;}"
            "QPushButton:hover {background-color: #d0d0d0;}"
            "QPushButton:pressed {background-color: #c0c0c0;}"
            "QProgressBar {text-align: center; border: 1px solid #cccccc; border-radius: 3px;}"
            "QProgressBar::chunk {background-color: #4CAF50;}"
            "QLabel {font-size: 10pt;}"
            "QTabWidget::pane {border: 1px solid #cccccc; border-radius: 3px;}"
            "QTabBar::tab {background: #e1e1e1; border: 1px solid #cccccc; border-bottom-color: #cccccc; border-top-left-radius: 3px; border-top-right-radius: 3px; padding: 5px;}"
            "QTabBar::tab:selected {background: #ffffff; border-bottom-color: #ffffff;}"
        )
    
    def setup_keygen_tab(self):
        """设置密钥生成标签页"""
        self.keygen_tab = QWidget()
        layout = QVBoxLayout(self.keygen_tab)
        
        # 创建按钮容器
        button_layout = QHBoxLayout()
        
        # 生成密钥按钮
        self.btn_generate = QPushButton("生成高级密钥")
        self.btn_generate.setStyleSheet("background-color: #4CAF50; color: white; font-weight: bold;")
        self.btn_generate.clicked.connect(self.generate_keys)
        button_layout.addWidget(self.btn_generate)
        

        
        # 进度条
        self.progress = QProgressBar()
        self.progress.setValue(0)
        
        # 状态标签
        self.status_label = QLabel("准备就绪")
        self.status_label.setAlignment(Qt.AlignCenter)
        
        # 鼠标晃动选项
        self.checkbox_mouse_entropy = QCheckBox("使用鼠标晃动增强随机性")
        self.checkbox_mouse_entropy.setToolTip("通过晃动鼠标收集额外的随机数据来增强密钥安全性")
        self.checkbox_mouse_entropy.setChecked(False)  # 默认不使用鼠标熵
        
        # 密钥显示区域
        self.key_result = QTextEdit()
        self.key_result.setReadOnly(True)
        self.key_result.setMinimumHeight(300)
        self.key_result.setFont(QFont("Consolas", 10))
        
        # 添加到主布局
        layout.addLayout(button_layout)
        layout.addWidget(self.progress)
        layout.addWidget(self.status_label)
        layout.addWidget(self.checkbox_mouse_entropy)
        layout.addWidget(self.key_result)
        layout.addStretch()
    
    def setup_rsa_crypto_tab(self):
        """设置RSA加解密标签页"""
        self.rsa_crypto_tab = QWidget()
        layout = QVBoxLayout(self.rsa_crypto_tab)
        
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
    
    def setup_image_steganography_tab(self):
        """设置图种制作标签页"""
        self.image_stego_tab = QWidget()
        layout = QVBoxLayout(self.image_stego_tab)
        
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
        
        # 添加获取随机图片按钮（修复版本）
        self.btn_get_random_image = QPushButton("获取随机图片")
        self.btn_get_random_image.clicked.connect(self.get_random_image)
        h_layout.addWidget(self.btn_get_random_image)
        
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
        self.save_location = QLineEdit()
        self.save_location.setReadOnly(True)
        group_embed_layout.addWidget(self.save_location)
        
        self.btn_browse_save = QPushButton("选择保存位置")
        self.btn_browse_save.clicked.connect(self.browse_save_location)
        group_embed_layout.addWidget(self.btn_browse_save)
        
        layout.addWidget(group_embed)
        
        # 图种提取
        group_extract = QGroupBox("提取图种")
        group_extract_layout = QVBoxLayout(group_extract)
        
        self.stego_file_path = QLineEdit()
        self.stego_file_path.setReadOnly(True)
        group_extract_layout.addWidget(self.stego_file_path)
        
        h_layout = QHBoxLayout()
        self.btn_browse_stego = QPushButton("浏览图种")
        self.btn_browse_stego.clicked.connect(self.browse_stego_file)
        h_layout.addWidget(self.btn_browse_stego)
        
        self.btn_extract_stego = QPushButton("提取文件")
        self.btn_extract_stego.setStyleSheet("background-color: #3F51B5; color: white;")
        self.btn_extract_stego.clicked.connect(self.extract_from_stego)
        h_layout.addWidget(self.btn_extract_stego)
        
        group_extract_layout.addLayout(h_layout)
        
        # 测试图种按钮
        self.btn_test_stego = QPushButton("测试图种")
        self.btn_test_stego.clicked.connect(self.test_stego_image)
        group_extract_layout.addWidget(self.btn_test_stego)
        
        # 状态标签
        self.stego_status = QLabel("请先选择图片和要隐藏的文件")
        group_extract_layout.addWidget(self.stego_status)
        
        layout.addWidget(group_extract)
    
    def setup_file_crypto_tab(self):
        """设置文件加解密标签页"""
        self.file_crypto_tab = QWidget()
        layout = QVBoxLayout(self.file_crypto_tab)
        
        # 密钥区域 - 修改为与RSA加解密保持一致
        
        # 公钥区域
        group_pub = QGroupBox("公钥")
        group_pub_layout = QVBoxLayout(group_pub)
        self.file_pub_key_text = QTextEdit()
        self.file_pub_key_text.setPlaceholderText("在此粘贴或导入公钥")
        self.file_pub_key_text.setFixedHeight(120)
        self.file_pub_key_text.setFont(QFont("Consolas", 9))
        group_pub_layout.addWidget(self.file_pub_key_text)
        
        # 使用当前公钥按钮
        self.btn_file_use_current_pub = QPushButton("使用当前生成密钥的公钥")
        self.btn_file_use_current_pub.clicked.connect(self.use_current_pub_key_for_file)
        group_pub_layout.addWidget(self.btn_file_use_current_pub)
        
        # 从文件加载公钥按钮
        self.btn_file_load_pub = QPushButton("从文件加载公钥")
        self.btn_file_load_pub.clicked.connect(self.load_pub_key_from_file)
        group_pub_layout.addWidget(self.btn_file_load_pub)
        
        # 私钥区域
        group_priv = QGroupBox("私钥")
        group_priv_layout = QVBoxLayout(group_priv)
        self.file_priv_key_text = QTextEdit()
        self.file_priv_key_text.setPlaceholderText("在此粘贴或导入私钥")
        self.file_priv_key_text.setFixedHeight(120)
        self.file_priv_key_text.setFont(QFont("Consolas", 9))
        group_priv_layout.addWidget(self.file_priv_key_text)
        
        # 使用当前私钥按钮
        self.btn_file_use_current_priv = QPushButton("使用当前生成密钥的私钥")
        self.btn_file_use_current_priv.clicked.connect(self.use_current_priv_key_for_file)
        group_priv_layout.addWidget(self.btn_file_use_current_priv)
        
        # 从文件加载私钥按钮
        self.btn_file_load_priv = QPushButton("从文件加载私钥")
        self.btn_file_load_priv.clicked.connect(self.load_priv_key_from_file)
        group_priv_layout.addWidget(self.btn_file_load_priv)
        
        # 添加到主布局
        layout.addWidget(group_pub)
        layout.addWidget(group_priv)
        
        # 文件操作区域
        group_files = QGroupBox("文件操作")
        group_files_layout = QVBoxLayout(group_files)
        
        # 加密文件部分
        encrypt_layout = QVBoxLayout()
        encrypt_layout.addWidget(QLabel("加密文件:"))
        
        h_layout = QHBoxLayout()
        self.encrypt_file_edit = QLineEdit()
        self.encrypt_file_edit.setReadOnly(True)
        h_layout.addWidget(self.encrypt_file_edit, 1)
        self.btn_browse_encrypt = QPushButton("浏览")
        self.btn_browse_encrypt.clicked.connect(self.browse_encrypt_file)
        h_layout.addWidget(self.btn_browse_encrypt)
        encrypt_layout.addLayout(h_layout)
        
        self.btn_encrypt_file = QPushButton("加密文件")
        self.btn_encrypt_file.setStyleSheet("background-color: #2196F3; color: white;")
        self.btn_encrypt_file.clicked.connect(self.encrypt_file)
        encrypt_layout.addWidget(self.btn_encrypt_file)
        
        # 解密文件部分
        decrypt_layout = QVBoxLayout()
        decrypt_layout.addWidget(QLabel("解密文件:"))
        
        h_layout = QHBoxLayout()
        self.decrypt_file_edit = QLineEdit()
        self.decrypt_file_edit.setReadOnly(True)
        h_layout.addWidget(self.decrypt_file_edit, 1)
        self.btn_browse_decrypt = QPushButton("浏览")
        self.btn_browse_decrypt.clicked.connect(self.browse_decrypt_file)
        h_layout.addWidget(self.btn_browse_decrypt)
        decrypt_layout.addLayout(h_layout)
        
        self.btn_decrypt_file = QPushButton("解密文件")
        self.btn_decrypt_file.setStyleSheet("background-color: #FF9800; color: white;")
        self.btn_decrypt_file.clicked.connect(self.decrypt_file)
        decrypt_layout.addWidget(self.btn_decrypt_file)
        
        # 添加到主布局
        main_ops_layout = QHBoxLayout()
        main_ops_layout.addLayout(encrypt_layout, 1)
        main_ops_layout.addLayout(decrypt_layout, 1)
        group_files_layout.addLayout(main_ops_layout)
        
        layout.addWidget(group_files)
        
        # 状态信息
        group_status = QGroupBox("操作状态")
        group_status_layout = QVBoxLayout(group_status)
        self.operation_status = QTextEdit()
        self.operation_status.setReadOnly(True)
        self.operation_status.setFixedHeight(100)
        group_status_layout.addWidget(self.operation_status)
        layout.addWidget(group_status)
    
    def load_key_package(self, file_path):
        """加载密钥包"""
        try:
            # 解压zip文件
            with zipfile.ZipFile(file_path, 'r') as zip_ref:
                # 检查是否有密码保护
                try:
                    # 尝试不使用密码解压
                    zip_ref.extractall(tempfile.gettempdir())
                    password_protected = False
                except RuntimeError:
                    # 需要密码
                    password, ok = QInputDialog.getText(self, "需要密码", "请输入密钥包密码:", QLineEdit.Password)
                    if not ok:
                        return
                    try:
                        zip_ref.setpassword(password.encode())
                        zip_ref.extractall(tempfile.gettempdir())
                        password_protected = True
                    except Exception as e:
                        QMessageBox.critical(self, "解压失败", f"密码错误或文件损坏: {str(e)}")
                        return
                
                # 查找密钥文件
                key_files = []
                for file_info in zip_ref.infolist():
                    if not file_info.is_dir():
                        key_files.append(os.path.join(tempfile.gettempdir(), file_info.filename))
                
                # 读取密钥信息
                if len(key_files) >= 3:
                    # 假设文件命名规则: key.json, public.pem, private.pem
                    for key_file in key_files:
                        file_name = os.path.basename(key_file)
                        if file_name == 'key.json':
                            with open(key_file, 'r', encoding='utf-8') as f:
                                key_data = json.load(f)
                                self.current_key_info = KeyInfo(
                                    key_id=key_data.get('key_id', ''),
                                    generated_at=key_data.get('generated_at', ''),
                                    formatted_key=key_data.get('formatted_key', ''),
                                    full_hex=key_data.get('full_hex', ''),
                                    public_key=key_data.get('public_key', ''),
                                    private_key=key_data.get('private_key', ''),
                                    entropy_sources=key_data.get('entropy_sources', {})
                                )
                        elif file_name.endswith('.pem'):
                            with open(key_file, 'r', encoding='utf-8') as f:
                                content = f.read()
                                if 'BEGIN PUBLIC KEY' in content and hasattr(self, 'pub_key_text'):
                                    self.pub_key_text.setText(content)
                                    if hasattr(self, 'file_pub_key_text'):
                                        self.file_pub_key_text.setText(content)
                                    if self.current_key_info:
                                        self.current_key_info.public_key = content
                                elif 'BEGIN PRIVATE KEY' in content and hasattr(self, 'priv_key_text'):
                                    self.priv_key_text.setText(content)
                                    if hasattr(self, 'file_priv_key_text'):
                                        self.file_priv_key_text.setText(content)
                                    if self.current_key_info:
                                        self.current_key_info.private_key = content
                    
                    self.statusBar().showMessage(f"成功加载密钥包: {os.path.basename(file_path)}")
                    QMessageBox.information(self, "加载成功", f"密钥包已成功加载！")
                    
                    # 更新显示
                    if hasattr(self, 'key_result') and self.current_key_info:
                        # 使用格式化字符串显示完整密钥信息
                        key_display = (
                            f"密钥ID: {self.current_key_info.key_id}\n"
                            f"生成时间: {self.current_key_info.generated_at}\n\n"
                            f"格式化密钥:\n{self.current_key_info.formatted_key}\n\n"
                            f"完整十六进制:\n{self.current_key_info.full_hex}\n\n"
                            f"RSA公钥:\n{self.current_key_info.public_key}\n\n"
                            f"RSA私钥:\n{self.current_key_info.private_key}"
                        )
                        self.key_result.setText(key_display)
            
        except Exception as e:
            QMessageBox.critical(self, "加载失败", f"密钥包加载失败: {str(e)}")
            self.statusBar().showMessage(f"密钥包加载失败: {str(e)}")
    
    def generate_keys(self):
        """生成密钥"""
        try:
            # 检查是否选择使用鼠标熵
            use_mouse_entropy = self.checkbox_mouse_entropy.isChecked()
            mouse_entropy = None
            
            # 如果选择了鼠标熵，打开对话框收集数据
            if use_mouse_entropy:
                self.status_label.setText("正在收集鼠标随机数据...")
                dialog = MouseEntropyDialog(self)
                
                # 显示进度条
                self.progress.setValue(0)
                
                # 连接信号
                dialog_entropy = [None]
                dialog.entropy_collected.connect(lambda data: dialog_entropy.__setitem__(0, data))
                
                # 等待对话框完成
                if dialog.exec_() == QDialog.Accepted:
                    mouse_entropy = dialog_entropy[0]
                else:
                    self.status_label.setText("已取消鼠标数据收集")
                    return
            
            # 禁用生成按钮
            self.btn_generate.setEnabled(False)
            self.status_label.setText("开始生成密钥...")
            
            # 创建并启动密钥生成线程
            self.key_generator = EnhancedKeyGeneratorThread(use_mouse_entropy=use_mouse_entropy)
            
            # 设置鼠标熵（如果有）
            if mouse_entropy:
                self.key_generator.set_mouse_entropy(mouse_entropy)
            
            # 连接信号
            self.key_generator.progress.connect(self.update_progress)
            self.key_generator.completed.connect(self.key_generated)
            self.key_generator.error.connect(self.key_error)
            
            # 启动线程
            self.key_generator.start()
            
        except Exception as e:
            QMessageBox.critical(self, "错误", f"生成密钥时发生错误: {str(e)}")
            self.btn_generate.setEnabled(True)
    
    def update_progress(self, value, status):
        """更新进度条"""
        self.progress.setValue(value)
        self.status_label.setText(status)
    
    def key_generated(self, key_info):
        """密钥生成完成"""
        self.current_key_info = key_info
        
        # 显示完整的密钥信息
        result = f"""===== 高级密钥生成结果 =====

密钥ID: {key_info.key_id}
生成时间: {key_info.creation_time}

===== 格式化密钥 =====
{key_info.formatted_key}

===== 完整十六进制 =====
{key_info.hex_key}

===== 公钥 =====
{key_info.public_key}

===== 私钥 =====
{key_info.private_key}
"""
        
        self.key_result.setText(result)
        
        # 如果设置了自动保存，保存密钥
        if self.settings.value("auto_save", False, bool):
            self.save_key_files(key_info)
        
        # 重新启用按钮
        self.btn_generate.setEnabled(True)
        self.status_label.setText("密钥生成完成!")
        
        QMessageBox.information(self, "成功", "密钥已成功生成")
    
    def key_error(self, error_message):
        """密钥生成错误"""
        QMessageBox.critical(self, "错误", f"生成密钥时发生错误: {error_message}")
        self.btn_generate.setEnabled(True)
        self.status_label.setText("生成密钥失败")
    
    def save_key_files(self, key_info, save_dir=None):
        """保存密钥文件"""
        try:
            # 获取保存路径
            if save_dir is None:
                save_dir = self.settings.value("default_save_path", os.path.expanduser("~"))
            
            # 创建临时目录
            temp_dir = tempfile.mkdtemp(prefix="key_")
            
            # 保存密钥信息文本文件
            txt_path = os.path.join(temp_dir, "key.txt")
            with open(txt_path, "w", encoding="utf-8") as f:
                f.write(f"密钥ID: {key_info.key_id}\n")
                f.write(f"创建时间: {key_info.creation_time}\n\n")
                f.write(f"===== 格式化密钥 =====\n")
                f.write(key_info.formatted_key)
                f.write("\n\n===== 完整十六进制 =====\n")
                f.write(key_info.hex_key)
            
            # 保存公钥（移除PEM格式的头尾）
            pem_path = os.path.join(temp_dir, "key.pem")
            # 移除PEM格式的头尾
            clean_public_key = key_info.public_key.replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "").strip()
            with open(pem_path, "w", encoding="utf-8") as f:
                f.write(clean_public_key)
            
            # 保存私钥（移除PEM格式的头尾）
            key_path = os.path.join(temp_dir, "key.key")
            # 移除PEM格式的头尾
            clean_private_key = key_info.private_key.replace("-----BEGIN PRIVATE KEY-----", "").replace("-----END PRIVATE KEY-----", "").strip()
            # 处理RSA私钥格式
            clean_private_key = clean_private_key.replace("-----BEGIN RSA PRIVATE KEY-----", "").replace("-----END RSA PRIVATE KEY-----", "").strip()
            with open(key_path, "w", encoding="utf-8") as f:
                f.write(clean_private_key)
            
            # 创建ZIP文件路径
            default_zip_name = f"密钥包_{time.strftime('%Y%m%d_%H%M%S')}.zip"
            zip_path = os.path.join(save_dir, default_zip_name)
            
            # 创建ZIP文件
            with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for file in [txt_path, pem_path, key_path]:
                    zipf.write(file, os.path.basename(file))
                
                # 设置ZIP密码为密钥ID
                zipf.setpassword(key_info.key_id.encode('utf-8'))
            
            # 清理临时文件
            shutil.rmtree(temp_dir)
            
            return zip_path
            
        except Exception as e:
            QMessageBox.critical(self, "错误", f"保存密钥文件失败: {str(e)}")
            raise
    
    def save_current_keys(self):
        """保存当前密钥"""
        if not self.current_key_info:
            QMessageBox.warning(self, "警告", "没有可保存的密钥")
            return
        
        try:
            # 选择保存位置
            zip_path, _ = QFileDialog.getSaveFileName(
                self, "保存密钥包", 
                os.path.join(os.path.expanduser("~"), f"密钥包_{time.strftime('%Y%m%d_%H%M%S')}.zip"), 
                "ZIP文件 (*.zip)"
            )
            
            if not zip_path:
                return
            
            # 获取保存目录
            save_dir = os.path.dirname(zip_path)
            
            # 保存密钥文件
            result_path = self.save_key_files(self.current_key_info, save_dir)
            
            # 如果save_key_files返回的路径与用户选择的不同，重命名文件
            if result_path != zip_path:
                os.rename(result_path, zip_path)
                result_path = zip_path
            
            QMessageBox.information(self, "成功", f"密钥已保存到: {result_path}\n解压密码: {self.current_key_info.key_id}")
        except Exception as e:
            QMessageBox.critical(self, "错误", f"保存密钥失败: {str(e)}")
    
    def load_keys(self):
        """加载密钥"""
        try:
            # 选择ZIP文件
            zip_path, _ = QFileDialog.getOpenFileName(self, "选择密钥包", "", "ZIP文件 (*.zip)")
            if not zip_path:
                return
            
            # 输入密码
            key_id, ok = QInputDialog.getText(self, "输入密码", "请输入密钥包密码:", QLineEdit.Password)
            if not ok:
                return
            
            # 创建临时目录
            temp_dir = tempfile.mkdtemp(prefix="key_")
            
            # 解压ZIP文件
            with zipfile.ZipFile(zip_path, 'r') as zipf:
                zipf.extractall(temp_dir, pwd=key_id.encode('utf-8'))
            
            # 读取密钥文件
            key_txt_path = os.path.join(temp_dir, "key.txt")
            key_pem_path = os.path.join(temp_dir, "key.pem")
            key_key_path = os.path.join(temp_dir, "key.key")
            
            if not all(os.path.exists(f) for f in [key_txt_path, key_pem_path, key_key_path]):
                raise ValueError("密钥包文件不完整")
            
            # 读取密钥信息
            with open(key_txt_path, "r", encoding="utf-8") as f:
                key_txt_content = f.read()
            
            with open(key_pem_path, "r", encoding="utf-8") as f:
                public_key = f.read().strip()
            
            with open(key_key_path, "r", encoding="utf-8") as f:
                private_key = f.read().strip()
            
            # 添加PEM格式头尾
            public_key = f"-----BEGIN PUBLIC KEY-----\n{public_key}\n-----END PUBLIC KEY-----"
            
            # 判断私钥类型并添加相应的头尾
            if len(private_key) > 2000:  # RSA私钥较长
                private_key = f"-----BEGIN RSA PRIVATE KEY-----\n{private_key}\n-----END RSA PRIVATE KEY-----"
            else:
                private_key = f"-----BEGIN PRIVATE KEY-----\n{private_key}\n-----END PRIVATE KEY-----"
            
            # 从文本中提取关键信息
            import re
            key_id_match = re.search(r'密钥ID: ([\w-]+)', key_txt_content)
            formatted_key_match = re.search(r'===== 格式化密钥 =====\n([\s\S]+?)\n\n=====', key_txt_content)
            hex_key_match = re.search(r'===== 完整十六进制 =====\n([\s\S]+)', key_txt_content)
            creation_time_match = re.search(r'创建时间: ([\w\s:-]+)', key_txt_content)
            
            key_id = key_id_match.group(1) if key_id_match else "未知"
            formatted_key = formatted_key_match.group(1).strip() if formatted_key_match else "未知"
            hex_key = hex_key_match.group(1).strip() if hex_key_match else "未知"
            creation_time = creation_time_match.group(1) if creation_time_match else time.strftime('%Y-%m-%d %H:%M:%S')
            
            # 创建密钥信息对象
            self.current_key_info = KeyInfo(
                key_id=key_id,
                formatted_key=formatted_key,
                hex_key=hex_key,
                public_key=public_key,
                private_key=private_key,
                creation_time=creation_time,
                entropy_sources={}
            )
            
            # 显示完整的密钥信息
            result = f"""===== 加载的密钥信息 =====

密钥ID: {key_id}
生成时间: {creation_time}

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
            
            # 清理临时文件
            shutil.rmtree(temp_dir)
            
            QMessageBox.information(self, "成功", "密钥已成功加载")
            
        except zipfile.BadZipFile:
            QMessageBox.critical(self, "错误", "无效的密钥包或密码错误")
        except Exception as e:
            QMessageBox.critical(self, "错误", f"加载密钥失败: {str(e)}")
    
    def use_current_formatted_key(self):
        """使用当前格式化密钥"""
        if not self.current_key_info:
            QMessageBox.warning(self, "警告", "没有可使用的密钥")
            return
        
        # 这里应该根据上下文使用格式化密钥
        pass
    
    def use_current_pub_key(self):
        """使用当前生成密钥的公钥"""
        if not self.current_key_info:
            QMessageBox.warning(self, "警告", "没有可使用的密钥")
            return
        
        self.pub_key_text.setText(self.current_key_info.public_key)
    
    def use_current_priv_key(self):
        """使用当前生成密钥的私钥"""
        if not self.current_key_info:
            QMessageBox.warning(self, "警告", "没有可使用的密钥")
            return

        self.priv_key_text.setText(self.current_key_info.private_key)
        
    def use_current_keys(self):
        """使用当前密钥"""
        if not self.current_key_info:
            QMessageBox.warning(self, "警告", "没有可使用的当前密钥")
            return
        
        try:
            # 在RSA加解密标签页中使用密钥（检查是否有该属性以避免错误）
            if hasattr(self, 'pub_key_text'):
                self.pub_key_text.setText(self.current_key_info.public_key)
            if hasattr(self, 'priv_key_text'):
                self.priv_key_text.setText(self.current_key_info.private_key)
            
            # 在文件加解密标签页中使用密钥（检查是否有该属性以避免错误）
            if hasattr(self, 'file_pub_key_text'):
                self.file_pub_key_text.setText(self.current_key_info.public_key)
            if hasattr(self, 'file_priv_key_text'):
                self.file_priv_key_text.setText(self.current_key_info.private_key)
            
            self.statusBar().showMessage("当前密钥已应用到所有相关区域!")
            QMessageBox.information(self, "密钥应用", "当前密钥已成功应用到所有相关区域!")
        except Exception as e:
            QMessageBox.critical(self, "错误", f"应用密钥失败: {str(e)}")
    
    def encrypt_text(self):
        """加密文本"""
        try:
            # 获取公钥和明文
            public_key = self.pub_key_text.toPlainText().strip()
            plaintext = self.input_text.toPlainText().strip()
            
            if not public_key:
                QMessageBox.warning(self, "警告", "请输入公钥")
                return
            
            if not plaintext:
                QMessageBox.warning(self, "警告", "请输入要加密的文本")
                return
            
            # 导入公钥
            rsa_key = RSA.import_key(public_key)
            cipher = PKCS1_OAEP.new(rsa_key)
            
            # 加密文本
            encrypted = cipher.encrypt(plaintext.encode())
            
            # Base64编码
            encrypted_b64 = base64.b64encode(encrypted).decode()
            
            # 显示结果
            self.result_text.setText(encrypted_b64)
            
            self.statusBar().showMessage("文本加密成功")
            
        except Exception as e:
            QMessageBox.critical(self, "错误", f"加密文本失败: {str(e)}")
            self.statusBar().showMessage("加密失败")
    
    def decrypt_text(self):
        """解密文本"""
        try:
            # 获取私钥和密文
            private_key = self.priv_key_text.toPlainText().strip()
            encrypted_text = self.input_text.toPlainText().strip()
            
            if not private_key:
                QMessageBox.warning(self, "警告", "请输入私钥")
                return
            
            if not encrypted_text:
                QMessageBox.warning(self, "警告", "请输入要解密的文本")
                return
            
            # Base64解码
            encrypted = base64.b64decode(encrypted_text)
            
            # 导入私钥
            rsa_key = RSA.import_key(private_key)
            cipher = PKCS1_OAEP.new(rsa_key)
            
            # 解密
            decrypted = cipher.decrypt(encrypted).decode()
            
            # 显示结果
            self.result_text.setText(decrypted)
            
            self.statusBar().showMessage("文本解密成功")
            
        except Exception as e:
            QMessageBox.critical(self, "错误", f"解密文本失败: {str(e)}")
            self.statusBar().showMessage("解密失败")
    
    def browse_image(self):
        """浏览图片"""
        file_path, _ = QFileDialog.getOpenFileName(self, "选择图片", "", "图片文件 (*.png *.jpg *.jpeg *.bmp)")
        if file_path:
            self.image_path.setText(file_path)
            self.current_image_path = file_path
            self.preview_image()
    
    def update_image_download_progress(self, value, message):
        """更新图片下载进度"""
        self.stego_status.setText(message)
    
    def random_image_downloaded(self, file_path, image_data):
        """随机图片下载完成"""
        self.image_path.setText(file_path)
        self.current_image_path = file_path
        self.stego_status.setText("随机图片下载完成!")
        self.btn_get_random_image.setEnabled(True)
        
        # 预览图片
        pixmap = QPixmap()
        pixmap.loadFromData(image_data)
        
        # 调整大小用于预览
        max_width = 600
        max_height = 400
        if pixmap.width() > max_width or pixmap.height() > max_height:
            pixmap = pixmap.scaled(max_width, max_height, Qt.KeepAspectRatio, Qt.SmoothTransformation)
        
        # 设置预览
        self.image_preview.setPixmap(pixmap)
        self.image_preview.setScaledContents(True)
        
    def random_image_error(self, error_message):
        """随机图片下载错误"""
        self.stego_status.setText("图片下载失败")
        self.btn_get_random_image.setEnabled(True)
        QMessageBox.critical(self, "错误", error_message)
        
    def get_random_image(self):
        """从Lorem Picsum获取随机图片"""
        self.btn_get_random_image.setEnabled(False)
        self.stego_status.setText("正在下载随机图片...")
        
        # 创建图片下载线程，设置宽度200，高度300
        self.image_downloader = ImageDownloadThread(width=200, height=300)
        self.image_downloader.progress.connect(self.update_image_download_progress)
        self.image_downloader.completed.connect(self.random_image_downloaded)
        self.image_downloader.error.connect(self.random_image_error)
        self.image_downloader.start()
    
    def preview_image(self):
        """预览图片"""
        try:
            image_path = self.image_path.text()
            if not os.path.exists(image_path):
                return
            
            # 加载图片
            pixmap = QPixmap(image_path)
            
            # 调整大小以适应预览窗口
            scaled_pixmap = pixmap.scaled(
                self.image_preview.size(),
                Qt.KeepAspectRatio,
                Qt.SmoothTransformation
            )
            
            # 显示图片
            self.image_preview.setPixmap(scaled_pixmap)
            
        except Exception as e:
            logging.error(f"预览图片失败: {e}")
    
    def browse_file(self):
        """浏览要嵌入的文件"""
        file_path, _ = QFileDialog.getOpenFileName(self, "选择要嵌入的文件", "")
        if file_path:
            self.file_path.setText(file_path)
    
    def browse_save_location(self):
        """浏览保存位置"""
        file_path, _ = QFileDialog.getSaveFileName(self, "保存图种", "", "图种文件 (*.png *.jpg)")
        if file_path:
            self.save_location.setText(file_path)
    
    def create_stego_image(self):
        """创建图种"""
        try:
            # 获取文件路径
            image_file = self.image_path.text()
            hidden_file = self.file_path.text()
            output_file = self.save_location.text()
            
            # 检查文件是否存在
            if not os.path.exists(image_file):
                QMessageBox.warning(self, "警告", "图片文件不存在")
                return
            
            if not os.path.exists(hidden_file):
                QMessageBox.warning(self, "警告", "要嵌入的文件不存在")
                return
            
            if not output_file:
                QMessageBox.warning(self, "警告", "请选择保存位置")
                return
            
            # 读取图片
            with open(image_file, "rb") as img_file:
                image_data = img_file.read()
            
            # 检查文件是否已经是ZIP格式
            is_zip_file = False
            try:
                with zipfile.ZipFile(hidden_file, 'r') as zip_test:
                    is_zip_file = True
            except zipfile.BadZipFile:
                is_zip_file = False
            
            # 如果不是ZIP文件，则打包为.zip文件
            if not is_zip_file:
                # 创建临时目录
                temp_dir = tempfile.mkdtemp(prefix="stego_")
                temp_zip_path = os.path.join(temp_dir, f"{os.path.basename(hidden_file)}.zip")
                
                # 创建ZIP文件
                with zipfile.ZipFile(temp_zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                    zipf.write(hidden_file, os.path.basename(hidden_file))
                
                # 使用临时ZIP文件
                hidden_file = temp_zip_path
            
            # 读取要隐藏的文件
            with open(hidden_file, "rb") as hf:
                hidden_data = hf.read()
            
            # 组合图片和隐藏数据
            combined_data = image_data + hidden_data
            
            # 保存图种
            with open(output_file, "wb") as output:
                output.write(combined_data)
            
            # 清理临时文件
            if is_zip_file is False and 'temp_zip_path' in locals():
                shutil.rmtree(temp_dir)
            
            QMessageBox.information(self, "成功", f"图种已成功创建: {output_file}")
            
        except Exception as e:
            QMessageBox.critical(self, "错误", f"创建图种失败: {str(e)}")
    
    def browse_stego_file(self):
        """浏览图种文件"""
        file_path, _ = QFileDialog.getOpenFileName(self, "选择图种文件", "", "图片文件 (*.png *.jpg *.jpeg)")
        if file_path:
            self.stego_file_path.setText(file_path)
    
    def extract_from_stego(self):
        """从图种中提取文件"""
        try:
            # 获取图种文件路径
            stego_file = self.stego_file_path.text()
            if not os.path.exists(stego_file):
                QMessageBox.warning(self, "警告", "图种文件不存在")
                return
            
            # 读取图种文件
            with open(stego_file, "rb") as f:
                data = f.read()
            
            # 检查PNG文件
            png_end = b"IEND"
            png_end_pos = data.rfind(png_end)
            if png_end_pos != -1:
                # PNG文件，从IEND之后开始
                hidden_data_start = png_end_pos + 4
            else:
                # 检查JPG文件
                jpg_end = b"\xFF\xD9"
                jpg_end_pos = data.rfind(jpg_end)
                if jpg_end_pos != -1:
                    # JPG文件，从FF D9之后开始
                    hidden_data_start = jpg_end_pos + 2
                else:
                    # 尝试找到ZIP文件头
                    zip_header = b"PK\x03\x04"
                    zip_header_pos = data.find(zip_header)
                    if zip_header_pos != -1:
                        hidden_data_start = zip_header_pos
                    else:
                        raise ValueError("无法识别的图种格式")
            
            # 提取隐藏数据
            hidden_data = data[hidden_data_start:]
            
            # 创建临时ZIP文件
            temp_dir = tempfile.mkdtemp(prefix="extract_")
            temp_zip_path = os.path.join(temp_dir, "hidden.zip")
            
            with open(temp_zip_path, "wb") as f:
                f.write(hidden_data)
            
            # 检查是否为有效的ZIP文件
            try:
                with zipfile.ZipFile(temp_zip_path, 'r') as zipf:
                    # 获取文件列表
                    file_list = zipf.namelist()
                    
                    if not file_list:
                        raise ValueError("ZIP文件为空")
                    
                    # 选择保存目录
                    save_dir = QFileDialog.getExistingDirectory(self, "选择保存目录")
                    if not save_dir:
                        return
                    
                    # 解压文件
                    zipf.extractall(save_dir)
                    
                    # 显示提取的文件列表
                    extracted_files = []
                    for root, _, files in os.walk(save_dir):
                        for file in files:
                            extracted_files.append(os.path.join(root, file))
                    
                    file_list_text = "\n".join(extracted_files)
                    QMessageBox.information(self,
                        "提取成功",
                        f"成功提取 {len(extracted_files)} 个文件:\n\n{file_list_text}"
                    )
                    
            except zipfile.BadZipFile:
                # 如果不是ZIP文件，直接保存原始数据
                # 选择保存路径
                save_path, _ = QFileDialog.getSaveFileName(self, "保存提取的文件", "", "所有文件 (*)")
                if save_path:
                    with open(save_path, "wb") as f:
                        f.write(hidden_data)
                    QMessageBox.information(self, "成功", f"文件已成功保存: {save_path}")
            finally:
                # 清理临时文件
                shutil.rmtree(temp_dir)
                
        except Exception as e:
            QMessageBox.critical(self, "错误", f"提取文件失败: {str(e)}")
    
    def format_file_size(self, size_bytes):
        """格式化文件大小"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024.0
    
    def test_stego_image(self):
        """测试图种文件"""
        try:
            # 获取图种文件路径
            stego_file = self.stego_file_path.text()
            if not os.path.exists(stego_file):
                QMessageBox.warning(self, "警告", "图种文件不存在")
                return
            
            # 获取文件大小
            file_size = os.path.getsize(stego_file)
            
            # 读取文件
            with open(stego_file, "rb") as f:
                data = f.read()
            
            # 识别图片类型
            image_type = "未知"
            hidden_data_size = 0
            has_hidden_data = False
            is_valid_zip = False
            
            # 检查PNG文件
            png_end = b"IEND"
            png_end_pos = data.rfind(png_end)
            if png_end_pos != -1:
                image_type = "PNG"
                hidden_data_start = png_end_pos + 4
                if hidden_data_start < file_size:
                    has_hidden_data = True
                    hidden_data_size = file_size - hidden_data_start
            else:
                # 检查JPG文件
                jpg_end = b"\xFF\xD9"
                jpg_end_pos = data.rfind(jpg_end)
                if jpg_end_pos != -1:
                    image_type = "JPEG"
                    hidden_data_start = jpg_end_pos + 2
                    if hidden_data_start < file_size:
                        has_hidden_data = True
                        hidden_data_size = file_size - hidden_data_start
                else:
                    # 尝试找到ZIP文件头
                    zip_header = b"PK\x03\x04"
                    zip_header_pos = data.find(zip_header)
                    if zip_header_pos != -1:
                        has_hidden_data = True
                        hidden_data_size = file_size - zip_header_pos
            
            # 检查是否为ZIP文件
            if has_hidden_data:
                hidden_data = data[hidden_data_start:]
                temp_zip_path = os.path.join(tempfile.gettempdir(), "test_hidden.zip")
                with open(temp_zip_path, "wb") as f:
                    f.write(hidden_data)
                
                try:
                    with zipfile.ZipFile(temp_zip_path, 'r') as zipf:
                        is_valid_zip = True
                        file_list = zipf.namelist()
                except zipfile.BadZipFile:
                    is_valid_zip = False
                finally:
                    if os.path.exists(temp_zip_path):
                        os.remove(temp_zip_path)
            
            # 构建结果消息
            message = f"文件信息:\n"
            message += f"- 文件大小: {self.format_file_size(file_size)}\n"
            message += f"- 图片类型: {image_type}\n"
            message += f"- 是否包含隐藏数据: {'是' if has_hidden_data else '否'}\n"
            
            if has_hidden_data:
                message += f"- 隐藏数据大小: {self.format_file_size(hidden_data_size)}\n"
                message += f"- 是否为ZIP文件: {'是' if is_valid_zip else '否'}\n"
                
                if is_valid_zip and 'file_list' in locals():
                    message += f"- 包含文件数: {len(file_list)}\n"
                    if len(file_list) <= 10:  # 只显示前10个文件
                        message += "- 包含文件:\n"
                        for file in file_list[:10]:
                            message += f"  * {file}\n"
                        if len(file_list) > 10:
                            message += f"  * ... 还有 {len(file_list) - 10} 个文件\n"
            
            QMessageBox.information(self, "图种测试结果", message)
            
        except Exception as e:
            QMessageBox.critical(self, "错误", f"测试图种失败: {str(e)}")
    
    def use_current_pub_key_file(self):
        """使用当前生成密钥的公钥文件"""
        if not self.current_key_info:
            QMessageBox.warning(self, "警告", "没有可使用的密钥")
            return
        
        # 保存临时公钥文件
        temp_dir = tempfile.mkdtemp(prefix="key_")
        temp_pub_key_path = os.path.join(temp_dir, "temp_pub_key.pem")
        
        # 移除PEM格式的头尾
        clean_public_key = self.current_key_info.public_key.replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "").strip()
        
        with open(temp_pub_key_path, "w", encoding="utf-8") as f:
            f.write(clean_public_key)
        
        self.pub_key_file_edit.setText(temp_pub_key_path)
    
    def use_current_priv_key_file(self):
        """使用当前生成密钥的私钥文件"""
        if not self.current_key_info:
            QMessageBox.warning(self, "警告", "没有可使用的密钥")
            return
        
        # 保存临时私钥文件
        temp_dir = tempfile.mkdtemp(prefix="key_")
        temp_priv_key_path = os.path.join(temp_dir, "temp_priv_key.key")
        
        # 移除PEM格式的头尾
        clean_private_key = self.current_key_info.private_key.replace("-----BEGIN PRIVATE KEY-----", "").replace("-----END PRIVATE KEY-----", "").strip()
        # 处理RSA私钥格式
        clean_private_key = clean_private_key.replace("-----BEGIN RSA PRIVATE KEY-----", "").replace("-----END RSA PRIVATE KEY-----", "").strip()
        
        with open(temp_priv_key_path, "w", encoding="utf-8") as f:
            f.write(clean_private_key)
        
        self.priv_key_file_edit.setText(temp_priv_key_path)
    
    def use_current_pub_key_for_file(self):
        """使用当前生成密钥的公钥到文件加密"""
        if hasattr(self, 'public_key_pem') and self.public_key_pem:
            self.file_pub_key_text.setPlainText(self.public_key_pem)
            self.operation_status.append("已从当前生成密钥复制公钥")
        else:
            QMessageBox.warning(self, "警告", "请先生成密钥！")
    
    def use_current_priv_key_for_file(self):
        """使用当前生成密钥的私钥到文件加密"""
        if hasattr(self, 'private_key_pem') and self.private_key_pem:
            self.file_priv_key_text.setPlainText(self.private_key_pem)
            self.operation_status.append("已从当前生成密钥复制私钥")
        else:
            QMessageBox.warning(self, "警告", "请先生成密钥！")
    
    def load_pub_key_from_file(self):
        """从文件加载公钥"""
        file_path, _ = QFileDialog.getOpenFileName(self, "选择公钥文件", "", "密钥文件 (*.pem *.key *.pub);;所有文件 (*.*)")
        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    pub_key_content = f.read()
                    self.file_pub_key_text.setPlainText(pub_key_content)
                    self.operation_status.append(f"已从文件加载公钥: {os.path.basename(file_path)}")
            except Exception as e:
                QMessageBox.critical(self, "错误", f"加载公钥文件失败: {str(e)}")
                self.operation_status.append(f"加载公钥文件失败: {str(e)}")
    
    def load_priv_key_from_file(self):
        """从文件加载私钥"""
        file_path, _ = QFileDialog.getOpenFileName(self, "选择私钥文件", "", "密钥文件 (*.pem *.key *.priv);;所有文件 (*.*)")
        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    priv_key_content = f.read()
                    self.file_priv_key_text.setPlainText(priv_key_content)
                    self.operation_status.append(f"已从文件加载私钥: {os.path.basename(file_path)}")
            except Exception as e:
                QMessageBox.critical(self, "错误", f"加载私钥文件失败: {str(e)}")
                self.operation_status.append(f"加载私钥文件失败: {str(e)}")
                
    def browse_pub_key_file(self):
        """浏览公钥文件 (保留以保持兼容性)"""
        self.load_pub_key_from_file()
    
    def browse_priv_key_file(self):
        """浏览私钥文件 (保留以保持兼容性)"""
        self.load_priv_key_from_file()
    
    def browse_encrypt_file(self):
        """浏览要加密的文件"""
        file_path, _ = QFileDialog.getOpenFileName(self, "选择要加密的文件", "")
        if file_path:
            self.encrypt_file_edit.setText(file_path)
    
    def browse_decrypt_file(self):
        """浏览要解密的文件"""
        file_path, _ = QFileDialog.getOpenFileName(self, "选择要解密的文件", "")
        if file_path:
            self.decrypt_file_edit.setText(file_path)
    
    def encrypt_file(self):
        """加密文件"""
        try:
            # 获取文件路径
            input_file = self.encrypt_file_edit.text()
            if not os.path.exists(input_file):
                QMessageBox.warning(self, "警告", "要加密的文件不存在")
                return
            
            # 选择保存位置
            output_file, _ = QFileDialog.getSaveFileName(self, "保存加密文件", "", "加密文件 (*.enc)")
            if not output_file:
                return
            
            # 从QTextEdit获取公钥内容
            public_key = self.file_pub_key_text.toPlainText().strip()
            if not public_key:
                QMessageBox.warning(self, "警告", "请先输入或导入公钥！")
                return
            
            # 导入公钥
            rsa_key = RSA.import_key(public_key)
            cipher = PKCS1_OAEP.new(rsa_key)
            
            # 生成随机的AES密钥
            aes_key = get_random_bytes(32)  # 256位AES密钥
            iv = get_random_bytes(16)  # 128位IV
            
            # 使用RSA加密AES密钥和IV
            encrypted_key = cipher.encrypt(aes_key + iv)
            
            # 创建AES-CBC加密器
            aes_cipher = AES.new(aes_key, AES.MODE_CBC, iv)
            
            # 加密文件
            self.operation_status.append("开始加密文件...")
            
            with open(input_file, "rb") as in_file, open(output_file, "wb") as out_file:
                # 写入加密的AES密钥长度和加密的密钥
                out_file.write(struct.pack('!I', len(encrypted_key)))
                out_file.write(encrypted_key)
                
                # 分块加密文件内容
                chunk_size = 65536
                total_size = os.path.getsize(input_file)
                processed_size = 0
                
                while True:
                    chunk = in_file.read(chunk_size)
                    if not chunk:
                        break
                    
                    # 填充到16字节的倍数
                    if len(chunk) % 16 != 0:
                        chunk += b' ' * (16 - len(chunk) % 16)
                    
                    # 加密并写入
                    encrypted_chunk = aes_cipher.encrypt(chunk)
                    out_file.write(encrypted_chunk)
                    
                    # 更新进度
                    processed_size += len(chunk)
                    progress = int((processed_size / total_size) * 100)
                    self.operation_status.append(f"加密进度: {progress}%")
            
            self.operation_status.append(f"文件加密完成: {output_file}")
            QMessageBox.information(self, "成功", "文件加密完成")
            
        except Exception as e:
            QMessageBox.critical(self, "错误", f"加密文件失败: {str(e)}")
            self.operation_status.append(f"加密失败: {str(e)}")
    
    def decrypt_file(self):
        """解密文件"""
        try:
            # 获取文件路径
            input_file = self.decrypt_file_edit.text()
            if not os.path.exists(input_file):
                QMessageBox.warning(self, "警告", "要解密的文件不存在")
                return
            
            # 选择保存位置
            output_file, _ = QFileDialog.getSaveFileName(self, "保存解密文件", "")
            if not output_file:
                return
            
            # 从QTextEdit获取私钥内容
            private_key = self.file_priv_key_text.toPlainText().strip()
            if not private_key:
                QMessageBox.warning(self, "警告", "请先输入或导入私钥！")
                return
            
            # 导入私钥
            rsa_key = RSA.import_key(private_key)
            cipher = PKCS1_OAEP.new(rsa_key)
            
            # 解密文件
            self.operation_status.append("开始解密文件...")
            
            with open(input_file, "rb") as in_file, open(output_file, "wb") as out_file:
                # 读取加密的AES密钥长度
                encrypted_key_len = struct.unpack('!I', in_file.read(4))[0]
                
                # 读取加密的AES密钥
                encrypted_key = in_file.read(encrypted_key_len)
                
                # 使用RSA解密AES密钥和IV
                decrypted_key = cipher.decrypt(encrypted_key)
                aes_key = decrypted_key[:32]  # 前256位是AES密钥
                iv = decrypted_key[32:48]     # 接下来的128位是IV
                
                # 创建AES-CBC解密器
                aes_cipher = AES.new(aes_key, AES.MODE_CBC, iv)
                
                # 分块解密文件内容
                chunk_size = 65536
                total_size = os.path.getsize(input_file) - 4 - encrypted_key_len
                processed_size = 0
                
                while True:
                    chunk = in_file.read(chunk_size)
                    if not chunk:
                        break
                    
                    # 解密
                    decrypted_chunk = aes_cipher.decrypt(chunk)
                    
                    # 写入解密的数据
                    out_file.write(decrypted_chunk)
                    
                    # 更新进度
                    processed_size += len(chunk)
                    progress = int((processed_size / total_size) * 100)
                    self.operation_status.append(f"解密进度: {progress}%")
            
            self.operation_status.append(f"文件解密完成: {output_file}")
            QMessageBox.information(self, "成功", "文件解密完成")
            
        except Exception as e:
            QMessageBox.critical(self, "错误", f"解密文件失败: {str(e)}")
            self.operation_status.append(f"解密失败: {str(e)}")
    
    def show_about(self):
        """显示关于信息"""
        QMessageBox.about(
            self,
            "关于高级密钥工具 v3.6",
            "高级密钥工具 v3.6\n\n"
            "功能特性：\n"
            "- 增强的RSA-4096密钥生成（支持鼠标晃动增强随机性）\n"
            "- RSA文本加解密（PKCS1_OAEP模式）\n"
            "- 图种制作与提取\n"
            "- 文件加解密（AES-CBC + RSA封装）\n"
            "- 密钥管理与保存\n\n"
            "v3.6 更新：\n"
            "- 新增鼠标晃动获取随机数功能\n"
            "- 修复随机图片获取功能\n"
            "- 优化密钥生成算法\n"
            "- 改进用户界面"
        )
    
    def resizeEvent(self, event):
        """窗口大小变化时重新预览图片"""
        super().resizeEvent(event)
        self.preview_image()


# 保存密钥到文件函数（命令行模式）
def save_keys_to_files(key_info):
    """保存密钥到文件（命令行版本）"""
    try:
        # 创建临时目录
        temp_dir = tempfile.mkdtemp(prefix="key_")
        
        # 保存密钥信息文本文件
        txt_path = os.path.join(temp_dir, "key.txt")
        with open(txt_path, "w", encoding="utf-8") as f:
            f.write(f"密钥ID: {key_info.key_id}\n")
            f.write(f"创建时间: {key_info.creation_time}\n\n")
            f.write(f"===== 格式化密钥 =====\n")
            f.write(key_info.formatted_key)
            f.write("\n\n===== 完整十六进制 =====\n")
            f.write(key_info.hex_key)
        
        # 保存公钥（移除PEM格式的头尾）
        pem_path = os.path.join(temp_dir, "key.pem")
        clean_public_key = key_info.public_key.replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "").strip()
        with open(pem_path, "w", encoding="utf-8") as f:
            f.write(clean_public_key)
        
        # 保存私钥（移除PEM格式的头尾）
        key_path = os.path.join(temp_dir, "key.key")
        clean_private_key = key_info.private_key.replace("-----BEGIN PRIVATE KEY-----", "").replace("-----END PRIVATE KEY-----", "").strip()
        clean_private_key = clean_private_key.replace("-----BEGIN RSA PRIVATE KEY-----", "").replace("-----END RSA PRIVATE KEY-----", "").strip()
        with open(key_path, "w", encoding="utf-8") as f:
            f.write(clean_private_key)
        
        # 创建ZIP文件路径
        zip_path = os.path.join(os.getcwd(), f"密钥包_{time.strftime('%Y%m%d_%H%M%S')}.zip")
        
        # 创建ZIP文件
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for file in [txt_path, pem_path, key_path]:
                zipf.write(file, os.path.basename(file))
            zipf.setpassword(key_info.key_id.encode('utf-8'))
        
        # 清理临时文件
        shutil.rmtree(temp_dir)
        
        return zip_path
        
    except Exception as e:
        print(f"保存密钥文件失败: {str(e)}")
        raise


def main():
    """主函数"""
    # 解析命令行参数
    parser = argparse.ArgumentParser(description="高级密钥工具 v3.6")
    parser.add_argument("--nogui", action="store_true", help="使用命令行模式")
    parser.add_argument("--generate-key", action="store_true", help="生成密钥")
    parser.add_argument("--encrypt", nargs=2, metavar=('INPUT', 'OUTPUT'), help="加密文件")
    parser.add_argument("--decrypt", nargs=2, metavar=('INPUT', 'OUTPUT'), help="解密文件")
    parser.add_argument("--pubkey", help="公钥文件路径")
    parser.add_argument("--privkey", help="私钥文件路径")
    parser.add_argument("--stego-create", nargs=3, metavar=('IMAGE', 'HIDDEN', 'OUTPUT'), help="创建图种")
    parser.add_argument("--stego-extract", nargs=2, metavar=('STEGO', 'OUTPUT'), help="提取图种")
    parser.add_argument("--mouse-entropy", action="store_true", help="使用鼠标熵增强随机性")
    
    args = parser.parse_args()
    
    # 清理临时文件
    try:
        import atexit
        temp_dirs = []
        
        def cleanup_temp_files():
            for temp_dir in temp_dirs:
                if os.path.exists(temp_dir):
                    try:
                        shutil.rmtree(temp_dir)
                    except:
                        pass
        
        atexit.register(cleanup_temp_files)
    except:
        pass
    
    # 命令行模式
    if args.nogui:
        # 生成密钥模式
        if args.generate_key:
            print("开始生成密钥...")
            
            # 初始化密钥生成器
            key_generator = EnhancedKeyGeneratorThread(use_mouse_entropy=args.mouse_entropy)
            
            # 如果使用鼠标熵，这里简单提示用户
            if args.mouse_entropy:
                print("注意：命令行模式下鼠标熵功能不可用")
                print("请使用GUI模式以启用鼠标熵功能")
            
            # 同步生成密钥
            key_info = key_generator.generate_key_sync()
            
            if key_info:
                print(f"\n密钥ID: {key_info.key_id}")
                print(f"格式化密钥: {key_info.formatted_key}")
                print(f"创建时间: {key_info.creation_time}")
                
                # 保存密钥
                zip_path = save_keys_to_files(key_info)
                print(f"\n密钥已保存到: {zip_path}")
                print(f"解压密码: {key_info.key_id}")
        
        # 文本加密模式（简化版）
        elif args.encrypt:
            try:
                input_file, output_file = args.encrypt
                
                if not os.path.exists(input_file):
                    print(f"错误: 文件不存在: {input_file}")
                    return
                
                if not args.pubkey or not os.path.exists(args.pubkey):
                    print("错误: 请指定有效的公钥文件")
                    return
                
                # 读取公钥
                with open(args.pubkey, "r", encoding="utf-8") as f:
                    public_key_content = f.read().strip()
                
                # 添加PEM格式头尾
                public_key = f"-----BEGIN PUBLIC KEY-----\n{public_key_content}\n-----END PUBLIC KEY-----"
                
                # 导入公钥
                rsa_key = RSA.import_key(public_key)
                cipher = PKCS1_OAEP.new(rsa_key)
                
                # 生成随机的AES密钥
                aes_key = get_random_bytes(32)
                iv = get_random_bytes(16)
                
                # 使用RSA加密AES密钥和IV
                encrypted_key = cipher.encrypt(aes_key + iv)
                
                # 创建AES-CBC加密器
                aes_cipher = AES.new(aes_key, AES.MODE_CBC, iv)
                
                # 加密文件
                print(f"开始加密文件: {input_file}")
                
                with open(input_file, "rb") as in_file, open(output_file, "wb") as out_file:
                    # 写入加密的AES密钥长度和加密的密钥
                    out_file.write(struct.pack('!I', len(encrypted_key)))
                    out_file.write(encrypted_key)
                    
                    # 分块加密文件内容
                    chunk_size = 65536
                    total_size = os.path.getsize(input_file)
                    processed_size = 0
                    
                    while True:
                        chunk = in_file.read(chunk_size)
                        if not chunk:
                            break
                        
                        # 填充到16字节的倍数
                        if len(chunk) % 16 != 0:
                            chunk += b' ' * (16 - len(chunk) % 16)
                        
                        # 加密并写入
                        encrypted_chunk = aes_cipher.encrypt(chunk)
                        out_file.write(encrypted_chunk)
                        
                        # 更新进度
                        processed_size += len(chunk)
                        progress = int((processed_size / total_size) * 100)
                        print(f"加密进度: {progress}%")
                
                print(f"文件加密完成: {output_file}")
                
            except Exception as e:
                print(f"加密文件失败: {str(e)}")
        
        # 文本解密模式（简化版）
        elif args.decrypt:
            try:
                input_file, output_file = args.decrypt
                
                if not os.path.exists(input_file):
                    print(f"错误: 文件不存在: {input_file}")
                    return
                
                if not args.privkey or not os.path.exists(args.privkey):
                    print("错误: 请指定有效的私钥文件")
                    return
                
                # 读取私钥
                with open(args.privkey, "r", encoding="utf-8") as f:
                    private_key_content = f.read().strip()
                
                # 尝试两种格式的私钥
                try:
                    private_key = f"-----BEGIN RSA PRIVATE KEY-----\n{private_key_content}\n-----END RSA PRIVATE KEY-----"
                    RSA.import_key(private_key)
                except:
                    private_key = f"-----BEGIN PRIVATE KEY-----\n{private_key_content}\n-----END PRIVATE KEY-----"
                
                # 导入私钥
                rsa_key = RSA.import_key(private_key)
                cipher = PKCS1_OAEP.new(rsa_key)
                
                # 解密文件
                print(f"开始解密文件: {input_file}")
                
                with open(input_file, "rb") as in_file, open(output_file, "wb") as out_file:
                    # 读取加密的AES密钥长度
                    encrypted_key_len = struct.unpack('!I', in_file.read(4))[0]
                    
                    # 读取加密的AES密钥
                    encrypted_key = in_file.read(encrypted_key_len)
                    
                    # 使用RSA解密AES密钥和IV
                    decrypted_key = cipher.decrypt(encrypted_key)
                    aes_key = decrypted_key[:32]
                    iv = decrypted_key[32:48]
                    
                    # 创建AES-CBC解密器
                    aes_cipher = AES.new(aes_key, AES.MODE_CBC, iv)
                    
                    # 分块解密文件内容
                    chunk_size = 65536
                    total_size = os.path.getsize(input_file) - 4 - encrypted_key_len
                    processed_size = 0
                    
                    while True:
                        chunk = in_file.read(chunk_size)
                        if not chunk:
                            break
                        
                        # 解密
                        decrypted_chunk = aes_cipher.decrypt(chunk)
                        
                        # 写入解密的数据
                        out_file.write(decrypted_chunk)
                        
                        # 更新进度
                        processed_size += len(chunk)
                        progress = int((processed_size / total_size) * 100)
                        print(f"解密进度: {progress}%")
                
                print(f"文件解密完成: {output_file}")
                
            except Exception as e:
                print(f"解密文件失败: {str(e)}")
        
        # 创建图种模式
        elif args.stego_create:
            try:
                image_file, hidden_file, output_file = args.stego_create
                
                # 检查文件是否存在
                if not os.path.exists(image_file):
                    print(f"错误: 图片文件不存在: {image_file}")
                    return
                
                if not os.path.exists(hidden_file):
                    print(f"错误: 要嵌入的文件不存在: {hidden_file}")
                    return
                
                # 读取图片
                with open(image_file, "rb") as img_file:
                    image_data = img_file.read()
                
                # 检查文件是否已经是ZIP格式
                is_zip_file = False
                try:
                    with zipfile.ZipFile(hidden_file, 'r') as zip_test:
                        is_zip_file = True
                except zipfile.BadZipFile:
                    is_zip_file = False
                
                # 如果不是ZIP文件，则打包为.zip文件
                temp_zip_path = None
                temp_dir = None
                
                if not is_zip_file:
                    # 创建临时目录
                    temp_dir = tempfile.mkdtemp(prefix="stego_")
                    temp_zip_path = os.path.join(temp_dir, f"{os.path.basename(hidden_file)}.zip")
                    
                    # 创建ZIP文件
                    with zipfile.ZipFile(temp_zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                        zipf.write(hidden_file, os.path.basename(hidden_file))
                    
                    # 使用临时ZIP文件
                    hidden_file = temp_zip_path
                
                # 读取要隐藏的文件
                with open(hidden_file, "rb") as hf:
                    hidden_data = hf.read()
                
                # 组合图片和隐藏数据
                combined_data = image_data + hidden_data
                
                # 保存图种
                with open(output_file, "wb") as output:
                    output.write(combined_data)
                
                # 清理临时文件
                if temp_dir and os.path.exists(temp_dir):
                    shutil.rmtree(temp_dir)
                
                print(f"图种已成功创建: {output_file}")
                
            except Exception as e:
                print(f"创建图种失败: {str(e)}")
        
        # 提取图种模式
        elif args.stego_extract:
            try:
                stego_file, output_dir = args.stego_extract
                
                if not os.path.exists(stego_file):
                    print(f"错误: 图种文件不存在: {stego_file}")
                    return
                
                # 确保输出目录存在
                if not os.path.exists(output_dir):
                    os.makedirs(output_dir)
                
                # 读取图种文件
                with open(stego_file, "rb") as f:
                    data = f.read()
                
                # 检查PNG文件
                png_end = b"IEND"
                png_end_pos = data.rfind(png_end)
                if png_end_pos != -1:
                    # PNG文件，从IEND之后开始
                    hidden_data_start = png_end_pos + 4
                else:
                    # 检查JPG文件
                    jpg_end = b"\xFF\xD9"
                    jpg_end_pos = data.rfind(jpg_end)
                    if jpg_end_pos != -1:
                        # JPG文件，从FF D9之后开始
                        hidden_data_start = jpg_end_pos + 2
                    else:
                        # 尝试找到ZIP文件头
                        zip_header = b"PK\x03\x04"
                        zip_header_pos = data.find(zip_header)
                        if zip_header_pos != -1:
                            hidden_data_start = zip_header_pos
                        else:
                            print("错误: 无法识别的图种格式")
                            return
                
                # 提取隐藏数据
                hidden_data = data[hidden_data_start:]
                
                # 创建临时ZIP文件
                temp_dir = tempfile.mkdtemp(prefix="extract_")
                temp_zip_path = os.path.join(temp_dir, "hidden.zip")
                
                with open(temp_zip_path, "wb") as f:
                    f.write(hidden_data)
                
                # 检查是否为有效的ZIP文件
                try:
                    with zipfile.ZipFile(temp_zip_path, 'r') as zipf:
                        # 解压文件
                        zipf.extractall(output_dir)
                        print(f"成功从图种中提取文件到: {output_dir}")
                        
                        # 显示提取的文件列表
                        print("提取的文件列表:")
                        for root, _, files in os.walk(output_dir):
                            for file in files:
                                print(f"  - {os.path.join(root, file)}")
                                
                except zipfile.BadZipFile:
                    # 如果不是ZIP文件，直接保存原始数据
                    output_file = os.path.join(output_dir, "extracted_data.bin")
                    with open(output_file, "wb") as f:
                        f.write(hidden_data)
                    print(f"提取的数据不是ZIP文件，已保存到: {output_file}")
                finally:
                    # 清理临时文件
                    if os.path.exists(temp_dir):
                        shutil.rmtree(temp_dir)
                        
            except Exception as e:
                print(f"提取图种失败: {str(e)}")
        
        else:
            parser.print_help()
    
    # GUI模式
    else:
        app = QApplication(sys.argv)
        
        # 设置应用程序信息
        app.setApplicationName("高级密钥工具")
        app.setOrganizationName("AdvancedKeyTools")
        
        # 创建并显示主窗口
        window = AdvancedKeyToolsGUI()
        window.show()
        
        # 运行应用程序
        sys.exit(app.exec_())


if __name__ == "__main__":
    # 清理临时文件
    try:
        import tempfile
        import glob
        
        # 清理可能的临时文件
        temp_dirs = glob.glob(os.path.join(tempfile.gettempdir(), "key_*"))
        for temp_dir in temp_dirs:
            if os.path.isdir(temp_dir):
                try:
                    shutil.rmtree(temp_dir)
                except:
                    pass
    except:
        pass
    
    # 运行主函数
    main()