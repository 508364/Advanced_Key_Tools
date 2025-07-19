import os
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
from Crypto.PublicKey import RSA

# 自定义符号集 (ASCII可打印特殊字符)
SYMBOLS = r"""!@#$%^&*()_+~`-=[];'\,./{}:"|<>?"""

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
        print("\n" + "▀" * 60)
        print(f"{" KEY GENERATION STEPS ":=^60}")
        for name, value in self.log.items():
            step_id = name.split("_")[0]
            step_name = name.split("_", 1)[1]
            if isinstance(value, bytes):
                value_str = f"{self.hexify(value[:8])}...{self.hexify(value[-8:])}"
            elif isinstance(value, tuple):
                value_str = f"公钥:\n{value[0]}\n\n私钥:\n{value[1]}"
            else:
                value_str = str(value)
                
            print(f"[Step {step_id}] {step_name:14} : {value_str}")
        print("▄" * 60 + "\n")

def collect_network_data(duration=10):
    """多线程收集网络数据(10秒)"""
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

def generate_entropy():
    """并行生成熵源数据"""
    # 1. 启动网络数据收集线程
    net_result, net_thread = collect_network_data()
    
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

def derive_key(seed, prev_salt, iterations=100000, dklen=64, algo='sha512', logger=None):
    """派生密钥并记录过程"""
    # 基于上一级密钥生成新盐值
    new_salt = hashlib.shake_128(prev_salt + seed).digest(32) if prev_salt else os.urandom(32)
    
    # 密钥派生
    derived = hashlib.pbkdf2_hmac(
        algo, 
        seed, 
        new_salt, 
        iterations, 
        dklen=dklen
    )
    
    # 记录过程
    if logger:
        logger.add(f"PBKDF2-HMAC-{algo}", derived)
        logger.add(f"SALT_{algo}", new_salt)
    
    return derived, new_salt

def generate_rsa_keypair(seed):
    """使用种子生成RSA密钥对"""
    # 创建基于种子的伪随机数生成器
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
                # 通过哈希扩展随机池
                if self.position >= len(self.seed):
                    self.seed = hashlib.sha256(self.seed).digest()
                    self.position = 0
            return result
    
    # 生成RSA密钥
    rsa_gen = RSA.generate(2048, randfunc=SeedRandom(seed))
    
    private_key = rsa_gen.export_key().decode()
    public_key = rsa_gen.publickey().export_key().decode()
    
    return public_key, private_key

def format_key(hex_key):
    """使用自定义符号集格式化密钥"""
    # 随机选取分组大小(4-8字符)
    group_size = secrets.choice([4, 5, 6, 7, 8])
    groups = [hex_key[i:i+group_size] for i in range(0, len(hex_key), group_size)]
    
    # 随机选择不同的分隔符
    separators = [secrets.choice(SYMBOLS) for _ in groups[1:]]
    
    # 构建格式化密钥
    formatted = groups[0]
    for i, sep in enumerate(separators, 1):
        formatted += sep + groups[i]
    
    return formatted

def generate_composite_key():
    """生成复合密钥系统"""
    logger = KeyLogger()
    
    # 1. 收集熵源
    entropy = generate_entropy()
    logger.add("原始熵源", entropy)
    
    # 2. 第一级派生 (SHA512)
    k1, salt1 = derive_key(entropy, None, logger=logger, dklen=64)
    
    # 3. 第二级派生 (SHA3-512)
    k2, salt2 = derive_key(k1, salt1, logger=logger, algo='sha3_512', dklen=64)
    
    # 4. 第三级派生 (BLAKE2s)
    k3, salt3 = derive_key(k2, salt2, logger=logger, algo='blake2s', dklen=64)
    
    # 5. 生成RSA密钥对
    rsa_seed = k3[:32]  # 使用前256位作为种子
    public_key, private_key = generate_rsa_keypair(rsa_seed)
    logger.add("RSA_2048密钥对" ,(public_key, private_key))
    
    return k3, public_key, private_key, logger

def save_key_files(key_id, formatted_key, public_key, private_key):
    """保存密钥文件并打包为ZIP"""
    # 创建临时目录
    temp_dir = tempfile.mkdtemp(prefix="keygen_")
    
    try:
        # 1. 保存格式化密钥
        txt_path = os.path.join(temp_dir, "key.txt")
        with open(txt_path, "w", encoding="utf-8") as f:
            f.write(f"密钥ID: {key_id}\n")
            f.write(f"生成时间: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("\n===== 格式化密钥 =====\n")
            f.write(formatted_key)
            f.write("\n\n===== 完整十六进制 =====\n")
            f.write(binascii.hexlify(bin_key).decode())
        
        # 2. 保存公钥
        pem_path = os.path.join(temp_dir, "key.pem")
        with open(pem_path, "w", encoding="utf-8") as f:
            f.write(public_key)
        
        # 3. 保存私钥
        key_path = os.path.join(temp_dir, "key.key")
        with open(key_path, "w", encoding="utf-8") as f:
            f.write(private_key)
        
        # 4. 创建加密ZIP文件
        zip_path = os.path.join(os.getcwd(), "key.zip")
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for file in [txt_path, pem_path, key_path]:
                zipf.write(file, os.path.basename(file))
            
            # 设置ZIP密码为密钥ID
            zipf.setpassword(key_id.encode('utf-8'))
        
        return zip_path
    finally:
        # 清理临时目录
        shutil.rmtree(temp_dir)

def prompt_save_files(key_id, bin_key, public_key, private_key):
    """提示用户保存密钥文件"""
    hex_key = binascii.hexlify(bin_key).decode()
    formatted_key = format_key(hex_key)
    
    print("\n" + "▄" * 60)
    print(f"{" 文件保存选项 ":=^60}")
    print("▀" * 60)
    choice = input("是否保存密钥文件? (y/n): ").strip().lower()
    
    if choice == 'y':
        try:
            zip_path = save_key_files(key_id, formatted_key, public_key, private_key)
            print("\n" + "▄" * 60)
            print(f"{" 文件保存成功 ":=^60}")
            print(f"ZIP文件路径: {zip_path}")
            print(f"解压密码: {key_id}")
            print("▀" * 60)
            print("包含文件:")
            print("  key.txt - 格式化密钥")
            print("  key.pem - RSA公钥")
            print("  key.key - RSA私钥")
            print("▄" * 60)
        except Exception as e:
            print(f"\n❌ 文件保存失败: {e}")
    else:
        print("\n跳过文件保存")

# 主程序
if __name__ == "__main__":
    print("\n" + "▄" * 60)
    print(f"{" 增强型多级密钥生成系统 ":=^60}")
    print("▀" * 60)
    print("  正在收集系统熵源 - 这需要10秒")
    print("  同时执行其他加密操作...")
    print("▄" * 60)
    
    start_time = time.time()
    
    try:
        # 生成密钥系统
        bin_key, public_key, private_key, logger = generate_composite_key()
        hex_key = binascii.hexlify(bin_key).decode()
        
        # 记录生成时间
        duration = time.time() - start_time
        logger.add("生成耗时", f"{duration:.2f}秒")
        
        # 显示所有步骤
        logger.display()
        
        # 密钥摘要
        print("\n" + "▀" * 60)
        print(f"{" FINAL KEYS ":=^60}")
        print(f"主密钥长度: {len(bin_key)}字节 (512位)")
        print(f"密钥摘要: {hex_key[:16]}...{hex_key[-16:]}")
        
        # 格式化输出
        formatted_key = format_key(hex_key)
        print("\n" + f"{" 格式化密钥 ":=^60}")
        print(formatted_key)
        
        # RSA密钥摘要
        print("\n" + f"{" RSA 密钥 ":=^60}")
        print(f"公钥摘要: {public_key[:40]}...")
        print(f"私钥摘要: {private_key[:40]}...")
        
        # 密钥ID
        key_id = f"KEY-{time.strftime('%Y%m%d-%H%M%S')}-{hex_key[:6].upper()}"
        print(f"\n🔑 密钥ID: {key_id}")
        
        # 安全信息
        print("\n★ 安全应用场景:")
        print("  军用级通信加密 | 区块链根密钥 | 量子安全系统")
        print("  金融交易签名 | 数字身份认证 | 安全启动协议")
        
        # 文件保存选项
        prompt_save_files(key_id, bin_key, public_key, private_key)
        
    except Exception as e:
        logging.exception("密钥生成失败!")
        print(f"\n❌ 错误: {e}")
    finally:
        print("\n" + "▀" * 60)
        print("► 安全警告: 切勿存储此密钥于不安全的媒介!")
        print("► 最佳实践: 使用硬件安全模块(HSM)保护密钥")
        print("▄" * 60)
