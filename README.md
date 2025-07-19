# Advanced_Key_Tools

**请勿用于非法用途**  
**严禁将此系统用于非法活动或未经授权的目的**

## 🛡️ 重要声明

本项目生成的高级密钥仅用于合法的安全研究、加密保护和授权测试场景。开发者对任何滥用行为不承担法律责任。任何使用本系统的用户都应遵守当地法律法规和国际加密技术使用规范。

**反复声明：请勿用于非法用途**

## 🌟 项目概述

这是一个军用级安全密钥生成系统，使用多源熵收集技术和多层加密算法派生，生成无法预测的高强度复合密钥（512位主密钥 + RSA-2048密钥对）。系统遵循NIST SP800-90B标准，达到量子安全级别。

## ⚙️ 核心技术

### 熵源采集机制
- 实时网络数据包分析（10秒监控）
- 系统进程指纹（PID/PPID/线程数）
- 高精度时间熵源（纳秒级时钟）
- UUID v4随机引擎
- 操作系统随机数发生器（/dev/urandom）

### 多层密钥派生架构
1. **原始熵源混合** - 组合5个熵源（128位+）
2. **PBKDF2-HMAC-SHA512** - 100,000轮迭代
3. **PBKDF2-HMAC-SHA3_512** - 抗量子加固
4. **PBKDF2-HMAC-BLAKE2s** - 最终密钥导出
5. **RSA-2048密钥对生成** - 基于种子确定性生成

### 安全特性
- 盐值级联传递（前轮输出作为后轮输入）
- 抗侧信道攻击设计
- 内存安全处理（敏感数据不落盘）
- 输出密钥格式混淆（动态分隔符）
- AES-256加密输出（ZIP密码保护）

## 📦 安装依赖

```bash
# Python 3.10+
pip install -r requirements.txt
```

##🚀 使用指南

```bash
python key_generator.py
```
>1系统自动收集熵源（需要10秒）
>2显示三级密钥派生过程
>3生成512位主密钥+RSA密钥对
>4选择是否导出加密文件

##📄 输出文件
* 可选择生成加密ZIP包含：

| 文件名     | 内容格式             | 用途说明                             |
|------------|----------------------|--------------------------------------|
| `key.txt`  | UTF-8 文本           | 通常用于存储格式化的密钥或十六进制值 |
| `key.pem`  | PEM 格式（Base64）   | 存储 RSA 公钥                        |
| `key.key`  | PKCS#8 格式（Base64）| 存储 RSA 私钥                        |

##⚠️ 安全警告

 1. **🔐 密钥保管责任**
  **生成的密钥等同于银行金库钥匙，丢失或泄露将导致安全系统崩溃**
 2. **🚫 禁用场景**
 - 禁止在未加密的公共网络传输
 - 禁止存储于云笔记/邮件附件
 - 禁止用于非法加密勒索
 3. **💣 ​​自毁机制​**
    程序运行时密钥仅存在于内存，关闭后立即消失
 4. **🛡️ ​​最佳实践**
    - 使用HSM硬件模块保管密钥
    - 实施MFA多因素验证
    - 定期密钥轮换（建议每90天）
    
##📜 输出示例

```text

▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀
=================== KEY GENERATION STEPS ===================
[Step 01] 原始熵源           : 2ca7c8a6ce1eda41...cc80dcf90628a35e
[Step 02] PBKDF2-HMAC-sha512 : 079f7c33b3b89b33...a85c319b3eb8070d
[Step 03] SALT_sha512    : 95fab9363f68e4ab...a2ee9d3ce0500152
[Step 04] PBKDF2-HMAC-sha3_512 : 880b1969d0b4870f...4a6e26598cb913ed
[Step 05] SALT_sha3_512  : 2365c7b1a8df1f9c...ba282c2cd981072f
[Step 06] PBKDF2-HMAC-blake2s : ff0da578cdc484f4...2421e65397cee482
[Step 07] SALT_blake2s   : 01d9222e21353350...29a20f825e3119fc
[Step 08] RSA_2048密钥对    : 公钥:
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5phQ1tPVuHnwovVXuMtO
5sZn/YrOqTq/PsdESztntFDz2PUFI0lIe8KsCcshjtRMPB5+6phvKDxMJqg3f2dA
76T+muY9wNITWtp6/MkQKB2/vP6EE5/D482UQlcoc91wxgmuouR5aeXmS/aKJQ8K
+yPwdxHCqRhsbBij83RWetfjbPkvJFTU2zQJfsZqCxBzMt03BI9IV7EqlrhkKLbZ
9owbN9SV1GWClW5XdRDHj53GRG4ybrG7V0vIgkC/h168XggHwve4L76sYsa3JLgc
d3wQJS7hzqTDc+Pid/8lH8/dw3mLQnt0TI17gaj78yUfVojDpy3qHRvwZ0gslA5c
RQIDAQAB
-----END PUBLIC KEY-----

私钥:
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEA5phQ1tPVuHnwovVXuMtO5sZn/YrOqTq/PsdESztntFDz2PUF
I0lIe8KsCcshjtRMPB5+6phvKDxMJqg3f2dA76T+muY9wNITWtp6/MkQKB2/vP6E
E5/D482UQlcoc91wxgmuouR5aeXmS/aKJQ8K+yPwdxHCqRhsbBij83RWetfjbPkv
JFTU2zQJfsZqCxBzMt03BI9IV7EqlrhkKLbZ9owbN9SV1GWClW5XdRDHj53GRG4y
brG7V0vIgkC/h168XggHwve4L76sYsa3JLgcd3wQJS7hzqTDc+Pid/8lH8/dw3mL
Qnt0TI17gaj78yUfVojDpy3qHRvwZ0gslA5cRQIDAQABAoIBACxZ7Wp0Ue3qXjMp
lxau290dGhE06my4JOJxNxx1L4wJ6ey3q6ZOyQcsuSQlEq5C/OqvPt/mM7L8bfUd
c5coh9/PzzyBvizg+uIFlZQbI+VjW2aBWWvg1a9x8esUkm4+kBs274TbBtMsabAA
mi9ohkcpcW2lV9hoHypnTtlbbeqwT7dmBd4F4fJArYXQwwLu69hP7xTpi2JJMt/8
aehB1tst8pprEPpwDdTVOwln1DUyCGfwHuwGUf13qwqk986R5ZaqnChSvci5K1tp
zqBAoSfciuqsW/7IGTG1Gh8j4m1n9LmXTlvBolW8tC7DVFNSb7hGOKVaw0f6Sqeg
wJwdyf0CgYEA57YQfWyP4uM3csnkpwtbnw27aAn7IV5SW9Mt91tQHe8HrNOPL84/
UI8EsSLlhkAE/7VufHgtpUqeOw4iMVN6uvV8Lx/hrPXD4kR4Jet+zOMK9JpAa+Hl
d9D+qL5cqRGMZuDC86s/1L65nJlyZXXJMWPXhrDgakn4rH5hvxI+i6MCgYEA/sRM
U6TOL8R4J9kMEdictKPyzfdrBQpgtqcfO/HSOtdEItVR5qyAurB2SOe1tlAZgTPc
Ia5aC51jrUrZt76ruZU5EZYCR9cyFyPeS84GkdbmeulIiiE5jvx5YtOR1vRm4Z7m
R5c7qXpPO04tJGYHR2/mp0pa4/75X9ttPJrN9vcCgYBf+verrKuRdUNDpkOzui2y
ndKSTwgak2KULM7uloGCVMAeI+g9CjcJ3KQ559WhnaU0cugYYQOvY1BV8A3T1tuQ
1B0jvBYUOh1w/aGzO3Bj2GxyU+75gTI3RngmV+w0EFPTTakTnE0th++E4b8ULg0w
C0Z8wYnEHW4HrbY5mooT9wKBgF0kNyN9ZURhd+xZlegQYXpJVkOm6SF2odUlVG3+
AvYwLWDuzHqhJo8aZKRS0kRNFIYAB8Lok1Mbv41jiCV9OBspSyv6w+qv6kg7fNIK
CKzY/HqDP1oAu6Ji+53965vCzro99cLGr7FOXhk4g5iDFLYxWwpeTMx+M32wI0e8
8QARAoGAcLpmONVDVIGcrotJJRVNZ+YLRXnl69SlxdGv1f/qKgpUjM7DiIbpQuln
3FoCSVvmpIQ6Rh0Iah9fVpzPc557lFPGQVPay6d7qaWj2MWAW69lAg4zJkpADbK1
l0Bznq8QIQuwlC+Ogn+AMW3dxdBVWCggCu13KnSjq/B8YFytxfM=
-----END RSA PRIVATE KEY-----
[Step 09] 生成耗时           : 14.31秒
▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄


▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀
======================== FINAL KEYS ========================
主密钥长度: 64字节 (512位)
密钥摘要: ff0da578cdc484f4...2421e65397cee482

========================== 格式化密钥 ===========================
ff0da5$78cdc4`84f496!eac1ba:765259`b07418@77e84d%ab37b7&d15420]ddb9bb(d00ce6<f53b45)7d9e2d%648625:fed91f(e549ba>a3e584}711d43^248024=21e653_97cee4!82

========================== RSA 密钥 ==========================
公钥摘要: -----BEGIN PUBLIC KEY-----
MIIBIjANBgkqh...
私钥摘要: -----BEGIN RSA PRIVATE KEY-----
MIIEogIB...

🔑 密钥ID: KEY-20250719-142649-FF0DA5

★ 安全应用场景:
  军用级通信加密 | 区块链根密钥 | 量子安全系统
  金融交易签名 | 数字身份认证 | 安全启动协议

▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
========================== 文件保存选项 ==========================
▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀
是否保存密钥文件? (y/n): y

▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
========================== 文件保存成功 ==========================
ZIP文件路径: *******\key.zip
▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀
包含文件:
  key.txt - 格式化密钥
  key.pem - RSA公钥
  key.key - RSA私钥
▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄

▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀
► 安全警告: 切勿存储此密钥于不安全的媒介!
► 最佳实践: 使用硬件安全模块(HSM)保护密钥
▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄

```
##📜 开源协议
#### 本项目采用 ​​MIT License​​ - 允许授权下的自由使用，但需保留版权声明并完全免责

```test
 ⚠️最终声明：请确保在合法范围内使用本系统，开发者对任何非法用途不承担任何责任⚠️
```
