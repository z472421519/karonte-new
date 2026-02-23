# 🎯 从这里开始！

## 欢迎使用 Karonte 固件分析工具

我已经为你创建了一套完整的文档和自动化工具，帮助你快速开始在新固件上进行实验。

---

## 📦 已创建的文档和工具

### 📚 文档（按推荐阅读顺序）

1. **[新手指南README.md](./新手指南README.md)** - 总览文档
   - 📖 文档索引和学习路径
   - 🎯 典型使用场景
   - 💡 最佳实践
   - 📞 获取帮助的方式

2. **[新固件分析流程.md](./新固件分析流程.md)** - 详细操作手册
   - 🔍 Karonte 工作原理深度解析
   - 📋 完整的11章操作流程
   - 🛠️ 环境准备和依赖安装
   - ⚙️ 配置文件详解
   - 🐛 常见问题和解决方案
   - 🎓 高级技巧（Pickle缓存、Blob固件分析）

3. **[快速参考.md](./快速参考.md)** - 速查手册
   - ⚡ 30秒快速开始
   - 📋 配置模板
   - 🔧 常用命令
   - 🐛 故障排查表

### 🛠️ 自动化工具

1. **`check_environment.sh`** - 环境检查脚本
   ```bash
   ./check_environment.sh
   ```
   - ✅ 检查 Python 版本和依赖
   - ✅ 检查系统资源（磁盘、内存）
   - ✅ 验证目录结构和关键文件

2. **`setup_new_firmware.sh`** - 固件准备自动化脚本
   ```bash
   ./setup_new_firmware.sh <厂商> <设备> <固件路径>
   ```
   - 🔄 自动创建目录结构
   - 📦 复制和提取固件
   - ⚙️ 生成配置文件
   - 🚀 创建运行脚本

---

## 🚀 三步快速开始

### 第一步：检查环境 ✅
```bash
./check_environment.sh
```

如果出现错误，按照提示安装依赖：
```bash
cd tool/
pip3 install -r requirements.txt
```

### 第二步：准备固件 📦
```bash
./setup_new_firmware.sh TP_Link Archer_C7 ~/Downloads/firmware.bin
```

这会自动：
- 创建 `firmware/TP_Link/Archer_C7/` 目录
- 提取固件（如果可能）
- 生成 `config/TP_Link/Archer_C7_analysis.json`
- 创建 `run_analysis_TP_Link_Archer_C7.sh` 运行脚本

### 第三步：运行分析 🔍
```bash
./run_analysis_TP_Link_Archer_C7.sh
```

查看结果：
```bash
cat results/TP_Link/Archer_C7/karonte_*.txt
```

---

## 📖 根据你的需求选择阅读路径

### 🎯 我是新手，想快速开始
1. 阅读 **[新手指南README.md](./新手指南README.md)** 的"5分钟快速开始"
2. 执行上面的"三步快速开始"
3. 遇到问题查看 **[快速参考.md](./快速参考.md)** 的"快速故障排查"

### 🎓 我想系统学习
1. 完整阅读 **[新固件分析流程.md](./新固件分析流程.md)** （约30分钟）
2. 理解 Karonte 的工作原理
3. 按照文档手动操作一次完整流程
4. 熟悉后使用自动化工具提高效率

### 🔬 我需要深入研究
1. 阅读 **[新固件分析流程.md](./新固件分析流程.md)** 的高级技巧章节
2. 阅读 [Karonte 论文](https://www.badnack.it/static/papers/University/karonte.pdf)
3. 研究 `tool/` 目录下的源码
4. 学习 angr 框架：https://docs.angr.io/

### 🆘 我遇到了问题
1. 查看 **[新固件分析流程.md](./新固件分析流程.md)** 第七章"常见问题处理"
2. 查看 **[快速参考.md](./快速参考.md)** 的故障排查表
3. 搜索 GitHub Issues
4. 查阅 **[新手指南README.md](./新手指南README.md)** 的"获取帮助"章节

---

## 📊 Karonte 工作原理（一图读懂）

```
固件镜像 (.bin)
      ↓
[固件提取]
   FirmAE Extractor
      ↓
文件系统 (squashfs-root/)
      ↓
[边界二进制文件发现 - BBF]
   识别网络暴露的二进制文件
   (httpd, telnetd, ftpd...)
      ↓
[二进制依赖图构建 - BDG]
   分析进程间通信（IPC）
   • 环境变量
   • 文件系统
   • 网络套接字
   • Setter/Getter
   • 语义分析
      ↓
[漏洞发现 - BF]
   污点分析追踪数据流
   检测：
   • 缓冲区溢出
   • 命令注入
   • 路径遍历
   • 格式化字符串
      ↓
分析报告 (/tmp/Karonte.txt_*)
```

---

## 🎯 典型工作流程

### 场景1: 分析路由器固件（最常见）

```bash
# 1. 检查环境
./check_environment.sh

# 2. 自动准备
./setup_new_firmware.sh Netgear R7000 ~/firmware/R7000.chk

# 3. 运行分析
./run_analysis_Netgear_R7000.sh

# 4. 查看漏洞
grep -i "alert\|vulnerability" results/Netgear/R7000/karonte_*.txt
```

### 场景2: 手动分析（高级用户）

```bash
# 1. 手动提取固件
cd firmware/Vendor/Device/
binwalk -e firmware.bin

# 2. 创建配置
nano config/Vendor/device.json

# 3. 运行
python tool/karonte.py config/Vendor/device.json results/output.txt

# 4. 分析结果
cat results/output.txt
```

### 场景3: 分析Blob固件（bootloader）

```bash
# 1. 使用 IDA/Ghidra 找到关键地址
#    - base_addr: 加载基址
#    - eg_source_addr: 输入函数地址

# 2. 创建 Blob 配置（参考 快速参考.md）

# 3. 运行分析
python tool/karonte.py config/blob.json
```

---

## 📋 配置文件快速参考

### Linux 固件（路由器、IoT设备）
```json
{
    "fw_path": "./firmware/VENDOR/DEVICE/squashfs-root",
    "bin": [],
    "stats": "True",
    "pickle_parsers": "",
    "angr_explode_bins": ["openvpn", "vpn"],
    "data_keys": [],
    "glob_var": [],
    "arch": "",
    "only_string": "False"
}
```

### Blob 固件（bootloader）
```json
{
    "bin": ["./firmware/bootloader.bin"],
    "base_addr": "0x80000000",
    "eg_source_addr": "0x80001234",
    "arch": "ARM",
    "fw_path": "",
    "stats": "True",
    "pickle_parsers": "",
    "data_keys": [],
    "angr_explode_bins": [],
    "glob_var": [],
    "only_string": "False"
}
```

---

## 💡 最佳实践

### ✅ 推荐
- 从小型固件开始练习
- 使用自动化脚本提高效率
- 保持良好的目录结构
- 记录分析笔记和发现
- 后台运行长时间分析

### ❌ 避免
- 不要在 root 下运行
- 不要同时分析多个大型固件
- 不要忽略环境检查的警告
- 不要在生产环境运行

---

## 🐛 快速故障排查

| 问题 | 快速解决 | 详细说明 |
|------|---------|---------|
| 环境检查失败 | `cd tool && pip3 install -r requirements.txt` | [新固件分析流程.md](./新固件分析流程.md) 第二章 |
| 固件提取失败 | `binwalk -e firmware.bin` | [新固件分析流程.md](./新固件分析流程.md) 第七章 7.2 |
| 分析卡住 | 添加问题二进制到 `angr_explode_bins` | [新固件分析流程.md](./新固件分析流程.md) 第七章 7.1 |
| 内存不足 | 减少 `tool/utils.py` 的 `MAX_THREADS` | [新固件分析流程.md](./新固件分析流程.md) 第七章 7.3 |

---

## 📞 获取帮助

### 问题优先级
1. 🔍 查阅文档（90%的问题都有答案）
   - [新固件分析流程.md](./新固件分析流程.md) - 详细手册
   - [快速参考.md](./快速参考.md) - 速查表
   - [新手指南README.md](./新手指南README.md) - 总览

2. 🌐 在线资源
   - GitHub Issues: https://github.com/angr/karonte/issues
   - angr 文档: https://docs.angr.io/
   - 论文: [IEEE S&P 2020](https://www.badnack.it/static/papers/University/karonte.pdf)

3. 💬 社区支持
   - 提交 GitHub Issue（附带完整日志和配置）
   - angr Slack 频道

---

## ✅ 检查清单

在开始分析前，请确认：

- [ ] ✅ 已运行 `./check_environment.sh` 且无错误
- [ ] ✅ 固件文件完整且可访问
- [ ] ✅ 磁盘空间充足（>10GB）
- [ ] ✅ 内存充足（推荐16GB+）
- [ ] ✅ 已阅读相关文档
- [ ] ✅ 配置文件路径正确
- [ ] ✅ 准备好等待分析完成（可能需要数小时）

---

## 🎉 现在开始你的第一次分析！

```bash
# 复制这些命令到终端运行：

# 1️⃣ 检查环境
./check_environment.sh

# 2️⃣ 准备固件（替换为你的实际参数）
./setup_new_firmware.sh YOUR_VENDOR YOUR_DEVICE /path/to/firmware.bin

# 3️⃣ 运行分析（使用生成的脚本）
./run_analysis_YOUR_VENDOR_YOUR_DEVICE.sh

# 4️⃣ 查看结果
cat results/YOUR_VENDOR/YOUR_DEVICE/karonte_*.txt
```

---

## 📚 文档结构总览

```
karonte/
├── START_HERE.md                 ← 你在这里！（入口文档）
├── 新手指南README.md             ← 学习路径和最佳实践
├── 新固件分析流程.md             ← 完整详细操作手册（12K）
├── 快速参考.md                   ← 命令和配置速查表
├── check_environment.sh          ← 环境检查工具
├── setup_new_firmware.sh         ← 固件准备自动化工具
├── README.md                     ← 原始项目说明
├── tool/                         ← Karonte 源码
├── config/                       ← 配置文件目录
├── firmware/                     ← 固件文件目录
└── results/                      ← 分析结果目录
```

---

## 🌟 成功提示

分析成功后，你会看到：

```
[Karonte] Finished, results in /tmp/Karonte.txt_42

分析完成！
结果保存在: results/VENDOR/DEVICE/karonte_20260223_143022.txt
```

查看发现的漏洞：
```bash
grep -i "alert" results/VENDOR/DEVICE/karonte_*.txt
grep -i "buffer overflow\|command injection" results/VENDOR/DEVICE/karonte_*.txt
```

---

## 📈 学习进度建议

### 第1天：环境和入门
- [ ] 阅读本文档（START_HERE.md）
- [ ] 运行环境检查
- [ ] 使用自动化工具完成第一次分析

### 第2-3天：理解原理
- [ ] 阅读 [新固件分析流程.md](./新固件分析流程.md)
- [ ] 手动操作一次完整流程
- [ ] 理解配置参数含义

### 第4-7天：实践积累
- [ ] 分析3-5个不同的固件
- [ ] 尝试调整配置参数
- [ ] 记录遇到的问题和解决方法

### 第2周及以后：深入研究
- [ ] 阅读 Karonte 论文
- [ ] 学习 angr 框架
- [ ] 研究源码
- [ ] 尝试修改检测规则

---

## 🎓 相关资源

### 必读
- ⭐ [Karonte 论文 (IEEE S&P 2020)](https://www.badnack.it/static/papers/University/karonte.pdf)
- ⭐ [angr 文档](https://docs.angr.io/)

### 工具
- [binwalk](https://github.com/ReFirmLabs/binwalk) - 固件提取
- [Ghidra](https://ghidra-sre.org/) - 逆向工程（免费）
- [IDA Pro](https://hex-rays.com/ida-pro/) - 反汇编器（商业）

### 数据集
- [Karonte 固件数据集](https://drive.google.com/file/d/1-VOf-tEpu4LIgyDyZr7bBZCDK-K2DHaj/view)

---

**准备好了吗？开始你的第一次固件安全分析吧！🚀**

*有问题随时查阅文档或寻求社区帮助！*

---

*文档版本: 1.0*
*创建日期: 2026-02-23*
*适用版本: Karonte master (Python 3)*
