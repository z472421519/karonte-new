# Karonte 新固件分析 - 新手指南

欢迎！这份指南将帮助你快速开始使用 Karonte 分析新固件。

## 📚 文档索引

我已经为你准备了以下文档和工具：

| 文件名 | 用途 | 适用人群 |
|-------|------|---------|
| [新固件分析流程.md](./新固件分析流程.md) | 完整详细的操作流程和原理说明 | 所有用户（必读）|
| [快速参考.md](./快速参考.md) | 快速命令和配置速查表 | 有一定基础的用户 |
| `setup_new_firmware.sh` | 自动化固件准备脚本 | 想要快速开始的用户 |
| `check_environment.sh` | 环境检查脚本 | 所有用户（首次使用必运行）|

---

## 🚀 5分钟快速开始

### 步骤 1: 检查环境
```bash
./check_environment.sh
```

如果看到错误，请按照提示安装缺失的依赖。

### 步骤 2: 准备固件
```bash
./setup_new_firmware.sh 厂商名 设备名 /path/to/firmware.bin
```

**示例：**
```bash
./setup_new_firmware.sh TP_Link Archer_C7 ~/Downloads/archer_c7_v5.bin
```

### 步骤 3: 运行分析
```bash
# 脚本会自动生成运行脚本
./run_analysis_TP_Link_Archer_C7.sh
```

### 步骤 4: 查看结果
```bash
cat results/TP_Link/Archer_C7/karonte_*.txt
```

---

## 📖 学习路径

### 🎯 路径1: 快速实践型（推荐新手）

1. ✅ 运行 `./check_environment.sh` 检查环境
2. ✅ 使用 `./setup_new_firmware.sh` 准备一个简单的固件
3. ✅ 运行生成的分析脚本
4. ✅ 查看 [快速参考.md](./快速参考.md) 了解常用命令
5. ✅ 遇到问题时查阅 [新固件分析流程.md](./新固件分析流程.md) 的"常见问题处理"章节

### 🎓 路径2: 系统学习型

1. ✅ 完整阅读 [新固件分析流程.md](./新固件分析流程.md)
2. ✅ 理解 Karonte 的工作原理（第一章）
3. ✅ 按照文档手动操作一次完整流程
4. ✅ 使用自动化脚本提高效率
5. ✅ 学习高级技巧（Pickle缓存、Blob固件分析等）

### 🔬 路径3: 研究深入型

1. ✅ 阅读 Karonte 论文：[IEEE S&P 2020](https://www.badnack.it/static/papers/University/karonte.pdf)
2. ✅ 研究源码：`tool/` 目录下的模块
3. ✅ 理解 angr 框架：https://docs.angr.io/
4. ✅ 尝试修改分析参数和配置
5. ✅ 为特定漏洞类型定制检测规则

---

## 🎯 典型使用场景

### 场景1: 分析路由器固件
```bash
# 1. 准备固件
./setup_new_firmware.sh Netgear R7000 ~/Downloads/R7000-V1.0.9.88.chk

# 2. 运行分析（Linux固件会自动提取）
./run_analysis_Netgear_R7000.sh

# 3. 查看发现的漏洞
grep -i "alert" results/Netgear/R7000/karonte_*.txt
```

### 场景2: 分析IoT设备固件
```bash
# 1. 手动提取固件（如果自动提取失败）
cd firmware/Vendor/Device/
binwalk -e device_firmware.bin

# 2. 创建配置文件
nano config/Vendor/device.json
# 设置 fw_path 指向 squashfs-root 目录

# 3. 运行分析
python tool/karonte.py config/Vendor/device.json
```

### 场景3: 分析Bootloader
```bash
# 1. 使用IDA/Ghidra分析获取关键地址
# - base_addr: 加载基址
# - eg_source_addr: 输入函数地址

# 2. 创建Blob配置
cat > config/bootloader.json << 'EOF'
{
    "bin": ["./firmware/bootloader.bin"],
    "base_addr": "0x08000000",
    "eg_source_addr": "0x08001234",
    "arch": "ARM",
    "fw_path": "",
    "stats": "True",
    ...
}
EOF

# 3. 运行分析
python tool/karonte.py config/bootloader.json
```

---

## 🛠️ 工具使用说明

### `check_environment.sh` - 环境检查

**功能：** 检查所有必需的依赖和系统资源

**使用：**
```bash
./check_environment.sh
```

**检查项目：**
- Python 版本
- Python 包（angr、networkx等）
- binwalk（可选）
- 磁盘空间
- 系统内存
- 目录结构
- 关键文件

### `setup_new_firmware.sh` - 固件准备自动化

**功能：** 自动创建目录、提取固件、生成配置文件和运行脚本

**语法：**
```bash
./setup_new_firmware.sh <厂商> <设备> <固件路径>
```

**示例：**
```bash
./setup_new_firmware.sh DLink DIR-868L /home/user/firmware.bin
```

**生成内容：**
- `firmware/DLink/DIR-868L/` - 固件文件
- `config/DLink/DIR-868L_analysis.json` - 配置文件
- `results/DLink/DIR-868L/` - 结果目录
- `run_analysis_DLink_DIR-868L.sh` - 运行脚本

---

## 💡 最佳实践建议

### ✅ DO（推荐）

1. **从简单固件开始**
   - 先分析小型IoT设备固件（几MB）
   - 熟悉流程后再分析复杂路由器固件

2. **保持良好的目录结构**
   ```
   karonte/
   ├── firmware/
   │   ├── Vendor1/
   │   │   ├── Device1/
   │   │   └── Device2/
   │   └── Vendor2/
   ├── config/
   │   ├── Vendor1/
   │   └── Vendor2/
   └── results/
       ├── Vendor1/
       └── Vendor2/
   ```

3. **使用配置文件版本控制**
   ```bash
   git add config/Vendor/device_v1.json
   git commit -m "Add config for Device v1"
   ```

4. **记录分析笔记**
   - 创建 `results/Vendor/Device/notes.md`
   - 记录发现的漏洞和分析心得

5. **后台运行长时间分析**
   ```bash
   nohup ./run_analysis_XXX.sh > analysis.log 2>&1 &
   tail -f analysis.log
   ```

### ❌ DON'T（避免）

1. **不要直接在 root 权限下运行**
   - Karonte 不需要 root 权限
   - 避免潜在的安全风险

2. **不要同时分析多个大型固件**
   - 会耗尽系统资源
   - 导致分析失败或系统崩溃

3. **不要忽略警告信息**
   - 固件提取失败会影响分析结果
   - 架构检测错误会导致分析不准确

4. **不要在生产环境运行**
   - CPU和内存占用高
   - 可能影响其他服务

5. **不要立即删除中间文件**
   - 保留 pickle 文件可以加速后续分析
   - 保留提取的固件可以手动检查

---

## 🔍 常见问题快速查找

### Q1: 环境检查失败怎么办？
→ 查看 [新固件分析流程.md](./新固件分析流程.md) 第二章"环境准备"

### Q2: 固件提取失败？
→ 查看 [新固件分析流程.md](./新固件分析流程.md) 第七章 7.2

### Q3: 分析卡住不动？
→ 查看 [新固件分析流程.md](./新固件分析流程.md) 第七章 7.1

### Q4: 没有发现边界二进制文件？
→ 查看 [新固件分析流程.md](./新固件分析流程.md) 第七章 7.2

### Q5: 如何解读分析结果？
→ 查看 [新固件分析流程.md](./新固件分析流程.md) 第六章"结果分析"

### Q6: 配置参数太多不知道怎么填？
→ 查看 [快速参考.md](./快速参考.md) 的"最小配置模板"

---

## 📊 预期时间表

| 阶段 | 预计时间 | 说明 |
|------|---------|------|
| 环境准备 | 10-30分钟 | 首次安装依赖 |
| 固件准备 | 5-10分钟 | 提取和配置 |
| 分析运行 | 5分钟 - 12小时 | 取决于固件复杂度 |
| 结果分析 | 30分钟 - 2小时 | 理解和验证发现 |

**总计（首次使用）：** 1-15小时

**总计（熟练后）：** 15分钟 - 12小时（主要是分析等待时间）

---

## 🎓 进阶学习资源

### 官方资源
- **论文：** [Karonte - IEEE S&P 2020](https://www.badnack.it/static/papers/University/karonte.pdf)
- **GitHub：** https://github.com/angr/karonte
- **固件数据集：** [Google Drive](https://drive.google.com/file/d/1-VOf-tEpu4LIgyDyZr7bBZCDK-K2DHaj/view)

### 相关工具
- **angr：** https://angr.io/ (二进制分析框架)
- **binwalk：** https://github.com/ReFirmLabs/binwalk (固件提取)
- **Ghidra：** https://ghidra-sre.org/ (逆向工程)
- **IDA Pro：** https://hex-rays.com/ida-pro/ (商业反汇编器)

### 背景知识
- 嵌入式系统安全
- 二进制分析基础
- 符号执行（Symbolic Execution）
- 污点分析（Taint Analysis）
- 进程间通信（IPC）机制

---

## 📞 获取帮助

### 遇到问题？按顺序尝试：

1. 查阅 [新固件分析流程.md](./新固件分析流程.md) 的"常见问题处理"章节
2. 查看 [快速参考.md](./快速参考.md) 的"快速故障排查"表格
3. 搜索 GitHub Issues: https://github.com/angr/karonte/issues
4. 阅读 angr 文档: https://docs.angr.io/
5. 在 GitHub 提交新 Issue

### 报告问题时请提供：
- 操作系统和版本
- Python 版本
- angr 版本
- 固件类型和大小
- 完整的错误日志
- 配置文件内容

---

## ✅ 成功案例模板

分析完成后，建议记录：

```markdown
# [厂商] [设备] 固件分析报告

## 基本信息
- 固件版本: X.X.X
- 固件大小: XXX MB
- 架构: ARM/MIPS/x86
- 分析日期: YYYY-MM-DD

## 分析配置
\`\`\`json
{配置文件内容}
\`\`\`

## 分析结果
- 分析时间: X 小时
- 边界二进制: X 个
- 二进制依赖关系: X 条
- 发现的漏洞: X 个

## 发现的漏洞列表
1. [类型] 在 [二进制] 的 [函数]
2. ...

## 漏洞详情
### 漏洞1: [标题]
- **类型:** Buffer Overflow / Command Injection / ...
- **位置:** /usr/bin/xxx at 0x401234
- **严重程度:** 高/中/低
- **描述:** ...
- **数据流:** ...

## 建议
- 修复建议
- 缓解措施
\`\`\`

---

## 🎉 开始你的第一次分析

准备好了吗？执行以下命令开始：

```bash
# 1. 检查环境
./check_environment.sh

# 2. 准备你的固件
./setup_new_firmware.sh <厂商> <设备> <固件路径>

# 3. 开始分析
./run_analysis_<厂商>_<设备>.sh

# 4. 享受探索漏洞的过程！
```

**祝你好运！🚀**

---

*最后更新: 2026-02-23*
*如有问题或建议，欢迎反馈！*
