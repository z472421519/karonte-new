# CFG 构建失败排查指南

## 问题位置

你选中的代码位于 [binary_dependency_graph.py:389-398](tool/bdg/binary_dependency_graph.py#L389-L398)，这是 Karonte 最容易失败的地方。

### 代码分析

```python
# 第389-390行：构建CFG（Control Flow Graph）
self._cfgs[b] = self._projects[b].analyses.CFG(
    collect_data_references=True,
    extra_cross_references=True
)
```

这段代码使用 **angr** 框架对二进制文件进行控制流图分析，是整个分析流程的关键步骤。

---

## 🔍 常见失败原因

### 1. **CFG 构建超时或卡住** ⭐ 最常见

**症状：**
- 程序长时间停留在 "Building XXX CFG (this may take some time)"
- CPU 占用100%但无进展
- 内存持续增长

**原因：**
- angr 在复杂函数上进行符号执行时陷入状态爆炸
- 二进制文件包含大量循环或递归
- 间接跳转过多导致路径爆炸

**解决方案：**

#### 方法1: 添加到黑名单（推荐）
```json
{
    "angr_explode_bins": [
        "httpd",          // 导致问题的二进制文件名
        "openvpn",
        "wpa_supplicant",
        "vpn"
    ]
}
```

#### 方法2: 修改 CFG 构建参数
编辑 [binary_dependency_graph.py:389](tool/bdg/binary_dependency_graph.py#L389)：

```python
# 原始代码（可能很慢）
self._cfgs[b] = self._projects[b].analyses.CFG(
    collect_data_references=True,
    extra_cross_references=True
)

# 修改为更快的配置
self._cfgs[b] = self._projects[b].analyses.CFGFast(
    normalize=True,
    data_references=False,  # 关闭数据引用收集
    cross_references=False   # 关闭交叉引用
)
```

#### 方法3: 添加超时机制
在第389行之前添加超时控制：

```python
import signal

def timeout_handler(signum, frame):
    raise TimeoutError("CFG construction timeout")

# 设置30分钟超时
signal.signal(signal.SIGALRM, timeout_handler)
signal.alarm(1800)  # 1800秒 = 30分钟

try:
    self._cfgs[b] = self._projects[b].analyses.CFG(
        collect_data_references=True,
        extra_cross_references=True
    )
finally:
    signal.alarm(0)  # 取消超时
```

---

### 2. **内存溢出 (OOM)**

**症状：**
- 系统内存耗尽
- 进程被 killed
- 错误信息: `MemoryError` 或 `Killed`

**原因：**
- 大型二进制文件（>10MB）
- CFG 节点过多
- 数据引用收集占用大量内存

**解决方案：**

#### 方法1: 增加系统交换空间
```bash
# Linux 系统
sudo fallocate -l 8G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
```

#### 方法2: 限制 angr 内存使用
```python
# 在 binary_dependency_graph.py 开头添加
import resource

# 限制最大内存为 8GB
resource.setrlimit(resource.RLIMIT_AS, (8 * 1024 * 1024 * 1024, -1))
```

#### 方法3: 使用 CFGFast 替代 CFG
```python
# CFGFast 内存占用更少
self._cfgs[b] = self._projects[b].analyses.CFGFast()
```

---

### 3. **二进制文件格式不支持**

**症状：**
- 错误: `CLE error: Cannot load binary`
- 错误: `Unsupported architecture`
- 立即抛出异常

**原因：**
- 二进制文件损坏
- 非标准 ELF 格式
- 加密或混淆的二进制文件
- 不支持的架构

**解决方案：**

#### 检查二进制文件
```bash
# 1. 检查文件类型
file /path/to/binary

# 2. 检查是否可执行
readelf -h /path/to/binary

# 3. 检查依赖
ldd /path/to/binary
```

#### 添加到黑名单
如果确认无法分析，添加到配置文件：
```json
{
    "angr_explode_bins": ["problematic_binary"]
}
```

---

### 4. **angr 版本兼容性问题**

**症状：**
- `AttributeError: 'CFG' object has no attribute 'XXX'`
- `TypeError: CFG() got an unexpected keyword argument`

**原因：**
- angr 版本不匹配
- API 变化

**解决方案：**

#### 检查 angr 版本
```bash
python3 -c "import angr; print(angr.__version__)"
```

应该是 `9.0.5739` 或相近版本。

#### 重新安装正确版本
```bash
pip3 uninstall angr claripy archinfo cle pyvex
pip3 install angr==9.0.5739 claripy==9.0.5739 archinfo==9.0.5739 \
             cle==9.0.5739 pyvex==9.0.5739
```

---

### 5. **特定二进制文件的 Bug**

**症状：**
- 特定二进制文件总是失败
- 其他二进制文件正常
- 错误信息不一致

**原因：**
- 二进制文件包含 angr 无法处理的特殊结构
- 间接跳转表错误
- PLT/GOT 解析失败

**解决方案：**

#### 启用详细日志
编辑 [binary_dependency_graph.py:19-20](tool/bdg/binary_dependency_graph.py#L19-L20)：

```python
# 原始代码（禁用angr日志）
angr.loggers.disable_root_logger()
angr.logging.disable(logging.ERROR)

# 修改为启用详细日志
angr.loggers.enable_root_logger()
angr.logging.set_level("DEBUG")  # 查看详细错误
```

#### 添加更详细的错误捕获
修改第399-401行：

```python
except Exception as e:
    log.warning(f"Failed to add {b}")
    log.error(f"Error details: {str(e)}")  # 添加这行
    log.error(f"Error type: {type(e).__name__}")  # 添加这行
    import traceback
    traceback.print_exc()  # 打印完整堆栈
    self._ignore_bins.append(bin_name)
```

---

## 🛠️ 调试步骤

### 步骤1: 识别失败的二进制文件

运行分析时观察日志：
```
[Karonte] Building httpd CFG (this may take some time)
# 如果卡在这里超过30分钟，说明 httpd 有问题
```

### 步骤2: 检查二进制文件

```bash
cd firmware/VENDOR/DEVICE/squashfs-root

# 检查问题二进制
file usr/bin/httpd
ls -lh usr/bin/httpd
readelf -h usr/bin/httpd
```

### 步骤3: 添加到黑名单测试

修改配置文件：
```json
{
    "angr_explode_bins": ["httpd"],  // 添加问题二进制
    ...
}
```

重新运行分析。

### 步骤4: 如果仍然失败，尝试其他方法

- 使用 CFGFast
- 添加超时机制
- 增加内存
- 更新 angr 版本

---

## 📊 性能优化建议

### 1. 使用 CFGFast（推荐用于大型固件）

**优点：**
- 速度快10-100倍
- 内存占用少
- 更稳定

**缺点：**
- 可能遗漏某些控制流
- 精度略低

**修改方法：**

编辑 [binary_dependency_graph.py:389](tool/bdg/binary_dependency_graph.py#L389)：

```python
# 方案1: 全部使用 CFGFast
self._cfgs[b] = self._projects[b].analyses.CFGFast(normalize=True)

# 方案2: 混合使用（小文件用CFG，大文件用CFGFast）
import os
file_size = os.path.getsize(b)
if file_size > 1024 * 1024:  # 大于1MB
    self._cfgs[b] = self._projects[b].analyses.CFGFast(normalize=True)
else:
    self._cfgs[b] = self._projects[b].analyses.CFG(
        collect_data_references=True,
        extra_cross_references=True
    )
```

### 2. 并行处理（谨慎使用）

如果有多个核心，可以尝试并行构建CFG：

```python
from multiprocessing import Pool

def build_cfg(binary_path):
    try:
        p = angr.Project(binary_path, auto_load_libs=False)
        cfg = p.analyses.CFGFast()
        return (binary_path, cfg)
    except:
        return (binary_path, None)

# 并行构建
with Pool(processes=2) as pool:  # 不要超过2，内存占用大
    results = pool.map(build_cfg, binary_list)
```

⚠️ **警告：** 并行处理会大幅增加内存占用。

### 3. 缓存 CFG 结果

修改代码以缓存已构建的CFG：

```python
import pickle

cfg_cache_file = f"/tmp/cfg_cache_{bin_name}.pk"

if os.path.exists(cfg_cache_file):
    # 加载缓存
    with open(cfg_cache_file, 'rb') as f:
        self._cfgs[b] = pickle.load(f)
    log.info(f"Loaded cached CFG for {bin_name}")
else:
    # 构建并缓存
    self._cfgs[b] = self._projects[b].analyses.CFG(...)
    with open(cfg_cache_file, 'wb') as f:
        pickle.dump(self._cfgs[b], f)
    log.info(f"Saved CFG cache for {bin_name}")
```

---

## 🚨 紧急快速修复

如果分析一直失败，使用这个快速修复补丁：

### 创建补丁文件

```bash
cat > cfg_fix.patch << 'EOF'
--- a/tool/bdg/binary_dependency_graph.py
+++ b/tool/bdg/binary_dependency_graph.py
@@ -386,8 +386,15 @@ class BinaryDependencyGraph:

                     log.info(f"Building {bin_name} CFG (this may take some time)")
                     # This might not work here
-                    self._cfgs[b] = self._projects[b].analyses.CFG(collect_data_references=True,
-                                                                   extra_cross_references=True)
+                    # 使用 CFGFast 替代，更快更稳定
+                    import os
+                    file_size = os.path.getsize(b)
+                    if file_size > 2 * 1024 * 1024:  # 大于2MB用CFGFast
+                        self._cfgs[b] = self._projects[b].analyses.CFGFast(normalize=True)
+                        log.info(f"Using CFGFast for large binary {bin_name}")
+                    else:
+                        self._cfgs[b] = self._projects[b].analyses.CFG(collect_data_references=True,
+                                                                       extra_cross_references=True)
                     memcplike = find_memcmp_like(self._projects[b], self._cfgs[b]) if blob else []

                     self._cpfs[b] = []
EOF

# 应用补丁
patch -p1 < cfg_fix.patch
```

---

## 📝 实际案例

### 案例1: Netgear 路由器固件

**问题：** httpd 二进制文件导致 CFG 构建卡住

**解决：**
```json
{
    "angr_explode_bins": ["httpd", "uhttpd", "mini_httpd"]
}
```

### 案例2: TP-Link 固件

**问题：** 内存不足，OOM killed

**解决：** 使用 CFGFast + 增加交换空间

### 案例3: D-Link 固件

**问题：** 特定二进制文件格式不支持

**解决：** 手动提取并使用 Ghidra 预分析，然后在配置中排除该文件

---

## ✅ 检查清单

在报告 Bug 前，请确认：

- [ ] 已检查 angr 版本 (`python3 -c "import angr; print(angr.__version__)"`)
- [ ] 已尝试添加到 `angr_explode_bins`
- [ ] 已检查系统内存是否充足
- [ ] 已启用详细日志查看错误信息
- [ ] 已检查二进制文件是否可读 (`file`, `readelf`)
- [ ] 已查看是否有类似的 GitHub Issues
- [ ] 已尝试 CFGFast 替代方案

---

## 📞 进一步帮助

如果以上方法都不奏效：

1. **查看 angr Issues：** https://github.com/angr/angr/issues
2. **Karonte Issues：** https://github.com/angr/karonte/issues
3. **提供以下信息：**
   - 固件类型和来源
   - 二进制文件信息 (`file` 输出)
   - 完整错误日志
   - angr 版本
   - 系统配置（内存、CPU）

---

## 🎯 总结

**CFG 构建失败的三大常见原因：**

1. **状态爆炸** → 添加到 `angr_explode_bins`
2. **内存不足** → 使用 CFGFast 或增加内存
3. **格式不支持** → 排除该二进制文件

**最推荐的解决方案：**
- ✅ 使用 CFGFast 替代 CFG（速度快、更稳定）
- ✅ 及时将问题二进制添加到黑名单
- ✅ 监控内存使用，及时中断失败的分析

---

*希望这份指南能帮助你解决 CFG 构建失败的问题！*
