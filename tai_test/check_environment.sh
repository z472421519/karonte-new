#!/bin/bash
# Karonte 环境检查脚本

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Karonte 环境检查${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

ERRORS=0
WARNINGS=0

# 1. 检查 Python 版本
echo -e "${YELLOW}[1/8] 检查 Python 版本...${NC}"
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
    PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
    PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)

    if [ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -ge 8 ]; then
        echo -e "${GREEN}✓ Python $PYTHON_VERSION${NC}"
    else
        echo -e "${RED}✗ Python 版本过低: $PYTHON_VERSION (需要 >= 3.8)${NC}"
        ERRORS=$((ERRORS+1))
    fi
else
    echo -e "${RED}✗ Python3 未安装${NC}"
    ERRORS=$((ERRORS+1))
fi
echo ""

# 2. 检查 pip
echo -e "${YELLOW}[2/8] 检查 pip...${NC}"
if command -v pip3 &> /dev/null; then
    PIP_VERSION=$(pip3 --version | awk '{print $2}')
    echo -e "${GREEN}✓ pip $PIP_VERSION${NC}"
else
    echo -e "${RED}✗ pip3 未安装${NC}"
    ERRORS=$((ERRORS+1))
fi
echo ""

# 3. 检查关键 Python 包
echo -e "${YELLOW}[3/8] 检查关键 Python 包...${NC}"

REQUIRED_PACKAGES=(
    "angr"
    "claripy"
    "archinfo"
    "cle"
    "pyvex"
    "networkx"
    "numpy"
)

for package in "${REQUIRED_PACKAGES[@]}"; do
    if python3 -c "import $package" 2>/dev/null; then
        VERSION=$(python3 -c "import $package; print($package.__version__)" 2>/dev/null || echo "unknown")
        echo -e "${GREEN}  ✓ $package ($VERSION)${NC}"
    else
        echo -e "${RED}  ✗ $package 未安装${NC}"
        ERRORS=$((ERRORS+1))
    fi
done
echo ""

# 4. 检查 binwalk（可选）
echo -e "${YELLOW}[4/8] 检查 binwalk (可选)...${NC}"
if command -v binwalk &> /dev/null; then
    BINWALK_VERSION=$(binwalk --help | head -1 | awk '{print $3}' || echo "unknown")
    echo -e "${GREEN}✓ binwalk $BINWALK_VERSION${NC}"
else
    echo -e "${YELLOW}⚠ binwalk 未安装 (可选，但推荐安装)${NC}"
    echo "  安装: sudo apt-get install binwalk"
    WARNINGS=$((WARNINGS+1))
fi
echo ""

# 5. 检查磁盘空间
echo -e "${YELLOW}[5/8] 检查磁盘空间...${NC}"
AVAILABLE_SPACE=$(df -BG . | tail -1 | awk '{print $4}' | sed 's/G//')
if [ "$AVAILABLE_SPACE" -gt 10 ]; then
    echo -e "${GREEN}✓ 可用磁盘空间: ${AVAILABLE_SPACE}GB${NC}"
else
    echo -e "${YELLOW}⚠ 磁盘空间较少: ${AVAILABLE_SPACE}GB (建议 >10GB)${NC}"
    WARNINGS=$((WARNINGS+1))
fi
echo ""

# 6. 检查内存
echo -e "${YELLOW}[6/8] 检查系统内存...${NC}"
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    TOTAL_MEM=$(free -g | awk '/^Mem:/{print $2}')
    if [ "$TOTAL_MEM" -gt 8 ]; then
        echo -e "${GREEN}✓ 系统内存: ${TOTAL_MEM}GB${NC}"
    else
        echo -e "${YELLOW}⚠ 内存较少: ${TOTAL_MEM}GB (建议 >16GB)${NC}"
        WARNINGS=$((WARNINGS+1))
    fi
elif [[ "$OSTYPE" == "darwin"* ]]; then
    TOTAL_MEM=$(sysctl -n hw.memsize | awk '{print int($1/1024/1024/1024)}')
    if [ "$TOTAL_MEM" -gt 8 ]; then
        echo -e "${GREEN}✓ 系统内存: ${TOTAL_MEM}GB${NC}"
    else
        echo -e "${YELLOW}⚠ 内存较少: ${TOTAL_MEM}GB (建议 >16GB)${NC}"
        WARNINGS=$((WARNINGS+1))
    fi
else
    echo -e "${YELLOW}⚠ 无法检测内存（操作系统不支持）${NC}"
    WARNINGS=$((WARNINGS+1))
fi
echo ""

# 7. 检查目录结构
echo -e "${YELLOW}[7/8] 检查目录结构...${NC}"
REQUIRED_DIRS=(
    "tool"
    "config"
    "firmware"
)

for dir in "${REQUIRED_DIRS[@]}"; do
    if [ -d "$dir" ]; then
        echo -e "${GREEN}  ✓ $dir/${NC}"
    else
        echo -e "${RED}  ✗ $dir/ 目录不存在${NC}"
        ERRORS=$((ERRORS+1))
    fi
done
echo ""

# 8. 检查关键文件
echo -e "${YELLOW}[8/8] 检查关键文件...${NC}"
REQUIRED_FILES=(
    "tool/karonte.py"
    "tool/requirements.txt"
    "tool/utils.py"
)

for file in "${REQUIRED_FILES[@]}"; do
    if [ -f "$file" ]; then
        echo -e "${GREEN}  ✓ $file${NC}"
    else
        echo -e "${RED}  ✗ $file 不存在${NC}"
        ERRORS=$((ERRORS+1))
    fi
done
echo ""

# 总结
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}检查完成${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

if [ $ERRORS -eq 0 ] && [ $WARNINGS -eq 0 ]; then
    echo -e "${GREEN}✓ 所有检查通过！环境已准备就绪。${NC}"
    echo ""
    echo "下一步："
    echo "  1. 运行: ./setup_new_firmware.sh VENDOR DEVICE FIRMWARE_PATH"
    echo "  2. 或查看: cat 快速参考.md"
    exit 0
elif [ $ERRORS -eq 0 ]; then
    echo -e "${YELLOW}⚠ 发现 $WARNINGS 个警告${NC}"
    echo "环境基本可用，但建议解决上述警告"
    echo ""
    echo "下一步："
    echo "  1. 运行: ./setup_new_firmware.sh VENDOR DEVICE FIRMWARE_PATH"
    exit 0
else
    echo -e "${RED}✗ 发现 $ERRORS 个错误和 $WARNINGS 个警告${NC}"
    echo ""
    echo "请先解决以下问题："
    echo ""

    if ! command -v python3 &> /dev/null; then
        echo "1. 安装 Python 3.8+:"
        echo "   Ubuntu/Debian: sudo apt-get install python3 python3-pip"
        echo "   macOS: brew install python3"
        echo ""
    fi

    if [ $ERRORS -gt 0 ]; then
        echo "2. 安装 Python 依赖:"
        echo "   cd tool/"
        echo "   pip3 install -r requirements.txt"
        echo ""
    fi

    if ! command -v binwalk &> /dev/null; then
        echo "3. (可选) 安装 binwalk:"
        echo "   Ubuntu/Debian: sudo apt-get install binwalk"
        echo "   macOS: brew install binwalk"
        echo ""
    fi

    exit 1
fi
