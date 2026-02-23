#!/bin/bash
# Karonte 新固件分析自动化脚本
# 用法: ./setup_new_firmware.sh VENDOR DEVICE FIRMWARE_PATH

set -e

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 检查参数
if [ "$#" -lt 3 ]; then
    echo -e "${RED}用法: $0 VENDOR DEVICE FIRMWARE_PATH${NC}"
    echo "示例: $0 TP_Link Archer_C7 /path/to/firmware.bin"
    exit 1
fi

VENDOR=$1
DEVICE=$2
FIRMWARE_PATH=$3
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Karonte 新固件分析准备脚本${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "厂商: $VENDOR"
echo "设备: $DEVICE"
echo "固件路径: $FIRMWARE_PATH"
echo ""

# 1. 检查固件文件是否存在
if [ ! -f "$FIRMWARE_PATH" ]; then
    echo -e "${RED}错误: 固件文件不存在: $FIRMWARE_PATH${NC}"
    exit 1
fi

# 2. 创建目录结构
echo -e "${YELLOW}[1/6] 创建目录结构...${NC}"
mkdir -p "$SCRIPT_DIR/firmware/$VENDOR/$DEVICE"
mkdir -p "$SCRIPT_DIR/config/$VENDOR"
mkdir -p "$SCRIPT_DIR/results/$VENDOR/$DEVICE"

# 3. 复制固件文件
echo -e "${YELLOW}[2/6] 复制固件文件...${NC}"
FIRMWARE_NAME=$(basename "$FIRMWARE_PATH")
cp "$FIRMWARE_PATH" "$SCRIPT_DIR/firmware/$VENDOR/$DEVICE/"
echo "固件已复制到: firmware/$VENDOR/$DEVICE/$FIRMWARE_NAME"

# 4. 提取固件
echo -e "${YELLOW}[3/6] 尝试提取固件...${NC}"
EXTRACT_DIR="$SCRIPT_DIR/firmware/$VENDOR/$DEVICE/_${FIRMWARE_NAME}.extracted"

# 检查是否安装 binwalk
if command -v binwalk &> /dev/null; then
    echo "使用 binwalk 提取固件..."
    cd "$SCRIPT_DIR/firmware/$VENDOR/$DEVICE"
    binwalk -e "$FIRMWARE_NAME" || echo -e "${YELLOW}警告: binwalk 提取可能失败${NC}"

    # 查找 squashfs-root 目录
    ROOTFS=$(find "$EXTRACT_DIR" -type d -name "squashfs-root" | head -1)

    if [ -z "$ROOTFS" ]; then
        # 尝试查找其他可能的根目录
        ROOTFS=$(find "$EXTRACT_DIR" -type d \( -name "rootfs" -o -name "root" \) | head -1)
    fi

    if [ -n "$ROOTFS" ]; then
        echo -e "${GREEN}✓ 找到文件系统根目录: $ROOTFS${NC}"
        FW_PATH_FOR_CONFIG="./firmware/$VENDOR/$DEVICE/_${FIRMWARE_NAME}.extracted/$(basename $ROOTFS)"
        USE_AUTO_EXTRACT="false"
    else
        echo -e "${YELLOW}警告: 未找到标准的文件系统根目录${NC}"
        echo "将使用 Karonte 内置的自动提取功能"
        FW_PATH_FOR_CONFIG="./firmware/$VENDOR/$DEVICE/$FIRMWARE_NAME"
        USE_AUTO_EXTRACT="true"
    fi
else
    echo -e "${YELLOW}警告: binwalk 未安装，将使用 Karonte 内置提取功能${NC}"
    echo "如需手动提取，请安装 binwalk: sudo apt-get install binwalk"
    FW_PATH_FOR_CONFIG="./firmware/$VENDOR/$DEVICE/$FIRMWARE_NAME"
    USE_AUTO_EXTRACT="true"
fi

cd "$SCRIPT_DIR"

# 5. 检测架构（如果已提取）
echo -e "${YELLOW}[4/6] 检测固件架构...${NC}"
DETECTED_ARCH="unknown"
if [ "$USE_AUTO_EXTRACT" = "false" ]; then
    # 尝试检测架构
    for bindir in "$ROOTFS/bin" "$ROOTFS/sbin" "$ROOTFS/usr/bin" "$ROOTFS/usr/sbin"; do
        if [ -d "$bindir" ]; then
            for binary in "$bindir"/*; do
                if [ -f "$binary" ] && [ -x "$binary" ]; then
                    ARCH_INFO=$(file "$binary" | head -1)
                    if echo "$ARCH_INFO" | grep -qi "ARM"; then
                        if echo "$ARCH_INFO" | grep -qi "aarch64\|ARM64"; then
                            DETECTED_ARCH="AARCH64"
                        else
                            DETECTED_ARCH="ARM"
                        fi
                        break 2
                    elif echo "$ARCH_INFO" | grep -qi "MIPS"; then
                        if echo "$ARCH_INFO" | grep -qi "MIPS64"; then
                            DETECTED_ARCH="MIPS64"
                        else
                            DETECTED_ARCH="MIPS"
                        fi
                        break 2
                    elif echo "$ARCH_INFO" | grep -qi "x86-64\|x86_64"; then
                        DETECTED_ARCH="x86_64"
                        break 2
                    elif echo "$ARCH_INFO" | grep -qi "80386\|i386"; then
                        DETECTED_ARCH="x86"
                        break 2
                    fi
                fi
            done
        fi
    done
    echo "检测到架构: $DETECTED_ARCH"
else
    echo "跳过架构检测（固件未提取）"
fi

# 6. 生成配置文件
echo -e "${YELLOW}[5/6] 生成配置文件...${NC}"
CONFIG_FILE="$SCRIPT_DIR/config/$VENDOR/${DEVICE}_analysis.json"

cat > "$CONFIG_FILE" << EOF
{
    "fw_path": "$FW_PATH_FOR_CONFIG",
    "bin": [],
    "pickle_parsers": "",
    "stats": "True",
    "data_keys": [],
    "angr_explode_bins": [
        "openvpn",
        "wpa_supplicant",
        "vpn",
        "dns",
        "ip",
        "log",
        "qemu-arm-static",
        "dhcp6-multi"
    ],
    "glob_var": [],
    "arch": "",
    "only_string": "False"
}
EOF

echo -e "${GREEN}✓ 配置文件已创建: $CONFIG_FILE${NC}"

# 7. 生成运行脚本
echo -e "${YELLOW}[6/6] 生成运行脚本...${NC}"
RUN_SCRIPT="$SCRIPT_DIR/run_analysis_${VENDOR}_${DEVICE}.sh"

cat > "$RUN_SCRIPT" << EOF
#!/bin/bash
# 自动生成的分析脚本
# 设备: $VENDOR $DEVICE
# 生成时间: $(date)

SCRIPT_DIR="\$(cd "\$(dirname "\${BASH_SOURCE[0]}")" && pwd)"
cd "\$SCRIPT_DIR"

echo "开始分析 $VENDOR $DEVICE 固件..."
echo "配置文件: config/$VENDOR/${DEVICE}_analysis.json"
echo ""

# 运行 Karonte
TIMESTAMP=\$(date +%Y%m%d_%H%M%S)
LOG_FILE="\$SCRIPT_DIR/results/$VENDOR/$DEVICE/karonte_\$TIMESTAMP.txt"

echo "日志文件: \$LOG_FILE"
echo ""

python tool/karonte.py \\
    "config/$VENDOR/${DEVICE}_analysis.json" \\
    "\$LOG_FILE"

echo ""
echo "=========================================="
echo "分析完成！"
echo "结果保存在: \$LOG_FILE"
echo "=========================================="
echo ""
echo "查看结果:"
echo "  cat \$LOG_FILE"
EOF

chmod +x "$RUN_SCRIPT"
echo -e "${GREEN}✓ 运行脚本已创建: $RUN_SCRIPT${NC}"

# 8. 总结
echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}准备完成！${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "目录结构:"
echo "  固件: firmware/$VENDOR/$DEVICE/"
echo "  配置: $CONFIG_FILE"
echo "  结果: results/$VENDOR/$DEVICE/"
echo ""

if [ "$USE_AUTO_EXTRACT" = "false" ]; then
    echo -e "${GREEN}固件已提取到:${NC}"
    echo "  $FW_PATH_FOR_CONFIG"
    echo ""
    echo "文件系统检查:"
    echo "  ls -la $ROOTFS"
    echo ""
fi

echo -e "${YELLOW}下一步操作:${NC}"
echo ""
echo "1. 检查配置文件（如有需要可手动编辑）:"
echo "   nano $CONFIG_FILE"
echo ""
echo "2. 运行分析:"
echo "   ./$RUN_SCRIPT"
echo ""
echo "   或者直接运行:"
echo "   python tool/karonte.py config/$VENDOR/${DEVICE}_analysis.json"
echo ""
echo "3. 查看结果:"
echo "   cat results/$VENDOR/$DEVICE/karonte_*.txt"
echo ""

if [ "$DETECTED_ARCH" != "unknown" ]; then
    echo -e "${GREEN}提示: 检测到架构为 $DETECTED_ARCH${NC}"
    echo ""
fi

echo -e "${YELLOW}注意事项:${NC}"
echo "- 分析可能需要数小时，请耐心等待"
echo "- 建议在后台运行: nohup ./$RUN_SCRIPT > analysis.log 2>&1 &"
echo "- 监控进度: tail -f analysis.log"
echo "- 如遇到问题，请查看 新固件分析流程.md"
echo ""
echo -e "${GREEN}完成！${NC}"
