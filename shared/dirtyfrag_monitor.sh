#!/bin/bash
#
# DirtyFrag (CVE-2026-43284 + CVE-2026-43500) 一键监控脚本
#
# DirtyFrag 有两个变体, 篡改目标不同:
#   变体1 xfrm-ESP: 篡改 /usr/bin/su  (与 Copy Fail 相同目标)
#   变体2 RxRPC:    篡改 /etc/passwd  (root entry)
#
# 用法: 在 QEMU 虚拟机内以 root 身份运行此脚本, 另一个终端跑 exp

SCRIPT_DIR="$(dirname "$0")"
BPF_SCRIPT="$SCRIPT_DIR/dirtyfragmonitor.bt"
LOG_FILE="/tmp/dirtyfrag_bpf_log.txt"

SU_TARGET="/usr/bin/su"
PASSWD_TARGET="/etc/passwd"
BACKUP_DIR="/tmp/dirtyfrag_backup"

echo "==================================================================="
echo "  DirtyFrag 监控脚本"
echo "==================================================================="
echo ""

# --- 1. 创建备份目录 ---
mkdir -p "$BACKUP_DIR"

# --- 2. 备份两个目标文件 ---
echo "[*] 备份目标文件..."
if [ -f "$SU_TARGET" ]; then
    cp "$SU_TARGET" "$BACKUP_DIR/su.clean"
    echo "    [OK] $SU_TARGET → $BACKUP_DIR/su.clean"
else
    echo "    [WARN] $SU_TARGET 不存在, 跳过"
fi

if [ -f "$PASSWD_TARGET" ]; then
    cp "$PASSWD_TARGET" "$BACKUP_DIR/passwd.clean"
    echo "    [OK] $PASSWD_TARGET → $BACKUP_DIR/passwd.clean"
else
    echo "    [WARN] $PASSWD_TARGET 不存在, 跳过"
fi

# --- 3. 记录攻击前状态 ---
echo ""
echo "[*] 攻击前文件状态:"
echo "    --- /usr/bin/su ---"
if [ -f "$SU_TARGET" ]; then
    md5sum "$SU_TARGET"
    ls -la "$SU_TARGET"
    echo "    ELF 入口点处字节:"
    xxd -l 16 -s 0x78 "$SU_TARGET" 2>/dev/null || echo "    (xxd 不可用)"
else
    echo "    (文件不存在)"
fi
echo ""
echo "    --- /etc/passwd (前32字节) ---"
if [ -f "$PASSWD_TARGET" ]; then
    head -1 "$PASSWD_TARGET"
    xxd -l 32 "$PASSWD_TARGET" 2>/dev/null || echo "    (xxd 不可用)"
else
    echo "    (文件不存在)"
fi

# --- 4. 检查 bpftrace ---
echo ""
if ! command -v bpftrace &>/dev/null; then
    echo "[!] bpftrace 未安装, 跳过内核调用链监控"
    echo "[!] 仅做前后文件对比"
    BPF_ENABLED=0
else
    BPF_ENABLED=1
fi

# --- 5. 启动 bpftrace 监控 ---
echo ""
echo "==========================================================="
echo "[!] 请在另一个终端运行 DirtyFrag exploit"
echo "[!] bpftrace 将监听 20 秒后自动结束"
echo "[!] 注意: 不要在 9p 共享目录运行 exp, 请 copy 到 /tmp 运行"
echo "==========================================================="
echo ""

if [ "$BPF_ENABLED" -eq 1 ]; then
    timeout 20 bpftrace "$BPF_SCRIPT" > "$LOG_FILE" 2>&1
fi

# --- 6. 记录攻击后状态 ---
echo ""
echo "[*] 攻击后文件状态:"
echo "    --- /usr/bin/su ---"
if [ -f "$SU_TARGET" ]; then
    md5sum "$SU_TARGET"
    ls -la "$SU_TARGET"
    echo "    ELF 入口点处字节 (偏移 0x78):"
    xxd -l 16 -s 0x78 "$SU_TARGET" 2>/dev/null || echo "    (xxd 不可用)"
    # 检查是否被 shellcode 覆盖 (0x31 0xff = xor edi, edi)
    ENTRY_BYTE=$(xxd -p -l 2 -s 0x78 "$SU_TARGET" 2>/dev/null)
    if [ "$ENTRY_BYTE" = "31ff" ]; then
        echo "    [!] 入口点已被 shellcode 覆盖! (0x31 0xff = xor edi,edi)"
    fi
else
    echo "    (文件不存在)"
fi
echo ""
echo "    --- /etc/passwd (root entry) ---"
if [ -f "$PASSWD_TARGET" ]; then
    ROOT_LINE=$(head -1 "$PASSWD_TARGET")
    echo "    $ROOT_LINE"
    if echo "$ROOT_LINE" | grep -q "^root::"; then
        echo "    [!] root 密码字段已被清空! (root:: 表示无密码)"
    fi
    xxd -l 32 "$PASSWD_TARGET" 2>/dev/null || echo "    (xxd 不可用)"
else
    echo "    (文件不存在)"
fi

# --- 7. 输出 bpftrace 日志 ---
if [ "$BPF_ENABLED" -eq 1 ]; then
    echo ""
    echo "==================================================================="
    echo "  BPFTRACE 捕获的内核调用链"
    echo "==================================================================="
    cat "$LOG_FILE"
fi

# --- 8. 总结 ---
echo ""
echo "==================================================================="
echo "  检测结果总结"
echo "==================================================================="

SU_CORRUPTED=0
PASSWD_CORRUPTED=0

if [ -f "$BACKUP_DIR/su.clean" ] && [ -f "$SU_TARGET" ]; then
    if ! diff -q "$BACKUP_DIR/su.clean" "$SU_TARGET" &>/dev/null; then
        SU_CORRUPTED=1
        echo "  [!] /usr/bin/su 已被篡改 (xfrm-ESP 变体生效)"
    fi
fi

if [ -f "$BACKUP_DIR/passwd.clean" ] && [ -f "$PASSWD_TARGET" ]; then
    if ! diff -q "$BACKUP_DIR/passwd.clean" "$PASSWD_TARGET" &>/dev/null; then
        PASSWD_CORRUPTED=1
        echo "  [!] /etc/passwd 已被篡改 (RxRPC 变体生效)"
    fi
fi

if [ "$SU_CORRUPTED" -eq 0 ] && [ "$PASSWD_CORRUPTED" -eq 0 ]; then
    echo "  [OK] 目标文件未被篡改 (exploit 未成功或未运行)"
fi

echo ""
echo "[*] 备份文件位于: $BACKUP_DIR/"
echo "[*] 恢复命令: bash $SCRIPT_DIR/dirtyfrag_recover.sh"
echo ""
