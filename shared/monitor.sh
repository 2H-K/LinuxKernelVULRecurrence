#!/bin/bash

TARGET="/usr/bin/su"
BPF_SCRIPT="$(dirname "$0")/monitor.bt"
LOG_FILE="/tmp/bpf_log.txt"

echo "[*] 攻击前分析: $TARGET"
python3 "$(dirname "$0")/howtorunelf.py" "$TARGET" 2>/dev/null

echo ""
echo "=================================================="
echo "[!] 现在在另一个终端运行 exp"
echo "[!] bpftrace 将监听 60 秒后自动结束"
echo "=================================================="
echo ""

# bpftrace 前台运行，20 秒超时自动退出
timeout 20 bpftrace "$BPF_SCRIPT" > "$LOG_FILE" 2>&1

# 攻击后分析
echo ""
echo "[*] 攻击后分析: $TARGET"
python3 "$(dirname "$0")/howtorunelf.py" "$TARGET" 2>/dev/null

echo ""
echo "===== BPFTRACE 捕获的内核调用链 ====="
cat "$LOG_FILE"
