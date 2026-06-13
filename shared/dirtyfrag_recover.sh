#!/bin/bash
#
# DirtyFrag 环境恢复脚本
#
# DirtyFrag 有两个变体, 可能篡改不同文件:
#   变体1 xfrm-ESP: /usr/bin/su  (page cache 被覆写)
#   变体2 RxRPC:    /etc/passwd  (root entry 被修改为 root::0:0...)
#
# 恢复方法: 用备份文件替换被篡改的文件, 清理 page cache

BACKUP_DIR="/tmp/dirtyfrag_backup"
SU_TARGET="/usr/bin/su"
PASSWD_TARGET="/etc/passwd"

echo "[*] DirtyFrag 环境恢复..."

# --- 恢复 /usr/bin/su (xfrm-ESP 变体目标) ---
if [ -f "$BACKUP_DIR/su.clean" ]; then
    echo "[*] 恢复 /usr/bin/su ..."
    rm -f "$SU_TARGET"
    cp "$BACKUP_DIR/su.clean" "$SU_TARGET"
    chmod u+s "$SU_TARGET"
    echo "    [OK] /usr/bin/su 已恢复, SUID 位已设置"
else
    echo "    [WARN] 备份文件 $BACKUP_DIR/su.clean 不存在, 跳过"
fi

# --- 恢复 /etc/passwd (RxRPC 变体目标) ---
if [ -f "$BACKUP_DIR/passwd.clean" ]; then
    echo "[*] 恢复 /etc/passwd ..."
    rm -f "$PASSWD_TARGET"
    cp "$BACKUP_DIR/passwd.clean" "$PASSWD_TARGET"
    chmod 644 "$PASSWD_TARGET"
    echo "    [OK] /etc/passwd 已恢复"
else
    echo "    [WARN] 备份文件 $BACKUP_DIR/passwd.clean 不存在, 跳过"
fi

# --- 清理 page cache ---
echo "[*] 清理 page cache ..."
echo 3 > /proc/sys/vm/drop_caches 2>/dev/null
if [ $? -eq 0 ]; then
    echo "    [OK] page cache 已清理"
else
    echo "    [WARN] 清理 page cache 失败 (可能需要 rw 文件系统)"
    echo "    [INFO] 如果根文件系统是 ro, 脏页无法写回, drop_caches 不会释放它们"
    echo "    [INFO] 这种情况下需要重启虚拟机才能完全恢复"
fi

# --- 验证恢复结果 ---
echo ""
echo "[*] 验证恢复结果:"

if [ -f "$SU_TARGET" ]; then
    echo "    /usr/bin/su:"
    md5sum "$SU_TARGET"
    ls -la "$SU_TARGET"
    ENTRY_BYTE=$(xxd -p -l 2 -s 0x78 "$SU_TARGET" 2>/dev/null)
    if [ "$ENTRY_BYTE" = "31ff" ]; then
        echo "    [!] 入口点仍被 shellcode 覆盖! page cache 未清理"
        echo "    [!] 请重启虚拟机"
    else
        echo "    [OK] 入口点正常"
    fi
else
    echo "    /usr/bin/su: 文件不存在!"
fi

if [ -f "$PASSWD_TARGET" ]; then
    echo "    /etc/passwd (root entry):"
    head -1 "$PASSWD_TARGET"
    if head -1 "$PASSWD_TARGET" | grep -q "^root::"; then
        echo "    [!] root 密码字段仍为空! page cache 未清理"
        echo "    [!] 请重启虚拟机"
    else
        echo "    [OK] root entry 正常"
    fi
else
    echo "    /etc/passwd: 文件不存在!"
fi

echo ""
echo "[*] 恢复完成"
