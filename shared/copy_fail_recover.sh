# 删除目录项（inode 仍被进程持有，不影响运行中的进程）
rm /usr/bin/su
# 创建新文件（新 inode，不再是 "busy" 状态）
cp /tmp/su.clean /usr/bin/su
# 恢复 SUID 位
chmod u+s /usr/bin/su