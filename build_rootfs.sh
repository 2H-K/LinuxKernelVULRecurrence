#!/bin/bash

set -e

# ======================== 配置变量 ========================
WORK_DIR="./copyfail-lab"
ROOTFS_DIR="$WORK_DIR/ubuntu-rootfs"
IMAGE_FILE="$WORK_DIR/rootfs.ext4"
IMAGE_SIZE_MB=1536
DEBOOTSTRAP_SUITE="noble"
DEBOOTSTRAP_MIRROR="http://archive.ubuntu.com/ubuntu"
PACKAGES="python3,strace,bpftrace,gcc,libc6-dev,make,curl"

# ======================== 检查权限 ========================
if [ "$EUID" -ne 0 ]; then
    echo "请使用 root 权限运行（sudo）"
    exit 1
fi

# ======================== 创建工作目录 ========================
mkdir -p "$WORK_DIR"

# 仅删除旧镜像文件，保留 ROOTFS_DIR
if [ -f "$IMAGE_FILE" ]; then
    echo "[*] 删除旧镜像文件，准备重构..."
    rm -f "$IMAGE_FILE"
fi

# ======================== 步骤1: debootstrap (按需执行) ========================
if [ -d "$ROOTFS_DIR/usr" ]; then
    echo "[1/6] 检测到已存在的 rootfs 目录，跳过 debootstrap 下载步骤。"
else
    echo "[1/6] 目录为空，开始使用 debootstrap 构建最小系统..."
    mkdir -p "$ROOTFS_DIR"
    debootstrap --variant=minbase --include="$PACKAGES" \
        "$DEBOOTSTRAP_SUITE" "$ROOTFS_DIR" "$DEBOOTSTRAP_MIRROR"
fi

# ======================== 步骤2: chroot 内定制 ========================
# 提示：即使目录存在，重新运行 chroot 定制也是安全的（覆盖配置）
echo "[2/6] 进入 chroot 定制/更新系统配置..."
chroot "$ROOTFS_DIR" /bin/bash -c '
    echo "copyfail" > /etc/hostname
    echo "root:root" | chpasswd
    
    # 检查用户是否存在，不存在则创建
    if ! id "asdf" >/dev/null 2>&1; then
        useradd -m -s /bin/bash asdf
    fi
    echo "asdf:test" | chpasswd

    chmod u+s /usr/bin/su
    apt clean
    rm -rf /var/lib/apt/lists/*
'

# ======================== 步骤3: 创建 init 脚本 ========================
echo "[3/6] 更新 /init 脚本..."
cat > "$ROOTFS_DIR/init" << 'INITEOF'
#!/bin/sh
mount -t proc none /proc
mount -t sysfs none /sys
mount -t devtmpfs none /dev
mount -t debugfs none /sys/kernel/debug
mount -t 9p -o trans=virtio shared /mnt/shared

echo ""
echo "=============================================="
echo "  Copy Fail Lab Ready (ro rootfs)"
echo "  Shared dir: /mnt/shared"
echo "  User: asdf (password: test)"
echo "=============================================="
echo ""
exec su -l asdf
INITEOF

chmod +x "$ROOTFS_DIR/init"
mkdir -p "$ROOTFS_DIR/mnt/shared"

# ======================== 步骤4: 创建 ext4 镜像 ========================
echo "[4/6] 重新创建空白 ext4 镜像 ($IMAGE_SIZE_MB MB)..."
dd if=/dev/zero of="$IMAGE_FILE" bs=1M count="$IMAGE_SIZE_MB" status=noxfer
mkfs.ext4 -F -L copyfail-root "$IMAGE_FILE"

# 

# ======================== 步骤5: 挂载并同步数据 ========================
echo "[5/6] 挂载新镜像并从 rootfs 目录同步内容..."
MOUNT_POINT="/mnt/rootfs_$$"
mkdir -p "$MOUNT_POINT"
mount "$IMAGE_FILE" "$MOUNT_POINT"

# 使用 cp -a 覆盖同步
cp -a "$ROOTFS_DIR/." "$MOUNT_POINT/"

# 写入 fstab
cat > "$MOUNT_POINT/etc/fstab" << EOF
/dev/vda / ext4 ro,noatime 0 1
proc /proc proc defaults 0 0
sysfs /sys sysfs defaults 0 0
devtmpfs /dev devtmpfs defaults 0 0
tmpfs /tmp tmpfs defaults 0 0
EOF

# ======================== 步骤6: 清理 ========================
echo "[6/6] 卸载并完成..."
umount "$MOUNT_POINT"
rmdir "$MOUNT_POINT"

# 恢复当前用户对镜像的所有权，方便 QEMU 读取
REAL_USER=$(logname 2>/dev/null || echo $SUDO_USER)
chown "$REAL_USER":"$REAL_USER" "$IMAGE_FILE"

echo "[✓] 重构完成！镜像路径: $IMAGE_FILE"