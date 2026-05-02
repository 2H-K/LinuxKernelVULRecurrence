# Copy Fail (CVE-2026-31431) 内核漏洞复现环境

> 本项目提供一个完整的 Linux 内核漏洞复现与调试环境，用于复现 Copy Fail（CVE-2026-31431），支持 QEMU + GDB 动态调试。

---

# 📌 漏洞简介

Copy Fail（CVE-2026-31431）是一个 Linux 内核本地提权漏洞：

- 影响范围：Linux 4.14 ~ 6.18 修复前
- 利用方式：普通用户 → root
- 类型：逻辑漏洞（非 race）
- 模块：`algif_aead`（AF_ALG 接口）

---

# 🧠 为什么选择 6.6.1

本项目使用 Linux **6.6.1**：

- ✔ 属于 6.6 LTS 分支
- ✔ 处于漏洞影响范围内
- ✔ patch 最少 → 编译最快
- ✔ 调试路径最干净

Linux 6.6.1 是 6.6 系列早期稳定版本，由官方发布并维护

---

# 🧰 一、宿主机环境要求

- Ubuntu 20.04 / 22.04 / 24.04（物理机或虚拟机）
- x86_64 CPU
- 支持 KVM

检查：

```bash
ls /dev/kvm
```

---

# 📦 二、安装依赖

```bash
sudo apt update
sudo apt install -y build-essential flex bison libncurses-dev libssl-dev libelf-dev \
    qemu-system-x86 qemu-utils wget cpio gdb curl e2fsprogs \
    debootstrap
```

---

# 📁 三、工作目录

```bash
mkdir -p ~/copyfail-lab
cd ~/copyfail-lab
```

![搭建完的文件结构](./workspace.png)

---

# 📥 四、下载内核源码

## 官方源（推荐）

```bash
wget https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.6.1.tar.xz
```

## 清华镜像（国内更快）

```bash
wget https://mirrors.tuna.tsinghua.edu.cn/kernel/v6.x/linux-6.6.1.tar.xz
```

## 解压

```bash
tar -xf linux-6.6.1.tar.xz
cd linux-6.6.1
```

---

# ⚙️ 五、配置内核

```bash
make defconfig
```

然后一键写入所有必需配置：

```bash
cat >> .config <<'EOF'
CONFIG_BLK_DEV_INITRD=y
CONFIG_DEVTMPFS=y
CONFIG_DEBUG_INFO=y
CONFIG_CRYPTO_USER_API_AEAD=y
CONFIG_CRYPTO_USER_API=y
CONFIG_VIRTIO=y
CONFIG_VIRTIO_PCI=y
CONFIG_VIRTIO_BLK=y
CONFIG_EXT4_FS=y
CONFIG_NET_9P=y
CONFIG_NET_9P_VIRTIO=y
CONFIG_9P_FS=y
CONFIG_RANDOMIZE_BASE=n
EOF

make olddefconfig
```

---

# 🔧 六、编译内核

```bash
make -j$(nproc)
```

生成：

* `vmlinux`（GDB 使用）
* `bzImage`（QEMU 启动）

---

# 📦 七、构建 rootfs（debootstrap 定制方案）

使用 debootstrap 从零构建极简 rootfs，仅包含漏洞复现所需的最小包集，排除 cloud-init / systemd 冗余服务等干扰。

## 7.1 debootstrap 构建最小系统

```bash
cd ~/copyfail-lab

sudo debootstrap --variant=minbase --include=python3,strace \
    noble ubuntu-rootfs http://archive.ubuntu.com/ubuntu
```

> `--variant=minbase`：只装 libc + dpkg + apt，最干净  
> `--include=python3,strace`：exploit 运行 + 调试必需

## 7.2 chroot 定制

```bash
sudo chroot ubuntu-rootfs /bin/bash -c '
    echo "copyfail" > /etc/hostname

    echo "root:root" | chpasswd
    useradd -m -s /bin/bash bob
    echo "bob:test" | chpasswd

    echo "none /dev devtmpfs defaults 0 0" > /etc/fstab

    apt clean
    rm -rf /var/lib/apt/lists/*
'
```

## 7.3 写入 init 脚本

```bash
sudo bash -c 'cat > ubuntu-rootfs/init <<INITEOF
#!/bin/sh
mount -t proc none /proc
mount -t sysfs none /sys
mount -t devtmpfs none /dev
mount -t debugfs none /sys/kernel/debug
mkdir -p /mnt/shared
mount -t 9p -o trans=virtio shared /mnt/shared

echo ""
echo "[+] Copy Fail Lab Ready (debootstrap)"
echo "[+] Shared dir mounted at /mnt/shared"
echo "[+] Logged in as: bob (unprivileged)"
echo ""
exec su -l bob
INITEOF'

sudo chmod +x ubuntu-rootfs/init
```

## 7.4 打包为 ext4 磁盘镜像

```bash
cd ~/copyfail-lab

# 根据实际大小调整 count（debootstrap minbase ~150-200MB，留余量）
sudo du -sh ubuntu-rootfs
dd if=/dev/zero of=rootfs.ext4 bs=1M count=512
mkfs.ext4 -F rootfs.ext4

sudo mkdir -p /mnt/rootfs
sudo mount rootfs.ext4 /mnt/rootfs
sudo cp -a ubuntu-rootfs/. /mnt/rootfs/
sudo umount /mnt/rootfs
```

## 7.5 验证 rootfs

```bash
sudo mkdir -p /mnt/rootfs && sudo mount rootfs.ext4 /mnt/rootfs

# 关键文件
ls /mnt/rootfs/init /mnt/rootfs/usr/bin/python3 /mnt/rootfs/usr/bin/strace

# exploit 依赖 /usr/bin/su 的 SUID 位 —— 必须存在且为 -rwsr-xr-x
ls -la /mnt/rootfs/usr/bin/su

sudo umount /mnt/rootfs
```

---

# 🚀 八、启动 QEMU

## 8.1 创建脚本

```bash
cd ~/copyfail-lab

cat > run.sh <<'EOF'
#!/bin/bash

KERNEL_IMAGE="./linux-6.6.1/arch/x86/boot/bzImage"
ROOTFS="./rootfs.ext4"
KERNEL_APPEND="console=ttyS0 nokaslr root=/dev/vda rw init=/init"
SHARED_DIR="./shared"

qemu-system-x86_64 \
  -kernel "$KERNEL_IMAGE" \
  -drive file="$ROOTFS",format=raw,if=virtio \
  -append "$KERNEL_APPEND" \
  -nographic \
  -s \
  -m 512 \
  -enable-kvm \
  -fsdev local,id=shared,path="$SHARED_DIR",security_model=none \
  -device virtio-9p-pci,fsdev=shared,mount_tag=shared
EOF

chmod +x run.sh
```

> `run.sh` 不带 `-S`，内核直接启动（VS Code 调试用）。
> 终端 GDB 调试用 `run-gdb.sh`（带 `-S`，暂停等 GDB 连接）。

## 8.2 创建共享目录

```bash
mkdir -p shared
```

将 exploit 文件放入 `shared/` 目录。

---

## 8.3 VS Code 图形化调试（推荐）

**Step 1** — 启动 QEMU（不带 `-S`，内核直接启动）：

```bash
./run.sh
```

等 QEMU 终端出现 `bob@(none):~$` 提示符。

**Step 2** — VS Code 按 `Ctrl+Shift+D`，顶部选 **"QEMU Kernel Debug"**，按 **F5** 连接。

**Step 3** — 在 VS Code 中打开 `crypto/algif_aead.c`，点击第 95 行左侧设断点。

**Step 4** — QEMU 终端执行 exploit：

```bash
python3 /mnt/shared/exp.py
```

VS Code 会在断点处暂停，可图形化查看变量、调用栈、内存。

> 如需终端 GDB 调试，使用 `./run-gdb.sh`（带 `-S`），工作流见 8.4。

---

## 8.4 终端 GDB 调试

**终端 1** — 启动 QEMU（带 `-S`，暂停等 GDB）：

```bash
./run-gdb.sh
```

**终端 2** — GDB 连接，放行内核启动：

```bash
gdb ./linux-6.6.1/vmlinux -ex "target remote :1234" -ex "continue"
```

等终端 1 出现 `bob@` 提示符后，终端 2 按 `Ctrl+C` 暂停内核，设断点：

```gdb
b _aead_recvmsg
b crypto_aead_decrypt
continue
```

---

# 🔥 九、触发漏洞

**终端 1**（QEMU 虚拟机内，已自动以 bob 身份登录）直接执行 exploit：

```bash
python3 /mnt/shared/exp.py
```

> init 脚本已自动完成：挂载 proc/sys/dev/debugfs、挂载 9p 共享目录、切换到 bob 用户。无需手动操作。

---

# 🎯 十、调试重点

关键函数：

* `_aead_recvmsg`
* `crypto_authenc_esn_decrypt`

观察：

* `assoclen`
* `scatterlist`
* `dst buffer`

---

# ❗ 十一、常见问题

## ❌ VFS: Unable to mount root fs

检查内核配置包含以下选项（用 `grep CONFIG_XXX .config` 确认）：

```
CONFIG_VIRTIO=y
CONFIG_VIRTIO_PCI=y
CONFIG_VIRTIO_BLK=y
CONFIG_EXT4_FS=y
```

## ❌ GDB 断点无法插入

内核启动完成前内存不可访问。先 `continue` 放行内核，等 shell 出现后再 `Ctrl+C` 设断点。

## ❌ 编译慢

```bash
make -j$(nproc)
```

## ❌ debootstrap 卡在下载

国内网络访问 `archive.ubuntu.com` 较慢，可换清华镜像：

```bash
sudo debootstrap --variant=minbase --include=python3,strace \
    noble ubuntu-rootfs http://mirrors.tuna.tsinghua.edu.cn/ubuntu
```

## ❌ rootfs 空间不足

debootstrap minbase 约 150-200MB，`dd count=512`（512MB）通常够用。如需额外包，增大 count 值。
