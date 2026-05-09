#!/usr/bin/env python3
import sys
import struct

def hex_dump(filename, max_bytes=256):
    """类似 xxd 的十六进制转储"""
    try:
        with open(filename, 'rb') as f:
            data = f.read(max_bytes)
    except Exception as e:
        print(f"无法读取文件: {e}")
        return False
    
    offset = 0
    while offset < len(data):
        chunk = data[offset:offset+16]
        
        # 十六进制部分
        hex_parts = []
        for i, b in enumerate(chunk):
            if i == 8:
                hex_parts.append('')
            hex_parts.append(f'{b:02x}')
        
        # ASCII 部分
        ascii_part = ''
        for b in chunk:
            if 32 <= b <= 126:
                ascii_part += chr(b)
            else:
                ascii_part += '.'
        
        print(f'{offset:08x}: {" ".join(hex_parts):<47}  {ascii_part}')
        offset += 16
    return True

def analyze_elf_execution(filename):
    """分析 ELF 文件执行起点"""
    try:
        with open(filename, 'rb') as f:
            header = f.read(64)
    except Exception as e:
        print(f"无法读取文件头: {e}")
        return
    
    # 1. 验证 ELF 魔数
    if header[:4] != b'\x7fELF':
        print("❌ 这不是 ELF 文件")
        return
    
    print("✅ ELF 文件格式验证通过")
    
    # 2. 基本属性
    ei_class = header[4]      # 1=32位, 2=64位
    ei_data = header[5]       # 1=小端, 2=大端
    
    arch_map = {1: "32位", 2: "64位"}
    endian_map = {1: "小端", 2: "大端"}
    
    print(f"   架构: {arch_map.get(ei_class, '未知')}")
    print(f"   字节序: {endian_map.get(ei_data, '未知')}")
    
    if ei_class == 2 and ei_data == 1:  # 64位小端
        # 3. 解析 ELF Header
        e_type = struct.unpack_from('<H', header, 0x10)[0]
        e_machine = struct.unpack_from('<H', header, 0x12)[0]
        e_entry = struct.unpack_from('<Q', header, 0x18)[0]
        
        type_map = {0: "无", 1: "重定位文件", 2: "可执行文件", 3: "共享对象"}
        machine_map = {0x3e: "x86-64"}
        
        print(f"   类型: {type_map.get(e_type, '未知')}")
        print(f"   机器架构: {machine_map.get(e_machine, '未知')}")
        
        # 4. 关键：程序入口点
        print(f"\n🎯 程序入口点地址: 0x{e_entry:x}")
        
        # 5. 计算文件偏移（基于常见基址）
        base_addr = 0x400000  # x86-64 Linux 可执行文件常用基址
        if e_entry >= base_addr:
            file_offset = e_entry - base_addr
            print(f"📍 文件偏移（基于基址 0x{base_addr:x}）: 0x{file_offset:x}")
            
            # 6. 显示入口点处的机器码
            print(f"\n入口点处的机器码（前16字节）:")
            try:
                with open(filename, 'rb') as f:
                    f.seek(file_offset)
                    instructions = f.read(16)
                hex_str = ' '.join(f'{b:02x}' for b in instructions)
                print(f"   {hex_str}")
            except Exception as e:
                print(f"   无法读取入口点数据: {e}")
            
            # 7. 教学解释
            print(f"\n📚 执行流程说明:")
            print(f"   1. 操作系统加载 ELF 文件到内存")
            print(f"   2. 从入口点 0x{e_entry:x} 开始执行")
            print(f"   3. 这些机器码通常是运行时启动代码（_start 函数）")
            print(f"   4. 最终会调用 main() 函数")
            
            # 8. 显示字符串（如果有）
            try:
                with open(filename, 'rb') as f:
                    content = f.read()
                if b'/bin/sh' in content:
                    print(f"\n🔍 文件中包含字符串: /bin/sh")
            except:
                pass

def main():
    if len(sys.argv) != 2:
        print("用法: python3 howtorunelf.py <elf文件路径>")
        print("示例: python3 howtorunelf.py /bin/ls")
        sys.exit(1)
    
    filename = sys.argv[1]
    
    print("=" * 70)
    print(f"ELF 文件头分析: {filename}")
    print("=" * 70)
    
    if not hex_dump(filename):
        sys.exit(1)
    
    print("\n" + "=" * 70)
    print("ELF 执行流程分析:")
    print("=" * 70)
    analyze_elf_execution(filename)

if __name__ == '__main__':
    main()
