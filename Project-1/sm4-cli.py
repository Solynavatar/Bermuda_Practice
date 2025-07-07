# sm4_cli.py
# 命令行启动器
import argparse
from sm4 import (
    encrypt_ecb, decrypt_ecb,
    encrypt_cbc, decrypt_cbc,
    encrypt_ctr, decrypt_ctr,
    encrypt_ofb, decrypt_ofb,
    encrypt_cfb, decrypt_cfb
)

def main():
    parser = argparse.ArgumentParser(description="SM4 加密/解密工具 (支持多种模式)")
    parser.add_argument("mode", choices=["ecb", "cbc", "ctr", "ofb", "cfb"], help="加密模式")
    parser.add_argument("action", choices=["encrypt", "decrypt"], help="加密或解密")
    parser.add_argument("key", help="16字节密钥，例如: 0123456789abcdeF")
    parser.add_argument("input", help="输入文件")
    parser.add_argument("output", help="输出文件")
    parser.add_argument("--iv", help="初始向量文件（除 ECB 模式外均需要）")
    args = parser.parse_args()

    key = args.key.encode()
    if len(key) != 16:
        raise ValueError("密钥必须是16字节！")

    with open(args.input, "rb") as f:
        data = f.read()

    if args.mode == "ecb":
        if args.action == "encrypt":
            result = encrypt_ecb(key, data)
        else:
            result = decrypt_ecb(key, data)
    else:
        if not args.iv:
            raise ValueError("模式 %s 需要 --iv 参数指定IV文件" % args.mode)
        with open(args.iv, "rb") as f:
            iv = f.read()
        if len(iv) != 16:
            raise ValueError("IV 必须是16字节！")

        if args.mode == "cbc":
            result = encrypt_cbc(key, data, iv) if args.action == "encrypt" else decrypt_cbc(key, data, iv)
        elif args.mode == "ctr":
            result = encrypt_ctr(key, data, iv) if args.action == "encrypt" else decrypt_ctr(key, data, iv)
        elif args.mode == "ofb":
            result = encrypt_ofb(key, data, iv) if args.action == "encrypt" else decrypt_ofb(key, data, iv)
        elif args.mode == "cfb":
            result = encrypt_cfb(key, data, iv) if args.action == "encrypt" else decrypt_cfb(key, data, iv)

    with open(args.output, "wb") as f:
        f.write(result)

    print(f"{args.action} 完成！结果已写入：{args.output}")

if __name__ == "__main__":
    main()

