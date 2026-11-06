# -*- coding: utf-8 -*-
"""
DNS劫持全能增强版 v8 - Android 入口
通过 python-for-android / Buildozer 打包为 APK 后在此启动。
也可在 Termux 中直接 python3 main.py 运行（需先把 dns_hijack.py 放同目录）。
"""
import os
import sys
import subprocess
import threading
import time

BASE = os.path.dirname(os.path.abspath(__file__))
HIJACK = os.path.join(BASE, "dns_hijack.py")

def start_hijack():
    if not os.path.exists(HIJACK):
        print("[!] dns_hijack.py not found in", BASE)
        return
    # 以当前目录为工作目录启动 hijack
    os.chdir(BASE)
    # 默认全自动启动（可通过环境变量或参数覆盖）
    cmd = [sys.executable, HIJACK, "--auto"]
    print("[+] Starting DNS Hijack:", " ".join(cmd))
    p = subprocess.Popen(cmd)
    try:
        p.wait()
    except KeyboardInterrupt:
        p.terminate()

if __name__ == "__main__":
    # 后台启动 hijack，主线程保持存活（供 Android Service/Activity 绑定）
    t = threading.Thread(target=start_hijack, daemon=True)
    t.start()
    while True:
        time.sleep(1)
