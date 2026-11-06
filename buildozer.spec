# Buildozer 配置 - DNS劫持全能增强版 v8 APK
[app]

# 应用标题
title = DNS Hijack Full

# 包名（需唯一）
package.name = dnshijackfull

# 包域
package.domain = com.lab

# 源码目录
source.dir = .

# 主入口
source.include_exts = py,png,jpg,kv,atlas

# 版本
version = 8.0

# 权限（需声明危险权限）
permissions = INTERNET,ACCESS_WIFI_STATE,ACCESS_NETWORK_STATE,CHANGE_WIFI_STATE,CHANGE_NETWORK_STATE,WRITE_EXTERNAL_STORAGE,READ_EXTERNAL_STORAGE,ACCESS_COARSE_LOCATION,ACCESS_FINE_LOCATION,WAKE_LOCK,FOREGROUND_SERVICE,SYSTEM_ALERT_WINDOW

# Android 最小/目标 SDK
android.min_sdk = 21
android.target_sdk = 33

# 架构
android.archs = armeabi-v7a, arm64-v8a

# 依赖
requirements = python3,cryptography

# 启动模式（service 后台常驻）
android.service = true

# 启动参数（全自动启动 DNS 劫持）
android.service_entry = main.py
android.service_log_level = info

# 图标（可选，放 icon.png 在根目录）
# icon.filename = icon.png

# 保持屏幕常亮
android.wakelock = true

[buildozer]

# 日志级别
log_level = 2

# 分支
branch = master

# 使用本地 p4a（如有）
# p4a.local = 

[android]

# 签名（debug 模式，发布需替换为自有 keystore）
android.debug = true
