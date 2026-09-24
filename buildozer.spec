[app]
title = Mihomo Hub
package.name = mihomohub
package.domain = org.converter
source.dir = .
source.include_exts = py,png,jpg,kv,atlas,json
version = 1.0.0
requirements = python3,kivy,pyyaml,urllib3

orientation = portrait
fullscreen = 0
android.permissions = INTERNET,FOREGROUND_SERVICE,ACCESS_NETWORK_STATE,WAKE_LOCK
android.api = 34
android.minapi = 24
android.ndk_api = 24
android.archs = arm64-v8a

[buildozer]
log_level = 2
warn_on_root = 1
