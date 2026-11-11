# NT Timebomb Patch（FlightPatch）5.3.0 中文说明

本项目用于处理 Windows 预览版的 **时间炸弹 / 证书过期** 问题，并附带一批离线镜像与引导
相关的维护命令。所有匹配都按 **字节码结构** 完成，不依赖 build 号或固定偏移。

> English README: [README.md](README.md)

---

## 一、能做什么

| 命令 | 作用 |
| --- | --- |
| `/cishim` | 绕过预览版 CI（代码完整性）的**构建过期**检查：改 `ci.dll` 的过期回调，并让全套引导器保留 BCD 的 `nointegritychecks` 选项 |
| `/cishim-boot` | 同上，但只处理引导器（不改 `ci.dll`） |
| `/winload-modify` | 正式版 `winload` 的场景：解除镜像哈希 / catalog / 吊销等引导门，用于双系统引导改过的映像 |
| `/slshim` | 替换许可层（SPP）相关组件（实验性） |
| `/bcd`、`/bcd-show` | 对离线 BCD 设置/查看 `nointegritychecks on` 与 `recoveryenabled No` |
| `/bcd-template` | 对镜像内的 `config\BCD-Template` 写入同样两项，便于**封装镜像**时预置 |
| `/image`、`/boot`、`/spp`、`/spponly`、`/nt6`、`/bootwim` | 早期 Win10（**Build < 15063**）FlightSigned 炸弹与 SPP/品牌信息的离线处理 |
| `/media`、`/bootfiles` | 生成完整安装 ISO、单独修补两个引导管理器 |
| `/restore` 及各类 `-restore` | 用 `.bak` 回滚到原始文件 |

---

## 二、运行要求

- **权限**：写系统文件需要管理员；离线修改受 WRP 保护的文件（如 `appinfo.dll`、`System32` 下
  的系统 DLL）请在 **WinPE 的 SYSTEM 提示符** 或 TrustedInstaller 权限下进行。
- **Secure Boot 必须关闭**：否则 loader 仍会拒绝改过的 `ci.dll`。
- **BCD 必须设置** `nointegritychecks on`（见下），否则改过的 `ci.dll` 会得到 `0xc0000428`。
- 目标映像的 `SYSTEM` 注册表 hive 需可写（离线信任库安装需要）。

---

## 三、快速开始：给预览版打 CI 过期补丁

### 1. 在 WinPE 中挂载目标卷（假设为 `W:`，EFI 分区为 `S:`）

```bat
:: 只处理 ci.dll（引导器已就位时）
nttimebomb.cmd /cishim W:\

:: 同时设置 BCD：nointegritychecks on + recoveryenabled No
nttimebomb.cmd /cishim W:\ /bcd S:\
```

输出应包含：

```
Windows\System32\ci.dll
  ...   CI build-expiry callback
Windows\System32\winload.efi
  ...   keep the loader's BCD nointegritychecks option
2 file(s) patched in W:\
```

### 2. 手动设置 BCD（等效）

```bat
nttimebomb.cmd /bcd S:\
nttimebomb.cmd /bcd S:\ {GUID}
nttimebomb.cmd /bcd-show S:\
```

`/bcd` 会同时写入 `nointegritychecks on` 与 `recoveryenabled No`：前者是 `ci.dll` 必需，
后者让失败的启动停在启动菜单而不是自动进入修复（自动修复会改写 BCD）。

### 3. 封装镜像时预置

```bat
nttimebomb.cmd /bcd-template D:\Mount
```

写入 `<root>\Windows\System32\config\BCD-Template`，部署后新建的 BCD 存储即自带这两项。

---

## 四、`/cishim` 支持的对象

- `Windows\System32\ci.dll`
- `winload.efi`、`winresume.efi`、`winload.exe`、`winresume.exe` 及其 `System32\Boot` 硬链接副本

三种输入形式均支持：

```bat
nttimebomb.cmd /cishim D:\Mount         :: 离线 Windows 根
nttimebomb.cmd /cishim D:\Extracted     :: 单独提取出来的文件夹
nttimebomb.cmd /cishim D:\Extracted\ci.dll
```

- **匹配不上就整体拒绝**，不会"猜着打"；
- 每个被改动的文件都会留下同目录的 `FILE.bak`；
- **未被改动**的目标（例如没有"删除 `nointegritychecks`"逻辑的 `winresume`）也会保留
  `FILE.bak`，这样一次操作的每个目标都能被 `/restore` 覆盖。

---

## 五、代码完整性与 BCD 的关系

| 现象 | 原因 | 处理 |
| --- | --- | --- |
| `0xc0000428`（loader 阶段） | 目标启动项没有生效的 `nointegritychecks`，或 Secure Boot 未关 | `nttimebomb /bcd S:\` 后重启 |
| `0xc0000098` | 早期版本的额外"强制 integrity option"改动与新预览版不兼容（已移除） | 用当前版本重打，或 `/cishim-restore` 后重来 |
| `0xc000021a` + 第二参数 `0xc0000428` | 改过的系统 DLL 未通过镜像校验 | 见下节"本地签名" |

`/cishim` 只保留"BCD `nointegritychecks` 选项"这一处 loader 改动；镜像哈希 / catalog /
吊销等门属于 `/winload-modify`（正式版 loader 场景）。

---

## 六、常见问题

### 1. 三个 UIAccess 程序（屏幕键盘 / 讲述人 / 放大镜）打不开

与过期证书、`consent.exe`、AppInfo 自动提权表**都无关**。实测（21390）四套补丁均无效，
把 **LUA 子系统整体关闭** 后全部正常：

```bat
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" ^
        /v EnableLUA /t REG_DWORD /d 0 /f
:: 重启
```

代价：不再有 UAC 提示、所有进程以完整管理员令牌运行、**Store/UWP 应用无法启动**。
只调低 UAC 滑块不够，必须是 `EnableLUA=0`。

### 2. Windows Defender 打不开

`WinDefend` 服务启动即退出（事件 7034），自身日志为空，属于平台拒绝在该 build 上运行。
本项目不提供修复。

### 3. `/image`、`/spponly`、`/nt6` 提示不适用

这些是早期 Win10 的 FlightSigned 处理，**只适用于 Build < 15063**。15063 及以后会
**不做任何修改**并提示改用 `/cishim`（CI）与 `/slshim`（许可）。

### 4. 签名相关

写受保护的系统二进制（旧版的 `/wintrust`、`/uac`、`/uiaccess` 等）需要本地自签名 + 信任库
安装；这些命令已从命令行移除（代码保留在 `src/wintrust_sign.h`、`src/signer.h` 等）。
WinPE 内没有签名提供程序（`0x8009001E`），相关签名步骤只能在完整 Windows 上完成。

---

## 七、回滚

```bat
:: 还原 ci.dll 与全套 loader
nttimebomb.cmd /cishim-restore W:\
:: 只还原 loader
nttimebomb.cmd /cishim-boot-restore W:\
:: 还原 winload-modify 改过的引导器
nttimebomb.cmd /winload-modify-restore W:\
:: 全部已知原始文件
nttimebomb.cmd /restore W:\
```

所有备份都是同目录的 `FILE.bak`（权限、时间戳保留），因此可以逐文件手工回退。

---

## 八、从源码构建

需要 Zig（`zig cc` 即可，无需 MSVC）：

```bat
zig cc -target x86_64-windows-gnu -municode -std=c11 -Oz -s src/flightpatch.c ^
    as-invoker.res -ladvapi32 -lbcrypt -lntdll -lversion -lcrypt32 -lncrypt ^
    -o nttimebomb-x64.exe
zig cc -target x86-windows-gnu  ... -o nttimebomb-x86.exe
zig cc -target aarch64-windows-gnu ... -o nttimebomb-arm64.exe
```

MMC 助手（`src/mmc.c`）额外链接 `-lwintrust`。`as-invoker.res` 是提权清单资源。

---

## 九、安全与风险提示

- 本项目会修改系统二进制与引导配置，**务必在虚拟机或可回滚的环境中先验证**；
- 关闭 Secure Boot、关闭 `EnableLUA`、绕过 CI 校验都会降低系统安全性；
- 请自行评估使用场景与合规性。许可证见 [LICENSE](LICENSE)。
