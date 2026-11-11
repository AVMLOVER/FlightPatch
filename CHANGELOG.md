# 更新日志（NT Timebomb Patch 5.3.0）

## 5.3.0 - 2026-11-12

### 弃用

- **`/mmc` 弃用**。运行时会打印弃用提示。功能保留可用，但在下一版本移除。
- **`/mmc-approval` 弃用**。运行时会打印弃用提示。功能保留可用，但在下一版本移除。
  - 已**回退**其中"把 `osk.exe` / `Narrator.exe` / `Magnify.exe` 写进 AppInfo 自动提权表"的改动。
    实测该改动对这三个程序无效，且 `appinfo.dll` 被改写后需要有效签名，风险高于收益。
  - 若你之前运行过带该改动的版本，请还原：
    ```bat
    :: WinPE 或 SYSTEM
    nttimebomb /mmc-approval-restore W:\
    ```

### 新结论：三个 UIAccess 程序用 `EnableLUA=0`，不再打补丁

`osk.exe` / `Narrator.exe` / `Magnify.exe` 在 `EnableLUA=1` 时无法启动，报普通错误弹窗
`ERROR_DS_REFERRAL`（8235），与过期证书、`consent.exe`、AppInfo 自动提权表**都无关**
（四套补丁逐一实测均无效）。把 **`EnableLUA` 设为 `0`** 并重启后全部正常。

```bat
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 0 /f
:: 重启
```

代价（请自行权衡）：

- 不再有 UAC 提权提示，所有进程以完整管理员令牌运行；
- **Store / UWP 应用无法启动**（包括 Windows 安全中心的 UWP 外壳）；
- 部分系统设置页可能提示不支持。

本工具不再为这三个程序提供补丁路径；`/uac`、`/uiaccess`、`/wd`、`/wintrust` 已从命令面移除
（代码保留在 `uac.h`、`uiaccess.h`、`wd.h`、`wintrust_sign.h`、`cert_patch.h`，仅供后续参考）。

### BCD：同时写入 `nointegritychecks` 与 `recoveryenabled`

- `/bcd ESP [GUID]` 现在一次写入两项：
  - `nointegritychecks on`（`/cishim` 的 `ci.dll` 必需，否则 loader 报 `0xc0000428`）
  - `recoveryenabled No`（失败时停在启动菜单，不自动进修复）
- `/bcd-show ESP [GUID]` 追加打印这两个元素的当前值。
- 新增 **`/bcd-template OFFLINE_ROOT`**：对
  `<root>\Windows\System32\config\BCD-Template` 写入同样两项，便于**封装镜像时预置**，
  使新建的 BCD 存储直接带上这两个设置。

### `/image`、`/boot`、`/spp`：15063 及以上直接拒绝

核心功能（早期 Win10 FlightSigned 炸弹：`ci.dll` + 全套 `winload`）只适用于
**Build < 15063** 的映像。15063 及以后：

- `/image ROOT /boot [/spp ...]`、`/spponly`、`/nt6 /file ...` **一律不做任何修改**
  （也不再重命名 `LicensingUI.exe`），直接退出并提示：

  ```
  Build 15063 is 15063 or newer, so this mode does not apply and no file was changed.
  Use nttimebomb /cishim OFFLINE_ROOT for the CI build-expiry restrictions and
  nttimebomb /slshim OFFLINE_WINDOWS_ROOT for the licensing side; both can be applied
  to the same image.
  ```

- 帮助文本与 `/spponly` 的说明同步改为"低于 Build 15063"。
- 旧版本里"15058+ 只重命名 LicensingUI.exe"的行为已移除：改名也不能解决新 build
  的 CI 与许可限制，只会让 `LicensingUI.exe` 缺失。

### 备份

- `/cishim`、`/cishim-boot` 现在会给**所有目标文件**留下 `FILE.bak`，包括本模式不改动的
  `winresume.efi` / `winresume.exe`（以前只有被改动的文件才有备份），这样一次操作的每个
  目标都能被 `/restore` 覆盖。

### 文档

- `README.md` 与本文同步重写：删除 `/wintrust` 系列章节（该命令已不存在），新增
  「UIACCESS 程序与 `EnableLUA=0`」章节、`/bcd` 的两项设置与 `/bcd-template`、
  `/mmc` 与 `/mmc-approval` 的弃用说明；构建说明与 `/spponly` 的版本边界统一改为
  Build 15063。
- 命令面最终为：`/slshim`、`/mmc`（弃用）、`/mmc-approval`（弃用）、`/cishim`、
  `/cishim-boot`、`/winload-modify`、`/bcd`、`/bcd-show`、`/bcd-template`、`/restore`、
  `/nt6`、`/media`、`/bootfiles`。`/wintrust`、`/wintrust-approval`、
  `/wintrust-approval-restore`、`/wintrust-restore`、`/wintrust-status`、`/uac`、
  `/uiaccess`、`/wd` 均已移除（代码保留在 `wintrust_sign.h`、`cert_patch.h`、
  `wintrust_status.h`、`uac.h`、`uiaccess.h`、`wd.h`）。

### 其他

- `/cishim`、`/cishim-boot` 可带 `/bcd ESP` 一步完成"打补丁 + 设置 BCD"。
- 修复：`/wintrust` 系列签名时 SIP 对受保护文件必然 `ERROR_ACCESS_DENIED` 的问题（改为在可写副本上
  由 SIP 签名后整份写回；该功能虽已从命令面移除，逻辑仍保留在共享签名器里，供后续功能复用）。
- 修复：`/mmc-approval`、`/uiaccess` 的暂存目录 id 为空导致的 `NTTP-*-` 目录重名。
- 文档：`TESTING.md` 增补"Round 10：三个 UIAccess 程序是 LUA 问题"的实测对照表。

## 5.3.0

- `/cishim`、`/cishim-boot`：只保留 BCD `nointegritychecks` 选项这一处，匹配不上就整体拒绝；
  新增 `/bcd`、`/bcd-show`。
- `/wintrust` 系列改为字节码自适应匹配（导出名 + `test/jcc/bts` 结构 + `CERT_E_EXPIRED` 常量），
  同一套规则在 x64/x86 上都验证过。
- 新增本地自签名流程（KSP → CryptoAPI 回退，WinPE 里给出明确原因）。
- 离线信任库写入（`offreg`），文件时间戳与 ACL 保留。
- `/restore`、`/cishim-restore`、`/cishim-boot-restore`、`/winload-modify-restore` 等回退集合。
- 新增 `/mmc-approval`（AppInfo 自动提权表）、`/slshim`、`/winload-modify`。
