# 更新日志（NT Timebomb Patch 5.4.2）

## 5.4.2 - 2026-11-17

### 命令面调整

- **移除 `/mmc`、`/mmc-restore`、`/mmc-approval`、`/mmc-approval-restore`**：命令行不再提供，
  帮助里已删除相关段落；**实现代码保留**（`src/mmc.c`、`src/mmc_approval.h`），以便后续维护。
- **`/winpe` 不再修改 BCD**：只处理启动链文件（原来写入的 `hypervisorlaunchtype Off` 已去掉，
  实测它对 VMware 的 `hypervMonitor_syn.c` panic 无效）。

### `/media` 集成 `/winpe`

```bat
nttimebomb /media D:\Preview.iso /work D:\NTTP-Work /out D:\Preview-patched.iso ^
           /oscdimg C:\Tools\oscdimg.exe /7zip C:\Tools\7z.exe /winpe
```

- 解包后**自动在工作目录里修补启动链**：`bootmgr.efi`、`efi\boot\bootx64.efi`、
  `bootmgfw.efi`、`cdboot*.efi`、`memtest*`、`efisys.bin` / `efisys_noprompt.bin` 内嵌镜像、
  BIOS `bootmgr`；
- 打包用 `oscdimg -m -o -h -u1 -udfver102 -j -bootdata:2#p0,e,b\boot\etfsboot.com#pEF,e,b\efi\microsoft\boot\efisys.bin`，
  **工作目录里修好的 `efisys.bin` 会作为 UEFI 引导镜像打进 ISO**；
- `sources\boot.wim` 按 `/bootwim` 规则修补：**除 `/spponly` 与 `/nt6` 两种模式外**，
  加不加 `/bootwim` 都修补。

## 5.4.1 - 2026-11-17

### `/winpe`：cdboot 规则，UEFI 光盘启动打通

- 新增 **cdboot 规则**：`call ; 8b d8 ; 85 c0 ; 79 ; 45 8b c6` 与 `85 c0 ; 79 ; 48 8b 4f 18`
  两处 `jns → jmp`（9909/14349 偏移 `0x2D58F`、`0x2E45A`）；
- 验证：按此改写的 `cdboot.efi` 与可用介质 `Patched_14357.1000_WinPE.iso` 内的 cdboot
  **逐字节完全一致（含 PE 校验和）**；`efisys.bin` 内嵌副本同样完全一致，容器大小不变；
- 修正容器内 PE 校验和的长度计算（补上 Authenticode 段、修正 DataDirectory 偏移）。

### 打包要求（实测结论）

- **必须用 `oscdimg` 打包**，并用 `-bootdata:...#pEF,e,b<补丁后 efisys.bin>` 把补丁后的
  UEFI 引导镜像写进 ISO。UltraISO 会沿用源 ISO 的引导镜像，目录树里替换 `efisys.bin` 无效；
- 不需要"原地改 ISO"的旁路方案。

### Legacy 与虚拟机设置

- BCD 写入 `hypervisorlaunchtype Off` 仍保留，但**不足以**避免 VMware 的
  `hypervMonitor_syn.c:940` panic；
- 有效做法：`.vmx` 中去掉 `vhv.enable`、`hypervisor.cpuid.v0` 两行（或取消勾选
  "Virtualize Intel VT-x/EPT or AMD-V/RVI"）。

## 5.4.0 - 2026-11-16

### 新增 `/winpe`（取代 `/bootmgr`）

```bat
nttimebomb /winpe PE_ROOT
```

目标：**保持 boot.wim 原版**，只改启动链文件，让 PE 在当前日期能启动。

- 默认处理 UEFI 全套：`bootmgr.efi`、`efi\boot\bootx64.efi`、`efi\boot\bootia32.efi`、
  `efi\microsoft\boot\bootmgfw.efi`、`cdboot.efi`、`cdboot_noprompt.efi`、`memtest.efi`、
  `boot\memtest.exe`；
- **同时处理 Legacy 的 `bootmgr`**（BIOS 压缩容器：解包 → 改内部镜像 → 重建）；
- 每个文件留 `FILE.bak`，PE 目录里不存在目标文件时跳过；
- 打印：`N boot manager(s) patched, M left untouched, in ROOT`。

改点沿用 `/image` 的引导器规则：镜像哈希门、boot application status、catalog 门、
0603 吊销结果。原理与 PDF 一致：让引导管理器不再因**过期证书**拒绝它要加载的
（未修改的）`winload.efi`/镜像。

### 注意

- 打补丁会破坏引导管理器的 Authenticode 签名 → **Secure Boot 必须关闭**；
- **Legacy 属实验性**：`bootmgr` 需要重压缩并重建容器，工具会在运行时提示先在虚拟机验证，
  实机/介质写入前请务必确认能正常进入 PE；
- `/bootmgr` 开关已移除，全部功能并入 `/winpe`。

### 验证

对 14349 原版 PE 目录执行 `/winpe`：6 个 UEFI 引导管理器全部识别并改写
（`bootmgr.efi` 5 处、`bootx64.efi` 5 处、`cdboot*.efi` 各 2 处、`memtest.efi` 3 处、`memtest.exe` 2 处），
`bootia32.efi`、`bootmgfw.efi` 在该目录中不存在故跳过。

## 5.3.5 - 2026-11-16

### `/bootmgr`：补充重要警告

改动引导管理器会**破坏其 Authenticode 签名**。对比用户提供的 9926"可用"与"原版"文件后确认：
可用那份其实是 **Windows 10 RTM 10240** 的引导管理器（`FileVersion 10.0.10240.16384`，
`WinVerifyTrust 0x0`），而原版 9926 的 `bootmgr.efi` 是 `0x800B0101`（证书过期）。

因此：

- **UEFI（尤其开 Secure Boot）**：应当**替换** `\bootmgr.efi`、`\efi\boot\bootx64.efi`、
  `\efi\microsoft\boot\bootmgfw.efi`、`cdboot.efi`、`cdboot_noprompt.efi`、`memtest.efi`
  为非过期 build（如 10240）的同名文件，而不是打补丁；
- **Legacy**：BIOS 的 `bootmgr` 容器重建风险高（实测会卡死 / VMware 报错），建议同样用替换法；
- `/bootmgr` 现在会在运行前打印这条警告，帮助文本也同步说明。

## 5.3.4 - 2026-11-15

### 新增 `/bootmgr` 开关

```bat
nttimebomb /bootmgr FOLDER
nttimebomb /bootmgr bootmgr bootmgr.efi
```

就地修补两个引导管理器，各留 `FILE.bak`：

- **`bootmgr.efi`**：走 PE 规则，只改镜像哈希门与 catalog 门（10143 实测：15 字节，
  含校验和）；
- **`bootmgr`（BIOS）**：解包其 16 位 stub 里的压缩 Boot Manager，按同一套 PE 规则修改
  内部镜像，再重建容器（沿用 `/bootfiles` 已在用的 `patch_legacy` 路径）。

### 10143 x86 适配情况

- `ci.dll`：属于**三处改点**布局，现有规则直接命中
  （`0x18650` `7c→eb`、`0x1F84C` `75→eb`、`0x272BE` `01→00`），无需新增规则；
- `bootmgr.efi` / `bootmgr`：`/bootmgr` 均识别并改写。

## 5.3.3 - 2026-11-15

### 32 位预览 CI：新增单闸门布局（10525 – 14347）

10525 及之后把三处改点合并成一处"过期闸门"：一个 `mov esi, 0C0000605h`，由
`test cl,cl ; je +13` 跳过"过期块"。按 BetaRookie 的原始方法（把通往过期状态的
条件跳转改成无条件）新增规则，要求 `mov r32,0xC0000605` 与符合条件的跳转**各唯一**，
否则整体拒绝。

| Build | 改点 |
| --- | --- |
| 10525 x86 | `0x26640` `74→eb` |
| 10546 x86 | `0x27582` `74→eb` |
| 10587 x86 | `0x2778A` `74→eb` |
| 14347 x86 | `0x2BD88` `74→eb` |

四个 build 均通过 `/image` 全流程（`ci.dll` + `winload.efi/.exe` + `winresume.efi/.exe`），
输出 `Verified offline updates`。

### 文档

- 新增 **`X86-CI.md`**：32 位 `ci.dll` 过期补丁的原理、两种布局的结构特征、8 个已验证 build
  的改点表、安全设计与用法。
- 既有的三处布局（9841 / 9860 / 9926 / 10074）支持不变，9841 仍与参考补丁逐字节一致。

## 5.3.2 - 2026-11-15

### 32 位预览版 CI 过期补丁（`/image`）

- 新增 32 位预览 CI 规则：按"证书起始时间分支 / flighting 状态分支 / 过期标志字节"三处结构定位，
  每处都要求在该文件中**唯一命中**，否则整体拒绝。
  - 分支 `7c`（或已改的 `eb`）→ `eb`；
  - `test byte [addr],1; jne` 的 `jne` → `eb`；
  - `jbe +2; mov bl/bh,1` 的立即数 `01` → `00`。
- 与用户提供的 9841 已修改 `ci.dll` 逐字节比对：**0 处差异**（含校验和）。
- 实测四个 32 位 build 全部识别并改写（`ci.dll` 三处 + 全套 loader）：

| Build | `ci.dll` | loader |
| --- | --- | --- |
| 9841 x86 | 0x13347 / 0x19C7A / 0x21C48 | winload.efi/.exe、winresume.efi/.exe |
| 9860 x86 | 0x1A2C1 / 0x20B90 / 0x277E2 | 同上 |
| 9926 x86 | 0x17C2A / 0x1E688 / 0x25670 | 同上 |
| 10074 x86 | 0x1822E / 0x1F1C8 / 0x26BA6 | 同上 |

## 5.3.1 - 2026-11-15

### 新增开关

- **`/disable-lua`、`/enable-lua`**：写 `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System` 的
  `EnableLUA`（0 / 1）。
  - 不带路径：修改**正在运行**的系统（需提权）；
  - 带 `OFFLINE_ROOT`：修改该卷的 `Windows\System32\config\SOFTWARE`，沿用证书库那套
    offreg 写入与"旧 hive 备份 + 分块覆盖"流程；
  - 改动需重启生效。三个 UIAccess 程序正是在 `EnableLUA=0` 时才能启动。

### 结构适配

- **`/image` 对 9833 / 9860 的 loader 适配**：`plan_boot_options` 原来写死
  `mov rcx, rbp` + 四字节 `cmovs ecx, r14d`，这两个 build 用的是
  `mov rcx, rsi` + 三字节 `cmovs ecx, ebp`，且第二条选项常量的距离不同。现改为：
  按 `mov rcx, reg` + `call` + `movzx ecx,[rsp+40]` + `test eax,eax` 定位，
  接受 3/4 字节两种 `cmovs` 编码与已打补丁的形式，并在后随窗口内查找
  `mov edx, 0x16000049`。补丁写成 `b1 01`（+ NOP 对齐）。
- 实测（原文件与补丁后逐字节对比）：
  - 9833 x64：`winload.efi`、`winload.exe`、`winresume.efi`、`winresume.exe` 各 3 处
    （镜像哈希门 6×NOP、catalog 门 6×NOP、loader integrity option `0f 48 cd → b1 01 90`），
    `ci.dll` 两处证书日期分支 `7e/74 → eb`；
  - 9860 x64：同样全部识别并改写；`winresume.*` 使用"alternate image status"分支。
  - **9833/9860 的 x86 版 `ci.dll` 仍未适配**：代码里对"带 `\SystemRoot\System32\ci.dll`
    字面量的 32 位预览 CI"明确拒绝（需要单独验证其 ABI），本轮未实现。

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
