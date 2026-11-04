# FlightPatch v4.4.0

工具在普通 Windows 或 WinPE 命令提示符中运行。它读取 PE 架构、可执行节、函数入口、常量引用和分支结构来定位补丁。命令无需 Build、PDB、预置文件哈希、PowerShell 或联网。匹配失败或系统文件架构冲突时，相关操作停止。

> **VMware 中部署 Windows Server 2016 TP5（14300）时，启动前将目标启动项的 `hypervisorlaunchtype` 设为 `Off`。** 安装的 `specialize` 阶段和 Hyper-V 组件安装可能重新启用它。如果第二阶段重启后闪现 Windows 标志、反复重启或进入 WinRE，请在这次重启后重新检查并设置。见下方的 [VMware 启动设置](#vmware-启动设置)。

## 就地处理离线系统

`/image` 接受含 `Windows` 目录的离线分区根目录或 DISM 挂载根目录。程序识别目标里已有的 UEFI、Legacy、`hvloader` 和 WinRE 文件。主系统和 WinRE 的 `ntoskrnl.exe` 保留原样。引导分区与 Windows 分区分开时，给目标引导分区分配盘符并通过 `/boot` 指定。WinRE 在独立恢复分区时用 `/recovery` 指定该分区。对已由 DISM 挂载的外层镜像，运行完成后由调用方决定是否提交。

```bat
flightpatch.cmd /image D:\Mount
flightpatch.cmd /image W:\ /boot S:\ /recovery R:\
```

程序检查目标属于离线 Windows。对于明确指定的引导分区，请确认它属于目标系统。外层镜像由 DISM 管理，处理内部 `Winre.wim` 时还需要在本地 NTFS 卷根目录暂存和挂载 WIM 副本。

## 替换 SPP 文件

`/spp` 使用你从正式版提取的文件。可以与 `/image` 一起运行，或通过 `/target` 只替换 SPP 文件。

```bat
flightpatch.cmd /image W:\ /spp G:\RTM-SPP
flightpatch.cmd /spp G:\RTM-SPP /target W:\
```

来源目录可直接放 `sppsvc.exe` 等 `spp*` 文件和 `spp` 子目录，也可保留 `System32` 或 `Windows\System32` 这一层。`.cat`、`.cer`、`.crt`、`.der`、`.p7b`、`.p7c` 和 `.sst` 可以平铺在 `sppsvc.exe` 旁，程序会将它们放入目标 `CatRoot\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}` 并保留文件名。若放在来源的 `CatRoot` 子目录，则保留 `CatRoot` 内的相对路径。同一文件只需提供一份。程序跳过 `sppnp.dll`。SPP 文件的所有者设为 `NT SERVICE\TrustedInstaller`，`sppsvc.exe` 和 `spp\store\2.0` 内的文件另外授予 `NT SERVICE\sppsvc` 完全控制。已有 CatRoot 文件保留所有者和 ACL。来源应由用户按目标架构与系统系列选择。 [BetaArchive 原帖](https://www.betaarchive.com/forum/viewtopic.php?t=38947)

给 x64 目标补齐 32 位 SPP 时，从同一套正式版 x64 Windows 的 `Windows\SysWOW64` 提取 `spp*` 文件及已有的 `spp` 子目录。把它们放在供体根目录的 `SysWOW64`、`Windows\SysWOW64` 或原生 SPP 文件旁的 `SysWOW64`。例如，平铺的 `D:\1\sppsvc.exe` 对应 `D:\1\SysWOW64\sppc.dll`。只提供一处 `SysWOW64`。程序将其中的 x86 SPP 文件写到目标 `Windows\SysWOW64`，沿用跳过 `sppnp.dll` 和设置所有者及 ACL 的规则。两套 SPP 共享目标 `System32\CatRoot`，证书和目录文件各提供一份即可。输出分别显示 System32、SysWOW64 和 CatRoot 的处理数量。x86 目标继续使用原生 SPP 文件。

组合运行时，先校验 SPP 来源，再处理引导和恢复文件，最后复制 SPP 文件。若最后一步失败，程序会报告引导文件已经处理，可重新运行 `/spp`。

复制 SPP SKU 软件包的 `.cat` 成功后，程序会在同一目录移除同一软件包标识、与目标 Windows 文件版本相符的旧 `.cat`。已手动移除的文件会跳过。程序根据目标版本定位旧文件。

### 从参考镜像迁移 SPP

使用 `/spp-reference` 指向一个已处理的 Windows 镜像根目录。来源和目标应是同一 Build、架构和 Windows 版本（如 Professional）。程序核对内核的 Build 和架构，并检查目标里是否存在来源的 SPP SKU 子目录。可单独迁移，也可和 `/image` 一起运行。

```bat
flightpatch.cmd /spp-reference D:\10074 /target D:\10074-target
flightpatch.cmd /image D:\10074-target /spp-reference D:\10074
```

该模式按 10074 样本筛选 SPP 组件。System32 选取 `spp.dll`、`sppc.dll`、`sppcext.dll`、`SppExtComObj.exe`、`sppobjs.dll`、`sppsvc.exe`、`sppwinob.dll` 和 `sppwmi.dll`，SysWOW64 取其中存在的 x86 文件。两个目录的 `spp` 下只迁移静态 `.xrm-ms` 文件，跳过 `spp\store`，保留目标的激活数据库、CatRoot 和其他 SPP 文件。这套文件筛选不包含注册表或组件存储的迁移。`/spp` 仍用于已手工筛选的正式版文件。

参考模式逐字节比较选中的文件。内容一致时跳过该文件，源独有的静态许可证仍会复制。10074 实测两套镜像的 `sppwmi.mof`、`slui.exe`、`slmgr.vbs`、`sppui\phone.inf` 和 SPP SKU 目录文件内容一致，这些路径不在批量迁移范围内。

### SPP 迁移排除项

供体中即使含有下列文件，`/spp` 和 `/spp-reference` 也会跳过，保留目标原件。

- `System32` 或 `SysWOW64` 顶层的 `sppcomapi.dll`、`sppcommdlg.dll`、`sppinst.dll`。`sppnp.dll` 在 SPP 扫描的各层均跳过。
- `spp\tokens\skus\csvlk-pack\csvlk-pack-Volume-CSVLK-2-ul-store-rtm.xrm-ms`
- `spp\tokens\skus\csvlk-pack\csvlk-pack-Volume-CSVLK-3-ul-store-rtm.xrm-ms`
- `spp\tokens\skus\csvlk-pack\csvlk-pack-Volume-CSVLK-4-ul-store-rtm.xrm-ms`

### 从原版镜像回退 SPP

将同 Build、架构和版本的原版映像挂载到另一个目录，例如 `D:\10074-original`。如果要回退 `D:\10074`，运行：

```bat
flightpatch.cmd /spp-restore D:\10074-original /target D:\10074
```

回退沿用 `/spp-reference` 的文件范围。每个恢复文件从原版复制内容、最后修改时间、所有者、主组、DACL 和继承保护设置。已有目录的权限保持原样。恢复后的文件逐批暂存和替换，出错时会尝试还原本次操作。工具只覆盖原版提供的路径。目标独有的文件、激活存储 `spp\store`、CatRoot、WinSxS 和注册表保留。`/spp-restore` 只与 `/target` 一起使用。

单文件回退时，`/spp-restore` 接受原版文件的路径，`/file` 指定相对于目标映像根目录的路径。源文件从原版挂载目录直接读取，可以保留原有权限。可明确选择 `spp\store` 中的文件或 System32 CatRoot 的证书和目录文件。用同 Build、架构和版本的原版文件。工具检查 PE 架构。

```bat
flightpatch.cmd /spp-restore D:\2\Windows\SysWOW64\sppwmi.dll /target D:\10074 /file Windows\SysWOW64\sppwmi.dll
```

## 写入权限

WinPE 使用 SYSTEM 命令提示符。普通 Windows 可从提升的命令提示符运行。出现拒绝访问或缺少权限时，可以用 NSudo 启动一个新命令提示符，再在其中运行 `flightpatch.cmd`。

```bat
NSudoLC.exe -U:T -P:E cmd.exe
NSudoLC.exe -U:S -P:E cmd.exe
```

`-U:T` 是 TrustedInstaller，`-U:S` 是 SYSTEM。打开新窗口后，切换到工具所在目录再运行。 [NSudo 发布页](https://github.com/M2TeamArchived/NSudo/releases)

## 生成独立文件副本

在 `flightpatch.cmd` 和编译生成的程序所在目录运行。

```bat
flightpatch.cmd check D:\9900x86
flightpatch.cmd patch D:\9900x86 D:\9900x86-patched
flightpatch.cmd patch D:\9900x64 D:\9900x64-patched
flightpatch.cmd patch D:\14300 D:\14300-patched
flightpatch.cmd check D:\14300-patched
```

- `check` 在内存中生成并核验补丁。已应用的规则会保留原字节。
- `patch` 写出到一个尚不存在的新目录。它逐个重新读取并校验输出，然后发布整组文件。
- 使用 `check-image` 或 `patch-image` 可从已应用的离线 Windows 根目录、或已挂载 WIM 的根目录读取。例如 `flightpatch.cmd patch-image W:\ D:\TP5-patched`。
- WinPE 写出使用当前命令提示符的 LocalSystem 身份，可用 `whoami /user` 查看 SID `S-1-5-18`。普通 Windows 直接使用当前账户的文件权限。批处理按运行环境选择 x86 或 x64 程序。
- 输入目录至少要有 `ci.dll`，以及 `bootmgfw.efi + winload.efi` 或 `bootmgr + winload.exe` 的完整配对。提供的 `bootmgr.efi`、内存诊断和恢复加载器也会纳入处理。提供 `ntoskrnl.exe` 时会另行定位内核的两处到期查询。

## Windows 恢复环境

在管理员命令提示符或 WinPE 的 SYSTEM 命令提示符中运行。新 WIM 的输出目录需要在本地 NTFS 卷上并预留 DISM 挂载和暂存空间。

```bat
flightpatch.cmd patch-winre G:\Winre.wim G:\Winre-v3.wim
```

工具复制源 WIM，用系统自带的 DISM 挂载副本的索引 1，检查并修改 `ci.dll` 及 `Windows\System32` 和 `Windows\System32\Boot` 中现有的 UEFI 与 Legacy 加载器。保留内核。校验写入内容并提交 WIM 后，才将副本移动到输出路径。源 WIM 保留。已挂载或已提取的 WinRE 可以先用 `flightpatch.cmd check-winre-mount W:\Mount` 只读检查。

修复既有系统时，从其 BCD 的 `recoverysequence` 确认当前使用的 `Winre.wim`，备份后再替换。准备部署镜像时，替换封装源内 `Windows\System32\Recovery\Winre.wim`。外部启动管理器和恢复 BCD 仍由目标虚拟机的启动分区管理。

## VMware 启动设置

在故障虚拟机中从 WinPE 启动，给虚拟硬盘的 EFI 系统分区分配盘符。以下以 `S:` 为例。先确认 `{default}` 是目标 TP5 的 `\Windows\System32\winload.efi`，再关闭该启动项的 Hyper-V 自动启动并核对结果。

```bat
bcdedit /store S:\EFI\Microsoft\Boot\BCD /enum {default}
bcdedit /store S:\EFI\Microsoft\Boot\BCD /set {default} hypervisorlaunchtype Off
bcdedit /store S:\EFI\Microsoft\Boot\BCD /enum {default}
```

确认显示 `hypervisorlaunchtype Off` 后，从虚拟硬盘重新启动。如果 `{default}` 指向其他系统，用目标 Windows 启动加载器的 GUID 代替。 [BCDEdit 设置说明](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/bcdedit--set)

## Hyper-V 加载器

把目标系统自己的 `hvloader.efi` 和 `hvloader.exe`（有哪份就提供哪份）放入输入目录。

```bat
flightpatch.cmd check-hvloader G:\
flightpatch.cmd patch-hvloader G:\ G:\Hv-v3
```

这两条命令只读取输入目录中的 `hvloader` 文件。检查通过后，补丁同时处理加载器的签名检查路径，以及微码加载失败后误读 PE 描述符的两处控制流。微码加载如果仍然失败，保留原始错误。输出是供离线部署的副本，对应目标的 `Windows\System32`。匹配器识别 AMD64 PE 结构，不依赖 Build 参数，实际样本验证覆盖 TP5 的 UEFI 和 Legacy 文件。Hyper-V 启动结果需要虚拟机复测。

## 14300 的 UEFI 故障

`0xc0000603` 对应 `STATUS_IMAGE_CERT_REVOKED`。FlightPatch 处理文件撤销检查、撤销列表返回路径、映像哈希和目录签名。这个状态仍可能由虚拟机实际启动的另一份引导器产生。

在测试虚拟机中确认 Secure Boot 已关闭。给虚拟机自己的 EFI 系统分区分配一个盘符。下例用 `S:` 表示 EFI 系统分区，`W:` 表示离线 Windows 分区。按实际盘符改写。

```bat
bcdedit /store S:\EFI\Microsoft\Boot\BCD /enum all
fc /b D:\14300-patched\bootmgfw.efi S:\EFI\Microsoft\Boot\bootmgfw.efi
fc /b D:\14300-patched\winload.efi W:\Windows\System32\winload.efi
```

如果虚拟机走 UEFI 默认入口，请用 `S:\EFI\Boot\bootx64.efi` 对照实际启动的文件。离线文件权限会影响替换操作是否写成功。上面的逐字节比较可以验证替换结果。

## 输出与验证范围

- `patch` 和 `patch-image` 生成平铺副本，供手工部署。UEFI 对应 ESP 的 `EFI\Microsoft\Boot` 或固件实际入口。Legacy 对应活动分区根目录的 `bootmgr`。`/image` 用于直接处理离线系统上的副本。
- Legacy `bootmgr` 保留原加载器和容器前缀。工具修改解包后的 PE、重封 XPRESS Huffman、再解包比对，并重算内外 PE 校验和。
- 已在普通 Windows 验证 9900 x86、9900 x64、原版 14300 离线目录和 14300、10514 的旧补丁副本。TP5 的两种 `hvloader` 和 WinRE 文件通过了 PE 校验与重复运行检查。正式版另验证了就地写入、内核保留、SPP 文件筛选、回滚和 `sppsvc` ACL。当前进程未提升，正式版的 DISM 提交及 TrustedInstaller 所有者设置待在管理员命令行或 WinPE 上验证。
- 退出码 0 表示成功，1 表示文件、结构或输出校验失败，2 表示参数错误，3 表示 WinPE 写出时缺少 SYSTEM 身份。

## 源码编译

使用 Zig 0.15.2。以下命令从仓库根目录运行，两个程序的目标架构只决定运行环境，处理的 Windows 文件架构由 PE 头独立识别。

```bat
zig rc /fo as-invoker.res -- src/flightpatch.rc
zig cc -target x86-windows-gnu -municode -std=c11 -Oz -s src/flightpatch.c as-invoker.res -ladvapi32 -lbcrypt -lntdll -lversion -o flightpatch-x86.exe
zig cc -target x86_64-windows-gnu -municode -std=c11 -Oz -s src/flightpatch.c as-invoker.res -ladvapi32 -lbcrypt -lntdll -lversion -o flightpatch-x64.exe
```
