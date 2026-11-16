# `/winpe`：让原版 WinPE 在当前日期启动

> **状态：待实机验证**。x64 规则已与"可用参考"逐字节对齐（见 §5），x86 规则为类比实现、
> 尚无参考可比对。等用户验证通过后再随版本发布。

## 1. 问题

Flightsigned 预览版 PE 里，`ci.dll` 与 `winload.efi` 的证书早已过期。`boot.wim` 本身要按
`/bootwim`（或 `/image`）打补丁 —— 这一步是**必须的**，因为 PE 内部的 CI 与 `winload`
校验还在。

在 `boot.wim` 之前还有一道关：**引导管理器**（`bootmgr.efi` / `bootmgr`）会校验它要加载的
镜像与加载器，遇到过期证书就中止 —— 表现为选完启动项直接回固件菜单（UEFI），或卡在
Logo 不转圈（Legacy）。

`/winpe` 只改介质上的启动链文件，**不动 `boot.wim`**：

```bat
:: 1. 先给 PE 打常规补丁
nttimebomb /bootwim W:\boot\boot.wim            (或 /image /spp 等，按需)
:: 2. 再修启动链
nttimebomb /winpe D:\ISO_ROOT
```

## 2. 处理范围

| 平台 | 文件 | 命中规则 |
| --- | --- | --- |
| UEFI x64 | `bootmgr.efi`、`efi\boot\bootx64.efi`、`efi\microsoft\boot\bootmgfw.efi` | x64 引导管理器规则（4 处） |
| UEFI x86 | `efi\boot\bootia32.efi` | x86 引导管理器规则（1 处） |
| 通用 | `cdboot.efi`、`cdboot_noprompt.efi` | 有匹配则改，无匹配则跳过 |
| 通用 | `memtest.efi`、`boot\memtest.exe` | 同上 |
| Legacy | `bootmgr` | 解包压缩容器 → 改内部镜像 → 重建 |

每个被改动文件保留 `FILE.bak`；不存在的文件直接跳过；**结构不识别就跳过、不猜着改**。

## 3. x64 规则（已与参考逐字节一致）

四处改点，全部要求在本文件内唯一命中：

| 站点 | 原始字节（14349） | 改写 | 语义 |
| --- | --- | --- | --- |
| 镜像状态门 | `call ; 8b d8 ; 85 c0 ; 79 xx ; 44 8b c6` | `79 → eb` | `jns` → `jmp`：直接走"通过"分支 |
| 镜像状态门（js 形式） | `call ; 8b d8 ; 85 c0 ; 78 xx ; 48 8d 4d` | `8b d8 → 31 c0` | 把状态清零（`xor eax,eax`） |
| catalog 状态门 | `85 c0 ; 79 xx ; 48 8b 85` | `79 → eb` | 同上，catalog 校验 |
| 文件吊销结果 | `85 c0 ; 8b d8 ; 41 0f 49 df ; 48 8b cf ; e8` | `41 0f 49 df → 31 db 90 90` | 吊销状态清零 |

14349 原版实测命中位置：

```
bootmgr.efi      0x56F94  0x57830  0x5848B  0x6640E
efi\boot\bootx64.efi  0x439C8  0x44264  0x44EBF  0x548DE
```

## 4. x86 规则

32 位引导管理器把状态放在 `esi`，`jns` 之后紧跟 `test bl,20h`：

```
85 f6 79 xx  f6 c3 20  →  jns 改为 jmp（79 → eb）
```

每个文件要求唯一命中；`memtest.efi` 在该布局下有两处候选，因此会被拒绝（保持原样）。

9909 x86 实测命中：

```
bootmgr.efi                          0x4D7F3
efi\boot\bootia32.efi                0x38D4B
cdboot.efi                           0x26DA9
cdboot_noprompt.efi                  0x26DB0
bootmgr（BIOS 容器）                  内部 4 处（沿用 /image 的引导器规则）
```

## 5. 验证

### 5.1 与可用参考对齐（x64，关键证据）

用户提供的 `Patched_14357.1000_WinPE` 中，`efi\boot\bootx64.efi` 与原版 14349 的
`efi\boot\bootx64.efi` **是同一 build（10.0.14316.1000，1,187,680 字节）**，因此可以直接
逐字节 diff。参考文件相对原版只有 5 处变化：

```
0x140    PE 校验和
0x439C8  79 → eb                     （镜像状态门）
0x44264  8b d8 → 31 c0               （js 形式）
0x44EBF  79 → eb                     （catalog 门）
0x548DE  41 0f 49 df → 31 db 90 90   （吊销结果）
```

**本工具按新规则处理 14349 的 `bootx64.efi` 后，与该参考文件比对：0 处差异**（连校验和都
一致）。这同时确认了：参考实现也是"改字节、保留旧签名"，并非替换为正式版文件。

### 5.2 覆盖情况

| 版本 | 结果 |
| --- | --- |
| 14349 x64 | `bootmgr.efi` 4 处、`bootx64.efi` 4 处（与参考 0 差异）、BIOS `bootmgr` 由 `/image` 规则处理；`cdboot*.efi`、`memtest*` 结构不匹配 → 跳过 |
| 9909 x86 | `bootmgr.efi`、`bootia32.efi`、`cdboot.efi`、`cdboot_noprompt.efi` 各 1 处；BIOS `bootmgr` 4 处 |
| 14357 参考 | 已含全部 4 处改点（本工具识别后不会再改） |

### 5.3 待验证

启动行为需要实机/虚拟机确认（UEFI 关 Secure Boot；Legacy 为实验性）。
建议顺序：

1. 只换 `bootmgr.efi` + `efi\boot\bootx64.efi`（保留原 `cdboot`/`memtest`），测 UEFI；
2. 通过后再加 BIOS `bootmgr`，测 Legacy；
3. 最后整体替换。

## 6. 识别分层（重要）

`/winpe` 对每个 x64 引导管理器按两级识别：

| 级别 | 适用布局 | 改法 | 状态 |
| --- | --- | --- | --- |
| 一级：已验证规则 | 14316 / 14349 / 14357（`bootx64.efi` 14316 系） | 4 处 1~4 字节外科手术（见 §3） | 与参考文件 **0 差异** |
| 二级：通用结构规则 | 9909 等早期 x64 预览 | `/image` 同款状态门（镜像哈希门、boot application status、catalog 门、0603 吊销） | 能识别、能改写，**尚未启动验证** |

识别过程会打印使用的是哪一级：

```
generic boot manager gates (layout not in the verified set)
```

### 6.1 9909 x64 实测

| 文件 | 命中 |
| --- | --- |
| `bootmgr.efi` | `0x5A62C` 哈希门、`0x5AFB5` 应用状态、`0x5BA93` catalog、`0x5AD31` 0603 |
| `efi\boot\bootx64.efi` | `0x433D0`、`0x43D59`、`0x44837`、`0x43AD5` |
| `efi\microsoft\boot\cdboot.efi` | `0x2D5AA`、`0x2E474` |
| `efi\microsoft\boot\cdboot_noprompt.efi` | `0x2D5B6`、`0x2E480` |
| `efi\microsoft\boot\memtest.efi` | `0x42B41` 哈希门、`0x43B49` alternate image status |
| `boot\memtest.exe` | 同上结构（`/image` 规则） |
| `bootmgr`（BIOS 容器） | 内部 `0x1A395`、`0x1A916`、`0x1B202`、`0x7E0C0` |

9909 这类早期 x64 的引导管理器使用 **32 位长跳转**（`0f 88`/`0f 89`），没有 14316 系的
`79`/`78` 短跳转与 `41 0f 49 df` 形态，因此一级规则（gates 0/1/0/0）不适用，自动走二级。

## 6.2 El Torito 镜像（UEFI 光盘启动的真正入口）

UEFI 从光盘启动时，固件执行的是 **`efi\microsoft\boot\efisys.bin`**（1,474,560 字节的
FAT12 镜像），它内部自带一份 `/EFI/BOOT/BOOTX64.EFI`：

```
/EFI/BOOT/BOOTX64.EFI   762688 字节 = cdboot.efi（与 ISO 里的 cdboot 逐字节相同）
```

也就是说 **ISO 目录里的 `efi\boot\bootx64.efi`（1,655,624 字节的 bootmgr）在 UEFI 光盘启动
时根本不会被使用**，只改它等于没改。`/winpe` 现在会：

1. 解析 `efisys.bin` / `efisys_noprompt.bin` 的 FAT 目录，找到内嵌的 `BOOTX64.EFI`；
2. 按同一套引导管理器规则原地修改（**大小不变**，不重排 FAT）；
3. 重算该 PE 的校验和，再整文件写回（保留 `FILE.bak`）。

14349 实测：两个 bin 各 3 处命中（镜像哈希门、catalog 门、loader integrity option），
文件大小不变，共 18 字节变化（含校验和），内嵌镜像的 `0f 85 xx` 已变为 `90 90 90 90 90 90`。

### 6.2.1 cdboot 的两处改点（已与可用介质逐字节对齐）

`efisys.bin` 里那份 `BOOTX64.EFI` 是 **cdboot.efi**（762,688 字节，6.4.9833 build）。
它对引导管理器只做两处状态判断，正确改点是两处 `jns → jmp`：

| 站点 | 结构 | 改写 | 14349/9909 偏移 |
| --- | --- | --- | --- |
| 镜像状态门 | `call ; 8b d8 ; 85 c0 ; 79 xx ; 45 8b c6` | `79 → eb` | `0x2D58F` |
| catalog 状态门 | `85 c0 ; 79 xx ; 48 8b 4f 18` | `79 → eb` | `0x2E45A` |

验证：把 9909 的 `cdboot.efi`（SHA-256 前缀 `a30d12fb`）按上述两处改写后，与可用介质
`Patched_14357.1000_WinPE.iso` 里的 cdboot（`28a0c03f`）**逐字节完全一致**，包括 PE 校验和；
`efisys.bin` 里内嵌的那份改写后同样完全一致，容器大小不变（1,474,560）。

**关键操作提示（实测结论）**：ISO 的 UEFI 引导镜像是独立于目录树的一份数据。UltraISO 重新
封装时会沿用**源 ISO 的引导镜像**，因此在目录树里替换 `efisys.bin` 并不会改变固件真正执行
的那一份 —— 表现为"文件都对、也替换了，仍然退回固件菜单"。

**必须用 `oscdimg` 打包**，并通过 `-bootdata` 显式指定补丁后的 `efisys.bin`：

```bat
oscdimg -m -o -u1 -udfver102 -j ^
  -bootdata:2#p0,e,bD:\iso\boot\etfsboot.com#pEF,e,bD:\iso\efi\microsoft\boot\efisys.bin ^
  D:\iso D:\out.iso
```

已验证：按此打包后 UEFI 能正常启动。不需要"原地改 ISO"之类的旁路方案。

## 6.4 Legacy 与虚拟机设置（实测）

Legacy 启动会在 PE 内核阶段触发 VMware 的 monitor panic：

```
MONITOR PANIC: vcpu-0:NOT_IMPLEMENTED vmcore/monitor/common/cpu/x86/hypervMonitor_syn.c:940
```

实测结论：

- 有效做法在虚拟机侧：把 `.vmx` 里的 `vhv.enable` 与 `hypervisor.cpuid.v0` 两行**去掉**
  （或取消勾选 "Virtualize Intel VT-x/EPT or AMD-V/RVI"），Legacy 即可正常启动。

## 7. 虚拟机侧问题（VMware）的完整说明

Legacy 实测时 VMware 会在 PE 内核启动阶段（屏幕切到 1024x768 后约 1 秒）直接 panic：

```
MONITOR PANIC: vcpu-0:NOT_IMPLEMENTED vmcore/monitor/common/cpu/x86/hypervMonitor_syn.c:940
Monitor Panic.  Last Disk I/O was to the MBR
```

这是 **VMware monitor 自身对 Hyper-V 合成接口的实现缺口**，不是 Windows 或补丁的问题：
penetration 说明引导管理器已经把 `boot.wim` 交出去了（PE 已进入图形阶段）。

实测过的处理方式：

| 做法 | 结果 |
| --- | --- |
| `.vmx` 里**去掉** `vhv.enable`、`hypervisor.cpuid.v0` 两行（或取消勾选 "Virtualize Intel VT-x/EPT or AMD-V/RVI"） | **有效**，Legacy 正常启动 |

因此 Legacy 使用建议：虚拟机侧按上表处理。`/winpe` 不再改动 BCD（5.4.2 起）。
