# 更新日志（NT Timebomb Patch 6.0.1）

## 6.0.1 - 2026-11-17

### 14951 的 CI 用符号确认并补上规则

14951 是官方 build，微软符号服务器上有完整符号（已下载核对）：

| 文件 | PDB | 关键符号 |
| --- | --- | --- |
| `bootmgr.efi` | `bootmgr.pdb` `E666021D…` | `ImgpValidateImageHash` @ `0x42248`、`BlSecurebootValidateSigningPolicy` @ `0x4359C`、`SIPolicyValidateImage` @ `0x502D4` |
| `ci.dll` | `ci.pdb` `D53E8947…` | 322 个公开符号（CI 内部函数未导出） |

在 `ci.dll` 里定位到**两个** `mov reg, 0C0000605h` 产出点（`0x362D1`、`0x36355`），其前方都是
`test cl, cl ; je` 形态。新增"产出点回溯"判定：

```
for each mov reg, 0C0000605h:
    walk back ≤ 24 bytes to "84 c9 74"
    je  →  eb        (unconditional skip of the expiry status)
```

实测 14951：命中 `0x362CA`、`0x3634A`（两个 `je`），其余字节不变。并且 14951 的
`winload.efi` / `winresume.efi` 能被**参考加载器配方**直接识别（`/image` 输出
`Verified offline updates`）。

> 符号还确认了一件重要的事：14951 的 `bootmgr.efi` 里**没有任何站点直接 call
> `ImgpValidateImageHash`**（它是通过指针调用的），所以介质侧只能靠"完整性开关锚点 + 函数窗口
> + 调用目标聚类"，这也解释了为什么该代介质只做到部分覆盖。

### README 全面重写

`README.md` 更新为 6.0 版本：三条判定链（CI / 加载器 / 介质）的详细说明、已验证 build 矩阵
（9841 → 14951，含 x86）、`/winpe` 细节（不留 `.bak`、`oscdimg -bootdata`、BCD 写入）、
已知限制（14951 BIOS `bootmgr`、14372/14951 介质无实测参照）以及安全模型。

## 6.0.0 - 2026-11-17

首个 6.x 正式版。这一版把 9841–14951 这几代预览版的处理方式统一为"按真实字节结构匹配"，
不再依赖版本号，并且全部对照可用成品校验过。

### 已验证的能力

| 路径 | 状态 |
| --- | --- |
| `install.wim`（`/image`）10074 x64 | 与可用成品 `ci.dll`、`winload.efi`、`winresume.efi` **逐字节一致**（含校验和） |
| `install.wim`（`/image`）10074 x86 | 走 9841 代规则（CI 过期标志 + 各加载器） |
| `install.wim`（`/image`）14300 x64 | `ci.dll` 与老版本成品 **0 差异**；加载器命中同一批站点 |
| `install.wim`（`/image`）10120 / 10166 x64 | `ci.dll` 四分支 + 四个加载器各三处 |
| 介质（`/winpe`）10074 x64 | 与可用成品 `bootmgr.efi`、`memtest.efi` **代码逐字节一致**，UEFI 与 Legacy 均实测可启动 |
| 介质（`/winpe`）10074 x86 / 10120 / 10166 / 10587 | 参考介质配方命中 |
| 介质（`/winpe`）14372 / 14951 | 引导管理器命中参考配方；BIOS `bootmgr` 保持原样并提示 |
| 10587 / 14372 / 14951 的 `ci.dll` | 新增宽松判定（`a8 01 74 17` + 两处 `84 c9 74`），覆盖 14393 一代 |

### 判定顺序（全部要求结构唯一命中）

1. **CI**：四分支参考配方 → 宽松（14393 一代）→ 经典综合判定；
2. **加载器**：参考配方（状态清零三处）→ 结构门（哈希 / catalog / 0603 / 完整性开关）；
3. **介质引导管理器**：已验证 4 改点 → 9841 代 → 参考介质配方（按调用目标聚类）→ 通用门。

任一环节匹配不到时**保持原样**，不写盘、不猜测；`/winpe` 不再保留 `.bak`（原地替换）。

### 兼容性

- 老版本已处理过的文件，新版本能识别为"已完成"（幂等），不会重复改坏；
- 9841（x64/x86）与 10074 的规则未改动，回归结果不变；
- 14951 的 `ci.dll` 与 BIOS `bootmgr` 仍属已知限制（无可用成品对照）。

## 5.6.4 - 2026-11-17

### CI 判定：四分支优先 + 宽松回退（按用户要求）

```
plan_ci_10074（10074/10120/10166 的四个分支，要求 4/4）
      ↓ 失败
plan_ci_late（10587/14300/14372/14951 一代的宽松判定）
      ↓ 失败
plan_ci（经典综合判定，含 plan_umci）
```

每次尝试前清空计划，避免前一个规则残留的编辑与新规则冲突。

**宽松判定的三个站点**（各自唯一）：

| 站点 | 定位 | 改动 |
| --- | --- | --- |
| 过期门 | `a8 01 74 17`（10587/14300 各自唯一） | `74 17` → `90 90` |
| 日期分支 | `84 c9 74` + 后随 flighting 位 | `74` → `eb` |
| 第二次日期分支 | `8b 74 24 58 84 c9 74` | `74` → `eb` |

验证（原版 → 本工具 vs 老版本成品）：

```
14300 ci.dll   diff vs patched: 0        ← 三个站点完全一致
10587 ci.dll   站点位置一致（0x27E68 / 0x31C59 / 0x31CCB）
```

### 加载器与介质

- `/image` 的加载器优先用"参考配方"（10074 一代三处清零），不支持时回退到原有的结构匹配；
- `/winpe` 优先用"参考介质配方"（按调用目标聚类 + 完整性开关锚点），**不再保留 `.bak`**（原地替换）。

### 已知差异

14300 的加载器"完整性开关"这一处，老版本改的是 `41 0f 48 ce`（`cmovs`），本版改的是其后的
`88 4c 24 40`（store），语义相同（都强制 `cl = 1`），因此该 4 字节与老成品不同、校验和随之不同。

## 5.6.3 - 2026-11-17

### 多 Build 覆盖核对（原始文件实测）

用各 build 的原始 `boot` 树与 `/image` 文件逐个实测，结果：

| Build | 介质（`/winpe`） | 镜像（`/image`） |
| --- | --- | --- |
| 10120 x64 | ✅ `bootmgr.efi` 3 处 + 开关、`bootx64.efi`、`memtest.efi`、`cdboot` | ✅ `ci.dll` 4 分支 + 四个加载器各 3 处 |
| 10166 x64 | ✅ 同上（`0x5580B/0x5619F/0x56CE9` 等） | ✅ 同上 |
| 10074 x86 | ✅ 9841 代规则（7 个文件，含 BIOS `bootmgr`） | ✅ x86 规则（CI 过期标志 + 各加载器） |
| 10074 x64 | ✅ 与成品代码逐字节一致 | ✅ 与成品逐字节一致 |
| 14951 x64 | ⚠️ 引导管理器可打（`0x3FBC2`、`0x40058` 等），**BIOS `bootmgr` 无法唯一匹配** | ⚠️ **`ci.dll` 结构不认识** |

14951 属于 14393 一代：`ci.dll` 的校验结构已改写（不是 10074 那四个分支的形态），
`boot\bootmgr`（BIOS）也需要单独定位。这两处**保持原样不动**（工具会保留 `.bak` 并提示），
待后续版本单独适配。

## 5.6.2 - 2026-11-17

### 按"真实文件"重定位：介质引导管理器与成品**代码逐字节一致**

用 10074 ISO 里的**纯原始文件**（`D:\10074-Boot`）重新校准，规则不再靠"出现次数最多"，而是：

1. 先定位**完整性开关**（`0f b6 4c 24 40 85 c0 41 0f 48 ce`，同代唯一）；
2. 只考虑该开关**前后 0x2000（一个函数大小）内**的状态检查站点；
3. 在这些站点里选**出现最多的调用目标**，清零它们的 `mov ebx, eax`；
4. 主路径的 `call` 目标不同（比如别的校验函数）时自动排除。

验证（`D:\10074-Boot` 原版 → 本工具输出 vs `D:\10074Install` 成品，只比代码区）：

| 文件 | 改点 | 与成品对比 |
| --- | --- | --- |
| `bootmgr.efi` | `0x55D14`（开关）+ `0x55857`、`0x561EB`、`0x56D35`（状态） | 仅 PE 校验和不同，**代码 0 差异** |
| `efi\microsoft\boot\memtest.efi` | `0x3E72C` + `0x3E27C`、`0x3F3DC` | 仅 PE 校验和不同，**代码 0 差异** |
| `efi\boot\bootx64.efi` | `0x405C8` + `0x4011A`、`0x40A99` | 同形态（无成品可比） |
| `cdboot.efi` / `cdboot_noprompt.efi` | 2 处 CD 引导门 | 与旧规则一致 |

（成品里那 1210 字节差异全部落在 `0x11313B+` 的**证书数据区**，那是作者重签证书造成的，不需要也无法复现。）

## 5.6.1 - 2026-11-17

### `/winpe` 参考配方补全：介质 `bootmgr.efi` 与成品**逐字节一致**

5.6.0 只覆盖了 3 个"`jns` 形态"的状态清零，漏了参考文件里两处 `js` 形态（`0x561EB`、`0x56D35`）。
本版改为按**调用目标分组**：

1. 收集所有 `mov [rsp+20h/28h], … ; call … ; mov ebx, eax ; test ; jns/js` 形态的站点；
2. 计算每处 `call` 的**目标地址**，取出现次数最多的那个校验函数；
3. 只清零"调用同一个校验函数"的站点（10074 介质上正好 3 处：`0x55857`、`0x561EB`、`0x56D35`）；
4. 完整性开关 `0x55D14` → `b1 01 90 90`。

验证（10074 介质 `bootmgr.efi`，与 `D:\10074Install\bootmgr.efi` 对比）：

```
total diffs vs reference: 0
```

含 PE 校验和在内完全一致。之前 UEFI 报 `0xc0000428` 很可能就是缺这两处 `js` 形态的清零。

## 5.6.0 - 2026-11-17

### `/winpe` 也改用"参考配方"

`/winpe` 修补介质引导管理器时，优先尝试与 install.wim 相同的**参考配方**（不是之前的"清所有状态"）：

- 三种 `mov [rsp+20h]/[rsp+28h]/[rsp+20h+reg], eax ; call … ; mov ebx, eax ; test ; jns` 形态 → `31 c0`；
- `mov [rsp+40h], cl`（完整性开关）→ `b1 01 90 90`；
- 备用状态 `8b f8 85 c0 0f 88` → `31 c0`。

10074 介质 `bootmgr.efi` 实测：`0x55857`（`8b d8 → 31 c0`）与 `0x55D14`（`b1 01 90 90`）**与参考文件一致**，
另外命中 3 处同形态的状态清零（`0x283C6`、`0x2FE50`、`0x4432C`）。输出里会打印 `reference media layout`。

> 已知缺口：参考文件里还有两处 `js` 形态（`0x561EB`、`0x56D35`，`8b d8 85 c0 0f 88`）本版**未覆盖** ——
> 这两处的定位还需要再核对偏移，`/winpe` 的参考配方因此仍属"部分覆盖"，待下版补齐。

### `/winpe` 不再做"全清 `0C0000428h`"

那套宽泛改写实测不能解决 UEFI 的 `0xc0000428`，反而让文件与参考差异变大，已从介质路径移除
（代码保留但不再调用）。

### 版本

- Legacy 与 UEFI 的 install.wim 路径（`/image`）保持 5.5.11/5.5.12 的逐字节一致结果；
- 发布 5.6.0，作为 `/winpe` 参考配方的验证版。

## 5.5.12 - 2026-11-17

### Legacy 加载器（`winload.exe` / `winresume.exe`）也走同一配方

之前 `/image` 对 `Windows\System32\winload.exe` 报 `Unsupported or ambiguous structure`，原因是
规则里两处掩码长度写错（模式 11 字节、掩码写成 12；备用状态那段 8 字节、掩码写成 9），
导致结构识别失败。修正后 Legacy 与 UEFI 用**同一套三处改动**：

| 作用 | 文件 | 改动位置（文件偏移） |
| --- | --- | --- |
| 镜像哈希状态 | `winload.exe` | `0x4419F` `8b d8 → 31 c0` |
| 完整性检查开关 | `winload.exe` | `0x44660` `88 4c 24 40 → b1 01 90 90` |
| 备用镜像状态 | `winload.exe` | `0x45681` `8b f8 → 31 c0` |
| 镜像哈希状态 | `winresume.exe` | `0x30783` |
| 完整性检查开关 | `winresume.exe` | `0x30C38` |
| 备用镜像状态 | `winresume.exe` | `0x318E8` |

并且规则现在是**幂等**的（已打过补丁的文件能被识别为"已完成"，不会报错）。

回归验证（UEFI 三个文件，与可用成品对比）：

```
ci.dll        diff: 0
winload.efi   diff: 0
winresume.efi diff: 0
```

### 移除 `mmc-*.exe` 残留

`nttimebomb-mmc-{x86,x64,arm64}.exe` 及 `src/mmc.c`、`src/mmc_approval.h`、打包脚本中的相关条目
全部删除（该功能已不再提供）。

## 5.5.11 - 2026-11-17

### 与"可用成品"逐字节一致（10074 x64，install.wim 与 PE 通用）

用户提供了别人做好的、**已确认可用**的 10074 文件（`ci.dll`、`winload.efi`、`winresume.efi`），
逐字节反推得到标准配方，并已实现：

**`ci.dll`（4 处条件跳转改 `EB`）**

| 偏移 | 原字节 | 改为 |
| --- | --- | --- |
| `0x1D92D` | `74` | `eb` |
| `0x26F3B` | `75` | `eb` |
| `0x30930` | `74` | `eb` |
| `0x309A2` | `74` | `eb` |

**加载器（`winload`/`winresume` 的 `.efi` 与 `.exe` 四个文件）**

| 作用 | 改动 | 定位方式 |
| --- | --- | --- |
| 镜像哈希状态 | `8b d8 → 31 c0` | `mov [rsp+20h],eax ; call … ; mov ebx,eax ; test eax,eax ; jns 67 ; mov r8d,esi` |
| 完整性检查开关 | `88 4c 24 40 → b1 01 90 90` | `0f b6 4c 24 40 85 c0 41 0f 48 ce` 之后 |
| 备用镜像状态 | `8b f8 → 31 c0` | `8b f8 85 c0 0f 88 a5 00 00 00` |

验证（10074 原版 → 本工具输出 vs 参考文件）：

```
ci.dll         diff vs reference: 0
winload.efi    diff vs reference: 0
winresume.efi  diff vs reference: 0
```

**含 PE 校验和在内完全一致**。这套规则对 `/bootwim`（PE）与 `/image`（install.wim）同时生效，
也覆盖 Legacy 用的 `winload.exe` / `winresume.exe`（同为 x64 PE）。

## 5.5.10 - 2026-11-17

### 加载器：清掉"flight-signed"标记

10074 的加载器在报告"证书过期"之前，会先把镜像标记为 flight-signed：

```
41 81 4e 08 00 00 60 00      or dword [r14+8], 600000h
```

`/bootwim` 现在把这处 `or` 整体改成 NOP（每个加载器 1 处），并把紧随其后的
`mov ebx, 0C0000605h` 清零：

| 文件 | 改点 |
| --- | --- |
| `winload.efi` | `0x1C523`（标记）+ `0x1C52B`（过期状态） |
| `winresume.efi` | `0xA50F4` + `0xA50FC` |

理由：Legacy 过了引导、过了加载器，却在 Logo 之后 `PAGE_FAULT_IN_NONPAGED_AREA`，很可能是
内核拿到的"flight 签名策略"与补丁后的 CI 状态不一致导致的。

### UEFI 建议用已验证引导管理器

介质侧的补丁仍无法让 UEFI 通过（`0xc0000428`），而用 14357 的引导文件可以走到 PE 阶段，
因此 10074 的 UEFI 请直接：

```bat
nttimebomb /winpe D:\10074 /bootmgr-from D:\Patched_14357.1000_WinPE
```

## 5.5.9 - 2026-11-17

### 逐条核对 5.5.0 对 10074 的改动（结论：都对，但少了一处）

与用户提供的 5.5.0 修改版逐字节 diff，`winload.efi` 五处改动的**语义都是正确的**：

| 偏移 | 改动 | 语义 |
| --- | --- | --- |
| `0x1ADC9` | `75 04 → 90 90` | 吊销失败的 `jne` 改为顺序执行 → 走成功 |
| `0x4FDF7` | `0f 85 … → 90×6` | 镜像哈希门 |
| `0x50294` | `41 0F 48 CE → B1 01 90 90` | 强制"完整性检查已禁用" |
| `0x50669` | `BB 03 06 00 C0` 的立即数清零 | `mov ebx, 0C0000603h` → `mov ebx, 0`（完全正确，四字节） |
| `0x512B9` | `8B F8 → 33 FF` | 状态清零 |

**缺的一处**：加载器自己还会产"证书过期"——`winload.efi 0x1C52B`、`winresume.efi 0xA50FC`
（`or dword [r14+8], 600000h` 之后 `mov ebx, 0C0000605h`）。5.5.0 没有改这里。

本版只补这一处（每个加载器 1 处，`b?` 寄存器清零），**不再**做 5.5.6/5.5.7 那种大面积清零。

## 5.5.8 - 2026-11-17

### 回退：加载器"状态清零"不再默认启用

5.5.6/5.5.7 的做法（把加载器里所有 `mov reg, 0C0000605h` / `0C0000428h` 改成成功）实测
**过于粗暴**：Legacy 出现 CPU 停止错误，且结合"5.5.0 + 14357 引导文件仍蓝"的实验可以确认，
问题在 **wim 侧**而不是引导侧。

本版把该清零从默认流程移除（代码保留），`/bootwim` 恢复为 5.5.0 的语义：
镜像哈希门、catalog/alternate 门、0603 吊销、loader integrity option。

## 5.5.7 - 2026-11-17

### 修复 5.5.6 导致的 `/bootwim` 失败（`Unsupported or ambiguous structure`）

原因：计划缓冲区只有 32 个槽位（`MAX_EDITS`），而加载器状态清零要给 `winload.efi` 写
**39 处**，先执行清零就把槽位占满，随后的结构计划（哈希门等）无处可写 → 整体判为
"结构不识别"。

修复：

- `MAX_EDITS` 32 → **96**；
- 清零改为在**结构计划成功之后**追加（结构识别是前提，清零是附加项，槽位不够时自动放弃）。

实测（10074 原版 `winload.efi`，`/image` 流程）：

```
01759E … 01BB44   invalid image hash status becomes success   （39 处）
01C52B            expired status becomes success             （1 处）
```

## 5.5.6 - 2026-11-17

### 真正的 `0C0000605h` 产生点在加载器里，不在 `ci.dll`

用户提供的"改过的 ci.dll"经逐字节核对：`0x1D940 7e→eb`、`0x30930 74→eb` **确实已打上**
（另外只有校验和变化），但 Legacy 仍报 `0xc0000605`。继续在 `winload.efi` / `winresume.efi`
里搜索状态产出点，找到了：

| 文件 | 位置 | 指令 |
| --- | --- | --- |
| `winload.efi` | `0x1C52B` | `or dword [r14+8], 600000h ; mov ebx, 0C0000605h` |
| `winresume.efi` | `0xA50FC` | 同上 |

也就是说 **加载器自己** 也会产出"证书过期"。同时加载器里还有大量
`mov reg, 0C0000428h` 的早退路径（`winload.efi` 39 处、`winresume.efi` 34 处）。

`/bootwim` 现在会对每个加载器做状态清零：

```
[b8..bf] 05 06 00 c0  →  31 <reg> 90 90 90      （过期状态 → 成功）
[b8..bf] 28 04 00 c0  →  31 <reg> 90 90 90      （无效镜像哈希 → 成功）
```

上限 48 处，至少命中 1 处才生效；`Windows\System32\` 与 `Windows\System32\Boot\`
下的四个加载器都会处理。

## 5.5.5 - 2026-11-17

### `cdboot` 与 El Torito 内嵌副本也清空 `0C0000428h`

"选完启动项立即出现 Recovery、没有 Logo"这个现象，最可能是**光盘引导程序 cdboot** 在
校验 `bootmgr.efi` 时就失败（cdboot 是最先执行的那个，它自己的错误界面正是这个）。

10074 的 `cdboot.efi` 里有 **12 处** `mov eax, 0C0000428h`，之前只改了 2 处 `jns` 门。现在：

- `cdboot.efi`、`cdboot_noprompt.efi`：2 处 `jns` 门 + **12 处状态赋值**（共 64 字节变化）；
- `efisys.bin` / `efisys_noprompt.bin` 内嵌的那份同样处理（容器大小不变，各 64 字节）。

### 覆盖汇总（10074 x64，原版文件）

| 文件 | 改动 |
| --- | --- |
| `bootmgr.efi` | 7 门 + 惯用式 + 16 状态（104 字节） |
| `efi\boot\bootx64.efi` | 4 门 + 惯用式 + 14 状态（86 字节） |
| `cdboot.efi` | 2 门 + 12 状态（64 字节） |
| `efisys.bin` 内嵌副本 | 2 门 + 12 状态（64 字节） |

## 5.5.4 - 2026-11-17

### 清空引导管理器里所有 `0C0000428h` 返回值

10074 的现象是"选完启动项立即出现 Recovery 屏、没有 Logo"，说明拒绝发生在 **bootmgr**
阶段；同时 `/bootwim` 的输出证明 PE 内部（`ci.dll`、四个加载器、wim 里的引导管理器）都已
按预期改写。因此问题在 bootmgr 还有别的路径会返回 `STATUS_INVALID_IMAGE_HASH`。

本版新增：把 x64 引导管理器里**每一处** `mov eax, 0C0000428h`

```
b8 28 04 00 c0   →   31 c0 90 90 90
```

都改成返回成功（上限 32 处，至少 1 处才生效）。10074 实测：

| 文件 | 改动 |
| --- | --- |
| `bootmgr.efi` | 7 处状态门 + 1 处惯用式 + 16 处状态赋值（共 104 字节变化） |
| `efi\boot\bootx64.efi` | 4 处状态门 + 1 处惯用式 + 14 处状态赋值（共 86 字节变化） |

## 5.5.3 - 2026-11-17

### 状态惯用式补丁生效（10074 / 10546 / 14300 x64）

上一版里那个"唯一状态惯用式"的匹配没命中，原因是**掩码长度写多了 1 个字符**（模式 9 字节、
掩码 10 个 `x`），`at()` 逐字节比较时读到字符串结尾的 `\0` 就永远不相等。修正后：

```
85 c0 75 0a b8 28 04 00 c0   →   31 c0 90 90 90      （返回成功而不是 0C0000428h）
```

实测（原版文件）：

| Build | `bootmgr.efi` | `bootx64.efi` |
| --- | --- | --- |
| 10074 x64 | 7 处状态门 + `0x56FCD` 状态 | 4 处状态门 + `0x417DB` |
| 10546 x64 | 7 处状态门 + `0x573E5` | `0xBF578` 状态 |
| 14300 x64 | `0x57ECD` 状态 | `0x44E51` 状态 |

10546/14300 的引导管理器不匹配 late 规则（结构更靠后），但**惯用式在各自文件里唯一**，
因此仅凭这一处也能得到有效补丁；10074 则是"状态门 + 惯用式"双保险。

## 5.5.2 - 2026-11-17

### 10074 x64 的根因定位（进行中）

逐段反汇编 `ImgpValidateImageHash` 后确认：10074 的校验体有 **7 个跳向同一错误块的状态门**
（`bootmgr.efi`：`0x56863 0x568C3 0x568DF 0x56904 0x56936 0x56A2C 0x56A72`），并且错误状态由
一个**全文件唯一的惯用式**产生：

```
85 c0 75 0a b8 28 04 00 c0      test eax,eax ; jne ok ; mov eax, 0C0000428h
```

该惯用式在 10074 / 10546 / 14300 的 `bootmgr.efi` 与 `bootx64.efi` 里**各自唯一**
（`0x56FC9` / `0x417D7`、`0x573E1` / `0xBF574`、`0x57ECD` / `0x44E51`）。计划把它改成
`31 c0 90 90 90`（返回成功），这是下一版的主改点。

> 说明：本版已在代码里加入该改动（`plan_winpe_signature_x64` 与 late x64 规则内的同款检查），
> 但当前构建中该字节比较**未命中**（同样的字节用脚本能匹配、程序里返回 0），尚在排查，
> 因此 **10074 仍需下一版验证**；10546 x64 `bootmgr.efi` 已能命中 late 规则（7 处门）。

### 规则覆盖更新

- 10546 x64 `bootmgr.efi`：late x64（7 处状态门）；
- 10546 x64 `bootx64.efi`、14300 x64：仍未命中，继续用通用规则。

## 5.5.1 - 2026-11-17

### late x64 规则：释放整段校验错误路径（10074 等）

10074 x64 的失败原因是**同一段校验体里有多个跳向同一个错误块的状态门**，只补一处不足以放行。
现在规则会：

1. 先用唯一锚点（`8b d8 85 c0 0f 88` + `41 8b ?? 08` + `41 b9 02 00 01 00`）确定错误块目标；
2. 再把**所有跳向该目标的 `js`**（最多 12 处）一并改成 NOP。

实测 10074 x64：

| 文件 | 释放的状态门 |
| --- | --- |
| `bootmgr.efi` | `0x56863` `0x568C3` `0x568DF` `0x56904` `0x56936` `0x56A2C` `0x56A72`（7 处） |
| `efi\boot\bootx64.efi` | `0x4107A` `0x411FF` `0x413FC` `0x41422`（4 处） |

### 规则覆盖（x64，均已用原版文件验证命中）

| Build | `bootmgr.efi` | `bootx64.efi` |
| --- | --- | --- |
| 9879 | late x64 | late x64 |
| 10074 | late x64（7 处） | late x64（4 处） |
| 10587 | late x64 | late x64 |
| 10546 | late x64 | **未命中**（回退通用规则） |
| 14300 | **未命中**（回退通用规则） | 未命中 |

10546 的 `bootx64.efi` 与 14300 的 x64 引导管理器结构更靠后，需要单独的符号分析与规则，暂列已知限制。

## 5.5.0 - 2026-11-17

### 9841 代 x64 引导管理器：结构化规则（实验性）

x86 的三处改点在 x64 代码里不存在（寄存器分配与跳转编码都不同），因此改用**语义等价**的
结构规则：9841 的哈希校验体里有**一对相隔 `0x1A`、跳向同一错误块的 `js` 状态检查**
（`8b d8 85 c0 0f 88 …` 后跟 `48 8b 4c 24 78`），把两处 `js` 都改成 NOP 让流程继续走成功
路径。规则要求这对结构在文件内**唯一**，否则拒绝写盘。

实测（原版 9841）：

| 文件 | 改点（文件偏移） |
| --- | --- |
| `bootmgr.efi` | `0x5CE3D`、`0x5CE57`（各 6 字节 NOP） |
| `efi\boot\bootx64.efi` | `0x42D41`、`0x42D5B` |

**这一条是实验性的**：它只跳过校验体的错误分支，尚未经过启动验证。若 UEFI 仍被拒，
可继续用 `/winpe … /bootmgr-from <已证介质>`（已验证可启动）。

### `/winpe` 重新写入介质 BCD：`nointegritychecks on`

从 5.5.0 起，`/winpe` 在修补启动链后会把介质里的两个 BCD 存储
（`EFI\Microsoft\Boot\BCD` 与 `boot\bcd`）都设为 `nointegritychecks on`，避免以后出现
"补丁生效但加载器仍拒 ci.dll"的情况。需要管理员/SYSTEM 权限；权限不足时打印提示并跳过，
不影响其它文件。

### 9841 代规则扩展到 9926 x86

用微软符号服务器上的 9926 `bootmgr.pdb`（`965CB91E…`）确认 `ImgpValidateImageHash@44`
位于 `0x4EEEE`，并发现 9926 的调用点形态与 9841 相同、只是第二处尾部不同：

| 形态 | 尾部 | 适用 |
| --- | --- | --- |
| jns 形式 | `8b 4d 08 8b d6 53 e8` | 9841、9926 |
| js 形式 | `8d 4d 98 e8` | 9841 |
| flag 形式 | `f6 c3 20 0f 85` | 9926 |
| 校验体内状态门 | `8b 45 c8 8b d3 ff 75 e0` | 9841 |

规则会优先使用"jns + js + 状态门"这套已验证组合；当 js 形式不存在时（9926）改用 flag 形式。
实测 9926 x86：`bootmgr.efi` `0x4D82E`/`0x4D83F`，`bootia32.efi` `0x38D36`/`0x38D47`，
各两处状态清零；9841 仍保持原三处（与可用参考一致）。

### 10074 适配与文档

- **10074 x86**：命中 9841 代规则（flag 形式），无需改动：
  `bootmgr.efi 0x4A062/0x4A073`、`bootia32.efi 0x35E35/0x35E46`；
- **10074 x64**：结构不同（哈希校验体里只有**一处**状态门，且后续是 `mov ?,0x1000002`
  常量），新增 late x64 规则：`bootmgr.efi 0x56A2C`、`bootx64.efi 0x411FF`（各 6 字节 NOP）；
- 符号确认：10074 x64 `bootmgr.pdb`（`2A688135…`）中 `ImgpValidateImageHash` 位于 `0x57540`；
- `README.md` 补充 `/winpe` 的 BCD 行为、boot manager 布局支持表，并把 **9841 x64 标记为已实测通过**。

### 符号分析结论（供后续维护）

从微软符号服务器取得 9841 的 `bootmgr.pdb`（x86 `1375A1F5…`、x64 `A432737E…`）并解析出
公开符号：`ImgpValidateImageHash`（x86 `0x5218B` / x64 `0x5DA28`）、
`ImgpValidateSigningPolicy`（x86 `0x52D68` / x64 `0x5E7C8`）。x86 的两处状态清零调用的是
同一个无符号函数（`0x5318B`），x64 侧该调用是间接调用，故改为直接处理校验体。

## 5.4.6 - 2026-11-17

### 9841 代 32 位引导管理器：原生规则（已逐字节验证）

按用户提供的"9841 x86 可用修改版 vs 原版"做逐字节 diff，得到该布局的三处改点：

| 站点 | 原字节 | 改写 | 说明 |
| --- | --- | --- | --- |
| 哈希状态清零（jns 形式） | `8b f0` | `31 f6` | `mov esi,eax` → `xor esi,esi` |
| 哈希状态清零（js 形式） | `8b f0` | `31 f6` | 同上 |
| 状态分支 | `79` | `eb` | `jns` → `jmp` |

每处都要求在本文件内唯一命中，否则整体拒绝。实测：

- 用原版 `9841 bootmgr.efi` / `bootia32.efi` 跑 `/winpe`，输出三处改点
  （`0x508D5`/`0x50F82`/`0x5188B` 与 `0x376B8`/`0x37D65`/`0x3866E`）；
- 结果与用户提供的可用文件**逐字节完全一致（0 差异，含 PE 校验和）**。

x64 的 9841 布局与 x86 不同（x86 的三处签名在 x64 里不存在），原生规则仍需一份
x64 9841 的可用参考；在此之前用 `/winpe ... /bootmgr-from` 即可启动（已验证）。

## 5.4.5 - 2026-11-17

### `/winpe ... /bootmgr-from VERIFIED_MEDIA_ROOT`

针对 9841 这类"引导管理器布局比已验证集合更老、通用状态门放不过加载器"的情况，新增一个
一步到位的替换开关：

```bat
nttimebomb /winpe D:\boot /bootmgr-from D:\Patched_14357.1000_WinPE
```

- 从给定目录拷贝 `bootmgr.efi` 与 `efi\boot\bootx64.efi`，覆盖目标介质上的同名文件；
- 覆盖前自动保留 `FILE.bak`；
- 其余文件（`cdboot*.efi`、`efisys*.bin`、`bootmgr`、`boot.wim`）仍按 `/winpe`、`/bootwim`
  的结果保持不变。

这样 9841 的 UEFI 可以用已验证的 14316 引导管理器启动，不必手工拷文件。

## 5.4.4 - 2026-11-17

### `/winpe`：规则按文件角色选择（修正误判）

之前 cdboot 规则会在 `bootmgr.efi` / `bootx64.efi` / `memtest.efi` 里"碰巧"命中，
把引导管理器当成 CD 引导程序打了 2 处补丁（9841 实测输出里出现
`CD boot application layout`）。现在：

- `cdboot.efi`、`cdboot_noprompt.efi` 以及 `efisys*.bin` 里内嵌的副本 → **cdboot 规则**（2 处）；
- `bootmgr.efi`、`bootx64.efi`、`bootia32.efi`、`bootmgfw.efi`、`memtest*` → **引导管理器规则**
  （14316–14357 用已验证的 4 处；其他布局回退到通用状态门）；
- BIOS `bootmgr` 容器 → 通用规则。

9841 实测（修正后）：`bootmgr.efi` `0x5BB89/0x5C50E/0x5CF4C`、`bootx64.efi`
`0x41A8D/0x42412/0x42E50`、`cdboot*.efi` 各 2 处、`efisys*.bin` 内嵌 2 处。

### 已知限制：9841 的 UEFI 启动仍被拒

9841 的 `bootmgr.efi` 属于早期布局，通用状态门不足以放行 wim 里的 `winload.efi`，
UEFI 启动会停在 `0xc0000428`（"The digital signature for this file couldn't be verified"），
Legacy 正常。临时可用已验证的 14316 引导管理器替换（见 README「9841 UEFI note」）。

## 5.4.3 - 2026-11-17

### `/bcd`、`/bcd-show` 支持介质根目录，并同时处理两个 BCD 存储

- 以前只认 `EFI\Microsoft\Boot\BCD`；现在如果目标目录同时有 `boot\bcd`（BIOS 存储），
  `/bcd` 会把 `nointegritychecks on` 与 `recoveryenabled No` **两个存储都写入**，
  `/bcd-show` 也两个都打印；
- 参数说明改为 `ESP_OR_MEDIA_ROOT`，可以直接对整个解开的 ISO 目录执行：
  ```bat
  nttimebomb /bcd D:\media
  nttimebomb /bcd-show D:\media
  ```

### 文档

- Legacy 的 VMware `hypervMonitor_syn.c:940` panic 标注为**仅 99xx 系列构建**（其他版本不受影响）。

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
