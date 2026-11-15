# 32 位预览版 CI（`ci.dll`）过期补丁说明

本文说明本工具如何解除 32 位 FlightSigned 预览版的 **CI 证书过期**限制，以及已验证的
build 与改点。适合需要自己动手或核对补丁的人参考。

> 64 位预览版（如 9833 / 9860 x64）走的是另一条规则（`\SystemRoot\System32\ci.dll`
> 字面量锚定的过期回调），不在本文范围。

## 一、原理

Flightsigned 版本用 **flight 证书**签名系统文件，证书里写死了有效期。系统时间越过有效期后，
`ci.dll` 的签名校验会把「证书过期」当成失败，返回 `STATUS_IMAGE_CERT_EXPIRED`
（`0xC0000605`），于是系统文件被视为无效。

绕过办法不是伪造证书，而是让判定路径**不再返回**这个状态：

- 找到 `mov reg, 0C0000605h` 所在的"证书已过期"分支；
- 把**通往该分支**的条件跳转改成无条件跳转（或把跳转整体 NOP 掉），使代码永远走"未过期"一侧；
- 若某版本还会写入一个"已过期"的标志字节，则把该立即数从 `1` 改为 `0`。

参考方法：BetaRookie《如何解除 Flightsigned Build 的时间炸弹》（2021/10/3），其中明确写出
「把 `mov ???, 0C0000605h` 前面的条件跳转改为无条件跳转，或 NOP 掉跳转」以及
`CipReportAndReprieveUMCIFailure` / `g_CiDeveloperMode` 的处理方式。

`ci.dll` 只是第一层：`winload` / `winresume` 还要去掉镜像哈希校验与完整性选项强制
（本工具的 `/image` 会对这些文件一并处理）。

## 二、两种 32 位布局与已验证 build

### 布局 A：三处改点（9841 – 10074）

| Build | 证书起始分支 | flighting 分支 | 过期标志 |
| --- | --- | --- | --- |
| 9841 x86 | `0x13347` `7c→eb` | `0x19C7A` `75→eb` | `0x21C48` `01→00` |
| 9860 x86 | `0x1A2C1` | `0x20B90` | `0x277E2` |
| 9926 x86 | `0x17C2A` | `0x1E688` | `0x25670` |
| 10074 x86 | `0x1822E` | `0x1F1C8` | `0x26BA6`（`mov bh,1`） |

结构特征（匹配时使用，与 build 号无关）：

1. 证书起始分支：`mov eax,[ebp-x] ; cmp …, [esi+0c] ; jl ; jg 08 8b 45`；
2. flighting 分支：`test byte [addr],1 ; jne <任意位移> ; test byte [ebp+8],10h`；
3. 过期标志：`jbe +2 ; mov bl/bh,1`（接受 `b0`–`b7` 任意低字节寄存器）。

**9841 已与作者提供的修改版 `ci.dll` 逐字节比对：0 处差异（含 PE 校验和）。**

### 布局 B：单处闸门（10525 – 14347）

| Build | 过期闸门 |
| --- | --- |
| 10525 x86 | `0x26640` `74→eb` |
| 10546 x86 | `0x27582` `74→eb` |
| 10587 x86 | `0x2778A` `74→eb` |
| 14347 x86 | `0x2BD88` `74→eb` |

结构特征：

```
cmp eax,[绝对地址]      ; 证书起始时间
jae +2 ; mov cl,1       ; 置"已过期"标志
test cl,cl
je  +13                 ; ← 修改点：未过期时跳过下面的"过期块"
or  edi,0x600000        ; 置 flighting 状态位
mov [ebp-30],edi
mov esi,0C0000605h      ; STATUS_IMAGE_CERT_EXPIRED
jmp 返回
```

把 `je`（`74`）改成 `jmp`（`eb`）后，"未过期"分支永远成立，过期块不再执行。
每个文件里 `mov r32, 0C0000605h` **只有一处**，且符合条件的跳转**只有一处**，因此规则要
求唯一命中，不一致就整体拒绝。

## 三、安全设计

- 两个布局都要求：要么三处全部唯一命中，要么单闸门唯一命中；否则**不写任何文件**；
- 修改后重算 PE 校验和；
- `/image` 是原子的：CI 与任一 loader 不识别时整体中止，不会留下半套补丁；
- 每个被改动文件都在同目录留下 `FILE.bak`（含权限与时间戳），可用 `/restore` 回退。

## 四、用法

```bat
:: WinPE 或 SYSTEM，指向挂载好的映像根
nttimebomb.cmd /image W:\
:: 也可指定引导分区与恢复分区
nttimebomb.cmd /image W:\ /boot S:\ /recovery W:\Recovery
:: 回退
nttimebomb.cmd /restore W:\
```

输出示例（10525 x86）：

```
W:\Windows\System32\ci.dll
  026640  CI certificate expiry gate
W:\Windows\System32\winload.efi
  ...     image hash status gate
  ...     catalog status gate
  ...     loader integrity option
...
Verified offline updates in W:\
```

## 五、验证记录

| Build | CI 改点 | loader | 结果 |
| --- | --- | --- | --- |
| 9841 x86 | 3 处 | winload.efi/.exe、winresume.efi/.exe | 与参考补丁 0 差异 |
| 9860 x86 | 3 处 | 同上 | 通过 |
| 9926 x86 | 3 处 | 同上 | 通过 |
| 10074 x86 | 3 处 | 同上 | 通过 |
| 10525 x86 | 1 处 | 同上 | 通过 |
| 10546 x86 | 1 处 | 同上 | 通过 |
| 10587 x86 | 1 处 | 同上 | 通过 |
| 14347 x86 | 1 处 | 同上 | 通过 |

## 六、已知限制

- 只覆盖 32 位预览版的 `ci.dll`；64 位预览版由另一条规则处理；
- 布局 B 只改"过期闸门"这一处。如果某个 build 的 `ci.dll` 还有第二处独立写过期的路径，
  需要单独补规则（工具会拒绝而不是猜）；
- `bootmgr` / `bootmgr.efi` 的压缩体不在本工具处理范围内（README 有说明）。
