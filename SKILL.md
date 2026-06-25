---
name: "r2-mcp-analyzer"
description: "Radare2 + eDBG MCP服务分析技能。基于R2-MCP服务进行静态逆向分析（函数识别、字符串提取、反编译、交叉引用追踪），基于eDBG进行动态调试（断点、内存、寄存器、运行时追踪），生成结构化分析报告。当用户需要逆向分析二进制文件或动态调试时触发此技能。"
---

# Radare2 MCP 二进制分析技能

基于 Radare2 MCP 服务对二进制文件进行深度逆向分析并生成结构化报告。

## 核心原则

**本技能不预设固定分析内容，而是根据用户的具体分析需求动态执行分析。**

用户可以指定：

- 二进制文件路径
- 分析目标（函数、字符串、交叉引用、反编译等）
- 分析深度（基础信息、函数列表、反编译伪代码、完整逆向报告）
- 特定地址范围或函数名过滤

### 分析决策框架

```
用户意图
├─ "这个程序做了什么"        → 架构概览路径（T1）
├─ "找到XXX函数在哪"         → 函数定位路径（T2）
├─ "有没有安全隐患"          → 安全审计路径（T4）
├─ "网络请求/URL在哪"         → 网络追踪路径（T3）
├─ "这个函数谁调用了"         → 调用链追踪路径（T5）
├─ "这段汇编什么意思"         → 反编译/反汇编路径（T6）
├─ "有没有加壳/混淆"          → 保护机制识别路径（T7）
└─ 模糊意图                  → 先获取文件信息建立全局认知，再追问细化
```

**关键判断：** 用户说"分析"时往往隐含了"理解逻辑"或"找到漏洞"的意图。分析过程中应主动记录关键发现，为后续深入分析积累素材。

***

# 第一部分：快速入门

## 1.1 核心流程

> **必须先调用** **`r2_open_file`** → 获取 `session_id` → 后续所有调用都需要此 ID

| 工具                      | 用途                     | 关键参数                                 |
| ----------------------- | ---------------------- | ------------------------------------ |
| `r2_open_file`          | 打开二进制文件，获取 session\_id | file\_path, auto\_analyze            |
| `r2_get_info`           | 获取文件详细信息（架构、平台、类型）     | session\_id                          |
| `r2_list_functions`     | 列出已识别的函数               | session\_id, filter                  |
| `r2_list_strings`       | 列出二进制中的字符串             | session\_id, min\_length             |
| `r2_decompile_function` | 反编译函数为伪代码              | session\_id, address                 |
| `r2_disassemble`        | 反汇编指定地址                | session\_id, address, lines          |
| `r2_get_xrefs`          | 获取交叉引用                 | session\_id, address, direction      |
| `r2_analyze_target`     | 执行特定分析策略               | session\_id, strategy                |
| `r2_run_command`        | 执行任意 r2 命令             | session\_id, command                 |
| `r2_config_manager`     | 管理分析配置                 | session\_id, action, key             |
| `r2_analysis_hints`     | 管理分析提示（修正分析错误）         | session\_id, action                  |
| `r2_manage_xrefs`       | 管理交叉引用                 | session\_id, action, target\_address |
| `r2_close_session`      | 关闭会话释放资源               | session\_id                          |

## 1.2 分析策略选择器

| 分析目标   | 推荐策略/工具                 | 说明           |
| ------ | ----------------------- | ------------ |
| 快速了解文件 | `r2_get_info`           | 架构、平台、文件类型   |
| 查看所有函数 | `r2_list_functions`     | 支持名称过滤       |
| 查找字符串  | `r2_list_strings`       | URL、密钥、错误信息等 |
| 理解函数逻辑 | `r2_decompile_function` | 生成类 C 伪代码    |
| 查看汇编指令 | `r2_disassemble`        | 精确的汇编级分析     |
| 追踪调用关系 | `r2_get_xrefs`          | 谁调用了/被谁调用    |
| 深度分析   | `r2_analyze_target`     | 多种策略可选       |

## 1.3 常见陷阱

**#1 大文件处理：**

```
OK:   r2_open_file(file_path="large.bin", auto_analyze=false)  (大文件 >10MB 先不开分析)
OK:   后续手动调用 r2_analyze_target(strategy="basic")         (按需分析)
BAD:  r2_open_file(file_path="large.bin", auto_analyze=true)    (大文件可能超时)
```

**#2 地址格式：**

```
OK:   address="0x401000"        (十六进制，带 0x 前缀)
OK:   address="sym.main"        (符号名)
OK:   address="main"           (函数名)
BAD:  address="401000"          (缺少 0x 前缀可能被误解)
```

**#3 会话管理：**

```
OK:   打开文件 → 分析 → 关闭会话（释放资源）
BAD:  打开多个文件不关闭（资源泄漏）
BAD:  关闭会话后继续使用 session_id
```

**#4 分析策略选择：**

```
OK:   先 basic(aa) → 再按需 blocks/calls/refs
OK:   小文件直接 full(aaa)
BAD:  大文件直接 full(aaa)（极耗时）
```

**#5 函数截断问题：**

```
症状:  反编译结果不完整，函数看起来被截断
修复:  r2_analyze_target(strategy="blocks") 修复基本块结构
      r2_config_manager(action="set", key="anal.hasnext", value="true")
```

**#6 字符串搜索不到：**

```
症状:  r2_list_strings 找不到目标字符串
修复:  r2_config_manager(action="set", key="bin.str.min", value="3") 降低最小长度
      r2_list_strings(mode="all") 搜索所有段（包括代码段中的字符串）
```

***

# 第二部分：工具规范

## 2.1 r2\_open\_file

打开二进制文件并创建分析会话。**必须第一个调用。** 返回 `session_id`，后续所有工具都需要此 ID。

**参数：**

| 参数            | 必填 | 默认值  | 说明                                     |
| ------------- | -- | ---- | -------------------------------------- |
| file\_path    | 是  | -    | 二进制文件的完整路径                             |
| auto\_analyze | 否  | true | 是否自动执行基础分析 (aa)。大文件 (>10MB) 建议设为 false |
| session\_id   | 否  | -    | 可选：复用现有会话 ID                           |

**返回字段：**

| 字段           | 说明                  |
| ------------ | ------------------- |
| `session_id` | **保存此值** — 后续所有调用必需 |

**注意事项：**

- 大文件（>10MB）强烈建议 `auto_analyze=false`，避免超时
- 如需深度分析，可后续调用 `r2_analyze_file` 或 `r2_analyze_target`

## 2.2 r2\_get\_info

获取二进制文件的详细信息。**打开文件后首先调用此工具了解文件基本信息。**

**参数：**

| 参数          | 必填 | 默认值   | 说明         |
| ----------- | -- | ----- | ---------- |
| session\_id | 是  | -     | 来自 open 结果 |
| detailed    | 否  | false | 是否返回详细信息   |

**返回关键信息：**

| 字段               | 说明                                |
| ---------------- | --------------------------------- |
| 架构 (arch)        | x86, arm, aarch64, mips 等         |
| 位数 (bits)        | 32 或 64                           |
| 平台 (os)          | linux, windows, android, darwin 等 |
| 文件类型 (type)      | ELF, PE, DEX, Mach-O 等            |
| 端序 (endian)      | little 或 big                      |
| 入口点 (entrypoint) | 程序入口地址                            |
| bintype          | 具体二进制格式                           |

**用途：** 根据文件信息决定后续分析策略（如 ARM 代码需要不同的分析思路）。

## 2.3 r2\_list\_functions

列出二进制文件中已识别的函数。使用 `afl` 命令。

**参数：**

| 参数          | 必填 | 默认值 | 说明                                 |
| ----------- | -- | --- | ---------------------------------- |
| session\_id | 是  | -   | 来自 open 结果                         |
| filter      | 否  | ""  | 函数名过滤器（如 'sym.Java' 只显示 Java 相关函数） |
| limit       | 否  | 500 | 最大返回数量（默认 500）                     |

**返回信息：**

| 字段 | 说明                                |
| -- | --------------------------------- |
| 地址 | 函数起始地址                            |
| 名称 | 函数符号名（如 sym.main, sym.imp.printf） |
| 大小 | 函数字节大小                            |

**过滤技巧：**

| 过滤器        | 用途                   |
| ---------- | -------------------- |
| `sym.main` | 查找 main 函数           |
| `sym.imp.` | 查找导入函数（库调用）          |
| `sym.Java` | 查找 Java 相关函数（DEX 文件） |
| `sym.sub.` | 查找子程序（内部函数）          |
| `fcn.`     | 查找 R2 自动识别的函数        |
| `loc.`     | 查找数据标签/位置            |

## 2.4 r2\_list\_strings

列出二进制文件中的字符串。通过配置 `bin.str.min` 进行底层过滤。

**参数：**

| 参数          | 必填 | 默认值  | 说明                             |
| ----------- | -- | ---- | ------------------------------ |
| session\_id | 是  | -    | 来自 open 结果                     |
| min\_length | 否  | 5    | 最小字符串长度（默认 5）                  |
| mode        | 否  | data | 搜索模式：'data' (iz) 或 'all' (izz) |

**模式说明：**

| 模式     | r2 命令 | 说明                  |
| ------ | ----- | ------------------- |
| `data` | iz    | 仅搜索数据段中的字符串（推荐，速度快） |
| `all`  | izz   | 搜索所有段（包括代码段），更全面但更慢 |

**使用技巧：**

- 如果找不到目标字符串，尝试降低 `min_length` 到 3-4
- 使用 `mode="all"` 搜索代码段中嵌入的字符串
- 字符串结果可用于定位功能代码（通过交叉引用）

## 2.5 r2\_decompile\_function

反编译指定地址的函数为伪代码。使用 `pdc` 命令。

**参数：**

| 参数          | 必填 | 默认值 | 说明                             |
| ----------- | -- | --- | ------------------------------ |
| session\_id | 是  | -   | 来自 open 结果                     |
| address     | 是  | -   | 函数地址（十六进制格式，如 0x401000 或 main） |

**输出：** 类 C 语言的伪代码，比汇编更易理解。

**最佳实践：**

- 先用 `r2_list_functions` 找到目标函数地址
- 反编译前确保已执行足够深度的分析（至少 basic）
- 如果伪代码不完整，尝试 `r2_analyze_target(strategy="blocks")`

## 2.6 r2\_disassemble

反汇编指定地址的代码。使用 `pd` 命令。

**参数：**

| 参数          | 必填 | 默认值 | 说明             |
| ----------- | -- | --- | -------------- |
| session\_id | 是  | -   | 来自 open 结果     |
| address     | 是  | -   | 起始地址（十六进制格式）   |
| lines       | 否  | 10  | 反汇编行数（默认 10 行） |

**用途：**

- 查看精确的汇编指令
- 理解编译器生成的具体代码
- 验证反编译结果的准确性
- 分析底层漏洞（如缓冲区溢出）

## 2.7 r2\_get\_xrefs

获取指定地址/函数的交叉引用。

**参数：**

| 参数          | 必填 | 默认值 | 说明                            |
| ----------- | -- | --- | ----------------------------- |
| session\_id | 是  | -   | 来自 open 结果                    |
| address     | 是  | -   | 目标地址或函数名                      |
| direction   | 否  | to  | 方向：'to'（谁引用了它）或 'from'（它引用了谁） |
| limit       | 否  | 50  | 最大返回数量（默认 50）                 |

**方向说明：**

| 方向     | 含义               | 用途          |
| ------ | ---------------- | ----------- |
| `to`   | 谁调用了这个函数/引用了这个数据 | 找调用者，追踪调用链  |
| `from` | 这个函数调用了谁/引用了什么数据 | 理解函数内部逻辑和依赖 |

**使用场景：**

- 找到某个函数的所有调用者：`direction="to"`
- 理解某个函数内部调用了哪些子函数：`direction="from"`
- 追踪字符串在哪里被使用：对字符串地址使用 `direction="to"`

## 2.8 r2\_analyze\_target

执行特定的 Radare2 递归分析策略。

**参数：**

| 参数          | 必填 | 默认值 | 说明           |
| ----------- | -- | --- | ------------ |
| session\_id | 是  | -   | 来自 open 结果   |
| strategy    | 是  | -   | 分析策略（见下表）    |
| address     | 否  | -   | 指定分析的起始地址或符号 |

**策略说明：**

| 策略         | r2 命令 | 说明               | 适用场景         | 耗时     |
| ---------- | ----- | ---------------- | ------------ | ------ |
| `basic`    | aa    | 基础分析，识别符号和入口点    | 所有文件的起点      | 低      |
| `blocks`   | aab   | 分析基本块结构（修复函数截断）  | 函数被截断时       | 低      |
| `calls`    | aac   | 递归分析函数调用目标       | 发现未识别的子函数    | 中      |
| `refs`     | aar   | 分析数据引用（字符串、全局变量） | 识别字符串引用      | 中      |
| `pointers` | aad   | 分析数据段指针          | C++ 虚表、跳转表恢复 | 中      |
| `full`     | aaa   | 全量深度分析           | 小文件或必要时      | **极高** |

**策略选择建议：**

```
小文件 (<5MB):   basic → 按需 calls/refs → 必要时 full
中等文件 (5-50MB): basic → 按需 calls/refs (避免 full)
大文件 (>50MB):   basic → 精确分析特定地址 (避免全局分析)
```

## 2.9 r2\_run\_command

在指定会话中执行任意 Radare2 命令。

**参数：**

| 参数          | 必填 | 说明         |
| ----------- | -- | ---------- |
| session\_id | 是  | 来自 open 结果 |
| command     | 是  | Radare2 命令 |

**常用命令参考：**

| 命令                 | 用途                           | 示例输出     |
| ------------------ | ---------------------------- | -------- |
| `afl~sym.main`     | 查找 main 函数                   | 函数地址和大小  |
| `iz~http`          | 搜索包含 http 的字符串               | URL 列表   |
| `ii`               | 列出导入函数                       | 所有导入的库函数 |
| `iE`               | 列出导出函数                       | 所有导出的函数  |
| `is`               | 列出符号表                        | 所有符号     |
| `pdf @ sym.main`   | 打印 main 函数的反汇编               | 完整汇编代码   |
| `px 64 @ 0x400000` | 打印 64 字节的十六进制数据              | 内存数据     |
| `q`                | 退出（不要用，用 r2\_close\_session） | -        |

## 2.10 r2\_config\_manager

管理 Radare2 的分析与显示配置。

**参数：**

| 参数          | 必填 | 说明               |
| ----------- | -- | ---------------- |
| session\_id | 是  | 来自 open 结果       |
| action      | 是  | get / set / list |
| key         | 是  | 配置键名             |
| value       | 否  | 设置的新值（仅 set 需要）  |

**关键配置参考：**

| 配置键               | 说明         | 推荐值            |
| ----------------- | ---------- | -------------- |
| `anal.strings`    | 开启字符串引用分析  | true           |
| `anal.datarefs`   | 代码引用数据     | true           |
| `anal.hasnext`    | 继续分析后续代码   | true           |
| `anal.jmp.after`  | 无条件跳转后继续分析 | true           |
| `anal.bb.maxsize` | 基本块大小限制    | 512 (默认)       |
| `bin.str.min`     | 字符串最小长度    | 3-5            |
| `anal.in`         | 分析范围       | io.maps (所有映射) |
| `asm.comments`    | 显示注释       | true           |
| `asm.decompiler`  | 反编译器选择     | pdc            |
| `scr.color`       | 彩色输出       | 0 (关闭，便于解析)    |

## 2.11 r2\_analysis\_hints

管理分析提示，用于修正 R2 的分析错误或优化显示。

**参数：**

| 参数          | 必填 | 说明             |
| ----------- | -- | -------------- |
| session\_id | 是  | 来自 open 结果     |
| action      | 是  | 操作类型（见下表）      |
| address     | 否  | 目标地址（默认当前光标位置） |
| value       | 否  | 参数值            |

**操作类型：**

| 操作                | 说明          | 示例                                                    |
| ----------------- | ----------- | ----------------------------------------------------- |
| `list`            | 列出当前地址的提示   | 查看已有提示                                                |
| `set_base`        | 修改立即数显示进制   | value='10' (十进制), '16' (十六进制), 's' (字符串), 'i' (IP 地址) |
| `set_arch`        | 强制指定后续代码的架构 | value='arm', 'x86'                                    |
| `set_bits`        | 强制指定位数      | value='16', '32', '64'                                |
| `override_jump`   | 强制指定跳转目标    | 修复间接跳转                                                |
| `override_opcode` | 自定义指令显示文本   | 替换当前指令                                                |
| `remove`          | 清除当前地址的所有提示 | 恢复默认                                                  |

**使用场景：**

- 代码被错误识别为数据：设置正确的架构和位数
- 立即数难以理解：切换显示进制（十进制/IP地址）
- 间接跳转目标错误：手动指定跳转目标

## 2.12 r2\_manage\_xrefs

管理代码和数据的交叉引用。

**参数：**

| 参数              | 必填 | 说明          |
| --------------- | -- | ----------- |
| session\_id     | 是  | 来自 open 结果  |
| action          | 是  | 操作类型        |
| target\_address | 是  | 目标地址或符号     |
| source\_address | 否  | 源地址（添加操作需要） |

**操作类型：**

| 操作           | r2 命令 | 说明          |
| ------------ | ----- | ----------- |
| `list_to`    | axt   | 查询谁引用了目标地址  |
| `list_from`  | axf   | 查询目标地址引用了谁  |
| `add_code`   | axc   | 手动添加代码引用    |
| `add_call`   | axC   | 手动添加函数调用引用  |
| `add_data`   | axd   | 手动添加数据引用    |
| `add_string` | axs   | 手动添加字符串引用   |
| `remove_all` | ax-   | 删除指定地址的所有引用 |

## 2.13 r2\_close\_session

关闭 Radare2 会话，释放资源。

**参数：**

| 参数          | 必填 | 说明        |
| ----------- | -- | --------- |
| session\_id | 是  | 要关闭的会话 ID |

**最佳实践：**

- 分析完成后及时关闭会话
- 长时间不用的会话也应关闭
- 不要在关闭后继续使用该 session\_id

***

# 第三部分：文件类型与场景

## 3.1 支持的文件类型

| 文件类型   | 扩展名              | 特点                 | 分析要点       |
| ------ | ---------------- | ------------------ | ---------- |
| ELF    | .so, .elf, 无扩展名  | Linux/Android 原生库  | 导入导出函数、符号表 |
| PE     | .exe, .dll, .sys | Windows 可执行文件      | 导入表、资源段、节区 |
| DEX    | .dex             | Android Dalvik 字节码 | 类、方法、字符串   |
| Mach-O | 无扩展名             | macOS/iOS 可执行文件    | 段结构、符号     |
| 脚本     | 各种               | 解释型脚本              | 字符串提取为主    |

## 3.2 分析场景速查

**功能分析：**

| 场景    | 推荐方法                                     | 说明          |
| ----- | ---------------------------------------- | ----------- |
| 程序入口  | `r2_get_info` → 入口点地址 → `r2_disassemble` | 从入口开始追踪执行流  |
| 主要功能  | `r2_list_functions` → 过滤关键函数名            | 按名称定位功能函数   |
| 字符串线索 | `r2_list_strings` → 搜索关键词                | URL、密钥、错误信息 |
| 函数逻辑  | `r2_decompile_function`                  | 伪代码理解算法     |
| 库函数调用 | `r2_list_functions` filter="sym.imp."    | 查看使用了哪些库    |

**安全分析：**

| 场景   | 推荐方法                          | 说明                      |
| ---- | ----------------------------- | ----------------------- |
| 漏洞搜索 | `r2_list_strings` 搜索危险函数名     | strcpy, sprintf, gets 等 |
| 加密识别 | 搜索 AES, RSA, DES, MD5 字符串     | 定位加密函数                  |
| 网络通信 | 搜索 URL、IP、socket 字符串          | 定位网络功能                  |
| 权限检查 | 搜索 uid, gid, setuid 字符串       | 定位权限相关代码                |
| 反调试  | 搜索 ptrace, debugger, trap 字符串 | 定位反调试机制                 |

**逆向工程：**

| 场景   | 推荐方法                                     | 说明          |
| ---- | ---------------------------------------- | ----------- |
| 算法还原 | `r2_decompile_function` + `r2_get_xrefs` | 理解核心算法      |
| 协议分析 | 字符串 + 交叉引用 + 反编译                         | 还原通信协议      |
| 加壳检测 | `r2_get_info` + `r2_list_functions`      | 函数数量异常少可能加壳 |
| 混淆识别 | 查看函数名和代码模式                               | 异常的命名和结构    |

## 3.3 搜索模式速查

| 目标         | 工具                  | 参数                             |
| ---------- | ------------------- | ------------------------------ |
| 查找 main 函数 | `r2_list_functions` | filter="main"                  |
| 查找导入函数     | `r2_list_functions` | filter="sym.imp."              |
| 查找 URL     | `r2_list_strings`   | min\_length=8, 然后过滤 http/https |
| 查找 IP 地址   | `r2_list_strings`   | min\_length=7, 然后过滤 IP 模式      |
| 查找密钥/密码    | `r2_list_strings`   | 搜索 key, pass, secret, token    |
| 查找危险函数     | `r2_list_functions` | filter="strcpy\|sprintf\|gets" |
| 追踪函数调用     | `r2_get_xrefs`      | direction="to"                 |
| 查看函数依赖     | `r2_get_xrefs`      | direction="from"               |
| 自定义搜索      | `r2_run_command`    | command="iz\~keyword"          |

## 3.4 进阶分析策略

**锚点扩散法** — 从已知信息出发，逐步扩大分析范围：

```
1. r2_list_strings(min_length=5)  → 找到关键字符串（如 URL、API 路径）
2. r2_get_xrefs(address=<字符串地址>, direction="to")  → 找到引用此字符串的函数
3. r2_decompile_function(address=<引用函数>)  → 理解使用逻辑
4. r2_get_xrefs(address=<引用函数>, direction="to")  → 找到谁调用了这个函数
5. 重复步骤 3-4 扩大分析范围
```

**函数追踪法** — 理解程序的执行流程：

```
1. r2_get_info()  → 获取入口点地址
2. r2_disassemble(address=<入口点>)  → 查看入口代码
3. r2_get_xrefs(address=<被调用函数>, direction="from")  → 查看入口调用了哪些函数
4. r2_decompile_function(address=<关键子函数>)  → 理解子函数逻辑
5. 递归追踪每个子函数的内部调用
```

**导入函数分析法** — 通过库调用推断程序功能：

```
1. r2_list_functions(filter="sym.imp.")  → 列出所有导入函数
2. 按功能分类导入函数：
   - 网络: connect, send, recv, socket, getaddrinfo
   - 文件: fopen, fread, fwrite, open, close
   - 加密: AES_encrypt, RSA_public_encrypt, MD5
   - 内存: malloc, free, memcpy, memset
   - 线程: pthread_create, pthread_mutex_lock
3. 对感兴趣的导入函数使用 r2_get_xrefs(direction="to")  → 找到使用位置
4. 分析使用导入函数的上下文
```

***

# 第四部分：工作流模板

### T1: 二进制文件概览

```
1. r2_open_file(file_path="target", auto_analyze=true)
   → session_id

2. r2_get_info(session_id, detailed=true)
   → 架构、平台、文件类型、入口点、段信息

3. r2_list_functions(session_id, filter="sym.imp.", limit=50)
   → 导入函数列表（了解使用了哪些库）

4. r2_list_functions(session_id, limit=100)
   → 所有函数概览（了解程序规模和结构）

5. r2_list_strings(session_id, min_length=8)
   → 关键字符串（URL、版本信息、错误消息）

6. r2_disassemble(session_id, address=<入口点>, lines=30)
   → 入口点代码，了解程序启动流程

7. r2_close_session(session_id)
```

### T2: 定位特定功能

```
1. r2_open_file(file_path="target", auto_analyze=true)
   → session_id

2. r2_list_strings(session_id, min_length=5)
   → 搜索与目标功能相关的字符串

3. r2_get_xrefs(session_id, address=<相关字符串地址>, direction="to")
   → 找到引用这些字符串的函数

4. r2_list_functions(session_id, filter="<关键词>")
   → 按名称搜索相关函数

5. r2_decompile_function(session_id, address=<目标函数>)
   → 反编译理解函数逻辑

6. r2_get_xrefs(session_id, address=<目标函数>, direction="to")
   → 找到谁调用了这个函数

7. r2_close_session(session_id)
```

### T3: 网络通信分析

```
1. r2_open_file(file_path="target", auto_analyze=true)
   → session_id

2. r2_list_strings(session_id, min_length=8)
   → 提取所有 URL、域名、IP 地址

3. r2_list_functions(session_id, filter="sym.imp.")
   → 查找网络相关导入: connect, send, recv, socket, gethostbyname, getaddrinfo

4. r2_get_xrefs(session_id, address=<网络函数>, direction="to")
   → 找到网络调用的位置

5. r2_decompile_function(session_id, address=<网络调用所在函数>)
   → 理解网络通信逻辑

6. r2_get_xrefs(session_id, address=<网络处理函数>, direction="to")
   → 追踪完整的网络调用链

7. r2_close_session(session_id)
```

### T4: 安全漏洞分析

```
1. r2_open_file(file_path="target", auto_analyze=true)
   → session_id

2. r2_list_functions(session_id, filter="sym.imp.")
   → 查找危险函数: strcpy, strcat, sprintf, gets, system, exec

3. r2_get_xrefs(session_id, address=<危险函数>, direction="to")
   → 找到危险函数的所有调用位置

4. r2_disassemble(session_id, address=<调用位置>, lines=20)
   → 检查缓冲区大小和输入验证

5. r2_list_strings(session_id, min_length=5)
   → 查找硬编码密钥、密码、token

6. r2_list_functions(session_id, filter="ptrace|debug|trap")
   → 查找反调试机制

7. r2_close_session(session_id)
```

### T5: 调用链追踪

```
1. r2_open_file(file_path="target", auto_analyze=true)
   → session_id

2. r2_analyze_target(session_id, strategy="calls")
   → 确保所有函数调用关系被分析

3. r2_get_xrefs(session_id, address=<目标函数>, direction="to")
   → 找到所有直接调用者

4. 对每个调用者递归执行 r2_get_xrefs(direction="to")
   → 构建完整的调用树

5. r2_get_xrefs(session_id, address=<目标函数>, direction="from")
   → 理解目标函数内部调用了什么

6. r2_decompile_function(session_id, address=<调用链中的关键函数>)
   → 反编译理解每层逻辑

7. r2_close_session(session_id)
```

### T6: 反编译与伪代码分析

```
1. r2_open_file(file_path="target", auto_analyze=true)
   → session_id

2. r2_analyze_target(session_id, strategy="basic")
   → 确保基础分析完成

3. r2_list_functions(session_id, filter="<目标函数名>")
   → 获取目标函数地址

4. r2_decompile_function(session_id, address=<目标函数地址>)
   → 获取伪代码

5. 如果伪代码不完整:
   r2_analyze_target(session_id, strategy="blocks")
   r2_config_manager(session_id, action="set", key="anal.hasnext", value="true")
   r2_decompile_function(session_id, address=<目标函数地址>)
   → 重新反编译

6. r2_disassemble(session_id, address=<目标函数地址>, lines=50)
   → 对比汇编验证伪代码准确性

7. r2_close_session(session_id)
```

### T7: 加壳/保护机制识别

```
1. r2_open_file(file_path="target", auto_analyze=false)
   → session_id（大文件先不开分析）

2. r2_get_info(session_id, detailed=true)
   → 查看段信息、入口点

3. r2_list_functions(session_id, limit=20)
   → 查看函数数量（加壳程序通常只有少量函数）

4. r2_list_strings(session_id, min_length=4)
   → 查看字符串（加壳程序字符串很少）

5. r2_disassemble(session_id, address=<入口点>, lines=50)
   → 查看入口代码（加壳程序入口通常是解壳代码）

判断标准:
- 函数数量极少（<10）且文件较大 → 可能加壳
- 入口代码大量 push/pop 和循环 → 可能是解壳代码
- 段名异常（如 .upx0, .vmp0）→ 已知壳
- 字符串极少 → 可能被加密

6. r2_close_session(session_id)
```

***

# 第五部分：高级技巧

## 5.1 分析策略优化

**按文件大小选择策略：**

| 文件大小    | 推荐策略                       | 原因        |
| ------- | -------------------------- | --------- |
| < 1MB   | basic → 按需 full            | 小文件可以完整分析 |
| 1-10MB  | basic → 按需 calls/refs      | 中等文件选择性分析 |
| 10-50MB | basic → 精确分析特定函数           | 大文件避免全局分析 |
| > 50MB  | auto\_analyze=false → 手动分析 | 超大文件需精确控制 |

**分析深度递进：**

```
Level 0: r2_get_info                    → 文件基本信息
Level 1: r2_list_functions + strings    → 函数和字符串概览
Level 2: r2_analyze_target(basic)        → 基础分析
Level 3: r2_analyze_target(calls/refs)  → 调用和数据引用分析
Level 4: r2_decompile_function          → 反编译伪代码
Level 5: r2_analyze_target(full)        → 全量深度分析（谨慎使用）
```

## 5.2 常见问题修复

**函数截断：**

```
症状: 反编译结果不完整，函数提前结束
原因: R2 未正确识别函数边界
修复:
  1. r2_analyze_target(strategy="blocks", address=<截断函数>)
  2. r2_config_manager(action="set", key="anal.hasnext", value="true")
  3. r2_config_manager(action="set", key="anal.jmp.after", value="true")
  4. 重新反编译
```

**间接跳转未解析：**

```
症状: 反编译中出现 "jump [未知地址]" 或 switch 语句不完整
修复:
  1. r2_analyze_target(strategy="pointers", address=<跳转表地址>)
  2. r2_config_manager(action="set", key="anal.jmp.tbl", value="true")
  3. 或使用 r2_analysis_hints(action="override_jump") 手动指定跳转目标
```

**代码被识别为数据：**

```
症状: 应该是代码的区域显示为数据字节
修复:
  1. r2_analysis_hints(action="set_arch", value="<正确架构>")
  2. r2_analysis_hints(action="set_bits", value="<正确位数>")
  3. r2_run_command(command="af @ <地址>") 重新分析为函数
```

**字符串引用缺失：**

```
症状: 知道字符串存在但找不到引用
修复:
  1. r2_config_manager(action="set", key="anal.strings", value="true")
  2. r2_analyze_target(strategy="refs")
  3. r2_manage_xrefs(action="add_string", target_address=<字符串地址>)
```

## 5.3 架构特定技巧

**ARM/AArch64：**

| 特点             | 分析建议                          |
| -------------- | ----------------------------- |
| Thumb/ARM 模式切换 | 注意函数地址最低位（1=Thumb, 0=ARM）     |
| 条件执行指令         | 很多指令带条件码，注意分析分支逻辑             |
| PLT/GOT        | 导入函数通过 PLT 调用，追踪到 GOT 表获取实际地址 |
| PIC/PIE        | 位置无关代码，地址可能需要重定位              |

**x86/x64：**

| 特点   | 分析建议                                                      |
| ---- | --------------------------------------------------------- |
| 调用约定 | cdecl（x86）/ System V AMD64（Linux）/ Microsoft x64（Windows） |
| 栈帧分析 | 注意 push ebp; mov ebp, esp（帧指针建立）                          |
| SEH  | Windows 异常处理，可能干扰控制流分析                                    |
| PIE  | 现代编译器默认开启，注意基址重定位                                         |

## 5.4 性能优化

**分析优先级（最快获得结果的路径）：**

| 优先级 | 操作                        | 原因             |
| --- | ------------------------- | -------------- |
| 1st | `r2_get_info`             | 零分析成本，揭示文件基本信息 |
| 2nd | `r2_list_strings`         | 快速获取关键信息线索     |
| 3rd | `r2_list_functions`       | 了解程序结构和规模      |
| 4th | `r2_get_xrefs`            | 追踪特定目标的引用关系    |
| 5th | `r2_decompile_function`   | 仅在确定目标后反编译     |
| 6th | `r2_analyze_target(full)` | 最耗时 — 仅在必要时使用  |

**性能规则：**

| 规则    | 慢方式                | 快方式                        |
| ----- | ------------------ | -------------------------- |
| 大文件处理 | auto\_analyze=true | auto\_analyze=false → 按需分析 |
| 函数过滤  | 列出全部 → 本地过滤        | 使用 filter 参数               |
| 字符串搜索 | min\_length=1      | min\_length=5-8（按需降低）      |
| 分析策略  | 直接 full(aaa)       | basic(aa) → 按需 calls/refs  |
| 会话管理  | 打开多个不关闭            | 用完即关，避免资源占用                |
| 并行分析  | 串行分析多个函数           | 同一消息中对不同函数发起反编译            |

## 5.5 与其他工具配合

**R2-MCP + MT-MCP 联合分析（Android SO 库）：**

```
场景: 分析 Android 应用中的 native 库 (.so 文件)

1. 先用 MT-MCP (mt-mcp-apk-analyzer) 分析 APK:
   - 搜索 System.loadLibrary 找到加载了哪些 SO 库
   - 提取 SO 文件路径

2. 再用 R2-MCP 分析 SO 文件:
   - r2_open_file 打开 SO 文件
   - r2_get_info 确认架构（arm/arm64）
   - r2_list_functions(filter="Java_") 找 JNI 函数
   - r2_decompile_function 分析 JNI 函数逻辑
```

**R2-MCP + Ghidra/IDA 对比验证：**

```
1. R2-MCP 快速分析 → 获取初步结果
2. Ghidra/IDA 深度分析 → 验证和补充
3. 对比两者反编译结果 → 确保分析准确性
```

***

# 第七部分：eDBG 动态调试

## 7.1 概述

[eDBG](https://github.com/ShinoLeah/eDBG) 是基于 eBPF 的 Android 动态调试器，与传统 ptrace 调试器不同，eDBG 不直接附加进程，具有**抗干扰和反检测特性**，几乎无法被目标程序感知。

**特点：**

- 基于 eBPF 实现，占用极小
- 用户态硬件断点，无法被检测
- 支持 uprobes 断点
- MCP 协议接口，便于 AI 集成

**连接地址：** `http://127.0.0.1:19810/mcp`

## 7.2 核心流程

> **必须先调用** **`attach`** 或 **`run`** → 获取目标进程 → 设置断点 → 执行调试

| 工具 | 用途 | 关键参数 |
| --- | --- | --- |
| `attach` | 附加到运行中的进程 | pid 或进程名 |
| `run` | 以调试模式启动程序 | program path |
| `break` | 设置普通断点（uprobes） | 地址或函数名 |
| `hbreak` | 设置硬件断点 | 地址 |
| `watch` | 设置内存观察点 | 地址 |
| `continue` | 继续执行 | - |
| `step` | 单步执行 | - |
| `next` | 执行到下一个分支/调用 | - |
| `finish` | 执行到当前函数返回 | - |
| `examine` | 查看内存内容 | 地址、长度 |
| `write_memory` | 写入内存 | 地址、数据 |
| `registers` | 查看寄存器 | - |
| `backtrace` | 栈回溯 | - |
| `list` | 反汇编查看 | 地址、行数 |
| `detach` | 脱离目标进程 | - |

## 7.3 分析决策框架

```
用户意图
├─ "程序跑起来了，想下断点"      → attach/run → break
├─ "想看某地址的内存数据"         → examine
├─ "想修改某个变量的值"           → watch → write_memory
├─ "想追踪函数调用链"             → break → continue → backtrace
├─ "程序crash了，想看堆栈"       → attach → backtrace
├─ "想看寄存器状态"              → registers
└─ "这个函数内部怎么执行的"       → break → step/next
```

## 7.4 与 R2 配合使用

静态分析和动态调试可以形成互补的工作流：

```
静态分析 (R2 MCP:5050)           动态调试 (eDBG MCP:19810)
         │                                    │
         ▼                                    ▼
   r2_open_file                            attach/run
   r2_list_functions                         │
   r2_decompile_function                     ▼
         │                              break/continue
         │                                    │
         ▼                                    ▼
   定位关键函数地址 ──────────────────→ 在目标地址下断点
                                         │
                                         ▼
                                   step/next/examine
                                         │
                                         ▼
                                    运行时验证理解
```

**典型工作流：**

```
1. R2 静态分析 → 找到可疑函数地址 0x401000
2. eDBG 附加进程 → 在 0x401000 下断点
3. 触发断点 → 单步执行观察程序行为
4. examine 查看内存数据
5. registers 查看寄存器状态
6. backtrace 查看调用链
```

## 7.5 断点类型选择

| 断点类型 | 命令 | 适用场景 | 特点 |
| --- | --- | --- | --- |
| 普通断点 | `break` | 函数入口、常用位置 | uprobes，用户态可检测 |
| 硬件断点 | `hbreak` | 精确单步 | 硬件实现，完全不可检测 |
| 写入观察点 | `watch` | 监控变量修改 | 写入时中断 |
| 读取观察点 | `rwatch` | 监控变量读取 | 读取时中断 |
| 访问观察点 | `awatch` | 监控变量访问 | 读写时中断 |

## 7.6 工具详解

### attach

附加到运行中的进程。

**参数：**

| 参数 | 必填 | 说明 |
| --- | --- | --- |
| target | 是 | 进程 PID 或进程名 |

**返回：** 目标信息，包含 pid、name 等

### run

以调试模式启动程序。

**参数：**

| 参数 | 必填 | 说明 |
| --- | --- | --- |
| program | 是 | 程序路径 |
| args | 否 | 命令行参数 |

### break / hbreak / watch

设置断点。

**参数：**

| 参数 | 必填 | 说明 |
| --- | --- | --- |
| target | 是 | 地址（0x开头）或函数名 |
| condition | 否 | 触发条件 |

### examine

查看内存内容。

**参数：**

| 参数 | 必填 | 默认值 | 说明 |
| --- | --- | --- | --- |
| address | 是 | - | 起始地址 |
| length | 否 | 64 | 查看长度（字节） |

### registers

查看所有寄存器状态。

### backtrace

查看栈回溯信息（调用链）。

### list

反汇编查看代码。

**参数：**

| 参数 | 必填 | 默认值 | 说明 |
| --- | --- | --- | --- |
| address | 是 | - | 起始地址 |
| lines | 否 | 10 | 反汇编行数 |

### continue / step / next / finish

执行控制。

| 命令 | 说明 |
| --- | --- |
| `continue` | 继续执行直到下一个断点 |
| `step` | 单步执行（进入函数） |
| `next` | 单步执行（跳过函数调用） |
| `finish` | 执行到当前函数返回 |

## 7.7 注意事项

**eDBG 要求：**

- ARM64 Android 设备
- Root 权限（推荐 KernelSU）
- 内核版本 5.10+（eBPF 支持）

**断点地址格式：**

```
OK:   target="0x401000"    (十六进制地址)
OK:   target="main"        (函数名)
OK:   target="0x401000+10" (偏移量)
BAD:  target="401000"       (缺少 0x 前缀)
```

**硬件断点限制：**

- 通常最多 4-8 个硬件断点
- 超出限制会报错
- 敏感调试用 `hbreak`

**uplate 模式：**

attach 时如果目标进程使用了 anti-debug 技术，可以尝试 `--uprobe` 模式，它使用 uprobes 替代 ptrace。

## 7.8 常见问题

**Q: attach 失败，显示 "No such process"**
```
可能是进程名拼写错误，或进程已退出
解决：确认进程存在，使用正确的大小写
```

**Q: break 设置成功但未触发**
```
可能是地址错误或内存权限问题
解决：先用 examine 确认地址可访问
```

**Q: step 卡住不动**
```
可能是进入了内核态或等待 I/O
解决：尝试 next 跳过，或用 continue
```

**Q: 设备不支持 eDBG**
```
eDBG 需要 eBPF 支持
检查：内核版本 >= 5.10，KernelSU 已安装
```

***

# 第八部分：输出规范

## 6.1 报告模板

报告文件命名：`{fileName}_{分析类型}报告.md`

```markdown
# {文件名} - {分析类型}分析报告

## 基本信息

| 项目 | 值 |
|------|------|
| 文件名 | {fileName} |
| 文件大小 | {文件大小} |
| 架构 | {arch} ({bits}位) |
| 平台 | {os} |
| 文件类型 | {type} |
| 端序 | {endian} |
| 入口点 | {entrypoint} |

## 分析配置

| 配置项 | 值 |
|--------|-----|
| 分析类型 | {分析类型} |
| 分析策略 | {策略列表} |
| 分析时间 | {时间戳} |

## 分析结果

### 1. {结果分类1}

{详细内容，包含函数地址、伪代码、交叉引用等}

### 2. {结果分类2}

{详细内容}

...

## 关键代码

{可选：反编译伪代码或关键汇编片段}

## 总结

{分析总结和建议}

---

*报告生成时间: {时间}*
*分析工具: R2-MCP Binary Analyzer*
```

## 6.2 报告撰写心法

一份好的逆向分析报告不只是罗列函数和字符串，而是让读者看完就知道"程序做了什么、有没有风险、关键逻辑在哪"。

**报告质量分级：**

| 等级 | 特征                  | 读者体验           |
| -- | ------------------- | -------------- |
| 初级 | 粘贴工具输出原文            | "看到了，但不知道什么意思" |
| 中级 | 按功能模块分类整理，标注关键函数/地址 | "知道结构，但不理解逻辑"  |
| 高级 | 每个发现都附带伪代码、调用链、风险评估 | "完全理解，可以直接行动"  |

**每个分析发现的必备要素：**

1. **定位信息** — 函数地址、函数名、关键字符串地址
2. **代码上下文** — 反编译伪代码或关键汇编片段
3. **调用关系** — 谁调用了这个函数、这个函数调用了谁
4. **影响分析** — 这个发现意味着什么，有什么安全影响
5. **建议** — 后续分析方向或修复建议

**代码片段呈现规范：** 用注释标注关键行：

```c
// 伪代码示例
void check_password(char *input) {
    char buf[64];
    strcpy(buf, input);              // ← [危险] 无边界检查的 strcpy
    if (strcmp(buf, "admin123") == 0) {  // ← [硬编码] 密码硬编码
        grant_access();
    }
}
```

## 6.3 解决方案建议

**重要原则：分析报告必须包含解决方案建议部分，指导用户如何处理分析结果。**

**工具选择原则：**

| 场景         | 推荐工具          | 说明            |
| ---------- | ------------- | ------------- |
| 快速分析       | R2-MCP        | 首选，直接在对话中分析   |
| 深度分析       | Ghidra        | 免费开源，功能强大     |
| 专业逆向       | IDA Pro       | 业界标准，插件丰富     |
| 动态调试       | GDB / LLDB    | 运行时调试         |
| 动态 Hook    | Frida         | 运行时修改和监控      |
| Android SO | R2-MCP + Jadx | 静态 + Java 层分析 |

**R2-MCP 操作建议：**

| 操作     | 建议方法                                               |
| ------ | -------------------------------------------------- |
| 快速了解文件 | open → get\_info → list\_functions                 |
| 查找功能代码 | list\_strings → xrefs → decompile                  |
| 理解算法   | decompile\_function + xrefs(direction="from")      |
| 安全审计   | list\_functions(imp) + list\_strings + xrefs       |
| 加壳检测   | get\_info + list\_functions(看数量) + disassemble(入口) |

**常见分析模式：**

| 需求     | 分析方法                                           |
| ------ | ---------------------------------------------- |
| 找到网络通信 | strings → URL/域名 → xrefs → decompile           |
| 找到加密算法 | strings → AES/RSA/DES → xrefs → decompile      |
| 找到认证逻辑 | strings → login/auth/token → xrefs → decompile |
| 找到漏洞   | functions(imp) → 危险函数 → xrefs → disassemble    |
| 理解协议   | decompile(网络处理函数) → 分析数据结构                     |

**解决方案模板：**

```markdown
## 解决方案建议

### 推荐工具

本分析结果推荐使用 **R2-MCP** 进行进一步分析，配合 **Ghidra** 验证。

### 后续分析步骤

1. **深入分析目标函数**
   - 函数地址: 0x{address}
   - 函数名: {function_name}

2. **R2-MCP 操作**
   - r2_decompile_function(address="0x{address}")
   - r2_get_xrefs(address="0x{address}", direction="to")
   - r2_get_xrefs(address="0x{address}", direction="from")

3. **验证分析**
   - 使用 Ghidra 打开文件对比反编译结果
   - 使用 GDB 动态调试验证执行流

### 注意事项

- 大文件分析时注意内存使用
- 分析完成后及时关闭会话
- 反编译结果可能与源代码有差异（编译器优化）

### 备选方案

如果 R2-MCP 无法满足需求，推荐使用:
- Ghidra（免费，支持反编译和脚本）
- IDA Pro（专业级，插件生态丰富）
- Binary Ninja（现代化 UI，API 友好）
```

***

# 附录

## A. Radare2 常用命令速查

**信息类：**

| 命令    | 用途     |
| ----- | ------ |
| `iI`  | 文件基本信息 |
| `ii`  | 导入函数   |
| `iE`  | 导出函数   |
| `is`  | 符号表    |
| `iz`  | 数据段字符串 |
| `izz` | 所有段字符串 |
| `iS`  | 段信息    |
| `iSS` | 节区信息   |

**分析类：**

| 命令          | 用途       |
| ----------- | -------- |
| `aa`        | 基础分析     |
| `aaa`       | 全量分析     |
| `aab`       | 基本块分析    |
| `aac`       | 调用分析     |
| `aar`       | 引用分析     |
| `aad`       | 指针分析     |
| `afl`       | 列出函数     |
| `af @ addr` | 在地址处定义函数 |

**反汇编/反编译类：**

| 命令     | 用途         |
| ------ | ---------- |
| `pd N` | 反汇编 N 行    |
| `pdf`  | 打印函数反汇编    |
| `pdc`  | 反编译为 C 伪代码 |
| `pdr`  | 基于寄存器的反编译  |

**交叉引用类：**

| 命令            | 用途          |
| ------------- | ----------- |
| `axt addr`    | 查找引用目标地址的代码 |
| `axf addr`    | 查找目标地址引用的代码 |
| `axC src tgt` | 添加调用引用      |

**搜索类：**

| 命令        | 用途       |
| --------- | -------- |
| `/x FF`   | 搜索十六进制字节 |
| `/z text` | 搜索字符串    |
| `/a jmp`  | 搜索汇编指令   |

## B. 常见文件类型特征

**ELF 文件：**

| 特征                 | 说明           |
| ------------------ | ------------ |
| Magic: 7f 45 4c 46 | ELF 文件头      |
| .text 段            | 代码段          |
| .data 段            | 已初始化数据段      |
| .bss 段             | 未初始化数据段      |
| .rodata 段          | 只读数据段（字符串常量） |
| .got/.plt 段        | 全局偏移表/过程链接表  |
| .dynsym/.dynstr    | 动态符号/字符串表    |

**PE 文件：**

| 特征                | 说明     |
| ----------------- | ------ |
| Magic: 4d 5a (MZ) | PE 文件头 |
| .text 节           | 代码节    |
| .data 节           | 数据节    |
| .rdata 节          | 只读数据节  |
| .rsrc 节           | 资源节    |
| IAT               | 导入地址表  |

**DEX 文件：**

| 特征                         | 说明       |
| -------------------------- | -------- |
| Magic: 64 65 78 0a (dex\n) | DEX 文件头  |
| string\_ids                | 字符串 ID 表 |
| type\_ids                  | 类型 ID 表  |
| method\_ids                | 方法 ID 表  |
| class\_defs                | 类定义      |

## C. 注意事项

1. **文件路径**: 使用完整的绝对路径
2. **大文件处理**: >10MB 的文件建议 auto\_analyze=false
3. **会话管理**: 分析完成后及时关闭会话释放资源
4. **分析策略**: 优先使用轻量级策略，避免不必要的 full 分析
5. **结果验证**: 重要发现建议用多种方式交叉验证
6. **敏感信息**: 在报告中适当脱敏
7. **MCP 服务器地址**: 以实际连接成功的 MCP 配置为准
8. **架构识别**: 分析前先确认文件架构，避免错误分析

