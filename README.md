# pe_resource_injector

PE 资源 / 元数据 / 签名 克隆与注入器。纯 C + 原生 Win32 API，不链接任何 C 运行时（`-nostdlib`）。

> 本仓库只放源码；编译好的 `peres.exe` / `peview.exe` 见 [Releases](https://github.com/yanghaoi/pe_resource_injector/releases)。
> 原理与踩坑记录见文章：[PE文件版本资源注入问题排查与工具实现](https://yanghaoi.github.io/2026/10/01/pe-wen-jian-ban-ben-zi-yuan-zhu-ru-wen-ti-pai-cha-yu-gong-ju-shi-xian/)。

## 功能

- **PE → PE 资源克隆**：指定源 PE 模板，把资源整批复制到目标 PE，按 7 个类别分别勾选
- **PE 元数据克隆**：复制 `TimeDateStamp` / `CheckSum` / 链接器版本号
- **数字签名查看与复制**：`CryptQueryObject` + `WinVerifyTrust`，证书链解析；签名数据迁移（注意：迁移后摘要不匹配，需 `signtool` 重新签署）
- **RT_VERSION 版本信息**：8 个标准字段，可手填或一键随机生成
- **随机资源注入**：RT_RCDATA 随机数据块、RT_BITMAP 随机位图、自定义类型资源
- **自建资源目录**：目标无 `.rsrc` 节时自动补一个空目录头 + 新 `.rsrc` 节
- **幂等清理**：按 `PRND_` 前缀 / 60000–60999 位图 ID 精确删除上次注入的资源
- **写回校验**：写完用 `FindResource` 逐个复查，识别不全则换顺序重试

## 项目结构

```
pe_resource_injector/
├── common/              共享基建
│   ├── peres.h          公共头文件：类型、宏、extern 声明
│   ├── util.c           无 CRT 基建：内存/字符串/对齐/随机数
│   └── buffer.c         动态字节缓冲区 BUF
├── peres/               PE 资源注入器源码
│   ├── version.c        VS_VERSIONINFO 构建 + 随机版本信息
│   ├── pe.c             PE 头解析/修补/追加节/证书表
│   ├── log.c            日志输出
│   ├── rescol.c         从源 PE 枚举收集资源
│   ├── sign.c           数字签名验证与显示
│   ├── updater.c        UpdateResource 写入/校验/清理
│   ├── inject.c         do_inject 主注入流程
│   ├── ui.c             GUI 窗口/布局/控件
│   ├── cli.c            命令行解析
│   └── main.c           peres 入口 + ___chkstk_ms
├── peview/              PE 查看器源码
│   ├── peview.h         peview 公共头文件
│   ├── peview_pe.c      PE 头/资源列表/目录树解析
│   ├── peview_enum.c    Windows API 资源枚举
│   ├── peview_sigscan.c 签名扫描
│   ├── peview_ui.c      peview GUI
│   └── peview_main.c    peview 入口
├── release/             构建输出目录（不入库，exe 见 Releases）
├── build.bat            构建脚本（编译两个目标到 release/）
├── .gitattributes       行尾约定（.bat 强制 CRLF）
├── .gitignore
├── LICENSE
└── README.md
```

## 编译

需要 MinGW-W64（winlibs 或等效发行版），GCC 14+，且 `gcc` 在 PATH 上。

```bat
build.bat
```

一次编译两个目标到 `release/`：`peres.exe`（资源注入器）+ `peview.exe`（PE 查看器）。

关键编译开关：

| 开关 | 作用 |
|---|---|
| `-nostdlib` | 不链接任何 CRT |
| `-Wl,--entry=WinMainCRTStartup` | 自定义入口 |
| `-fno-builtin` | 禁止 GCC 合成 memcpy/memset 库调用 |
| `-fno-stack-protector` | 去掉需要 CRT 支持的栈保护 |
| `-fno-asynchronous-unwind-tables` | 去掉异常处理表 |

## 使用

```bat
release\peres.exe                              :: 启动 GUI
release\peres.exe app.exe                      :: 命令行，另存为 app.patched.exe
release\peres.exe app.exe --inplace            :: 就地修改，自动备份 app.exe.bak
release\peres.exe app.exe --on=3,4             :: 额外开启自定义类型资源 + 随机语言
release\peres.exe app.exe --src=tpl.exe        :: 从 tpl.exe 克隆资源与元数据
release\peres.exe app.exe --src=tpl.exe --nocopy=5 --copy=6   :: 只克隆元数据
release\peres.exe app.exe --src=tpl.exe --copysig             :: 连同数字签名一起复制
release\peres.exe app.exe --showsig            :: 只看签名信息
release\peres.exe --help                       :: 查看全部选项
```

复制类别：`0` 版本信息 · `1` 图标 · `2` 清单 · `3` 界面资源 · `4` 位图/光标/字体/RCDATA · `5` 自定义类型 · `6` PE 元数据

## 技术要点

本项目在实践中遇到并解决了四个 `UpdateResource` API 行为问题：

1. **无资源目录的 PE**：`UpdateResource` 报 `ERROR_INTERNAL_ERROR (1359)`，需自行补一个 16 字节空目录头 + 新 `.rsrc` 节
2. **自建资源目录不可靠**：字节布局完全合规，Windows 也可能只识别部分条目；改为只补空目录头，让 `UpdateResource` 自行构建
3. **写入顺序约束**：同一会话内先写字符串类型名再写字符串名会失败（`ERROR_NOT_SUPPORTED`）；两种顺序各自只对一半样本有效，需写完回读校验 + 换顺序重试
4. **删除可能未提交**：`EndUpdateResource` 在资源较多时可能不提交删除请求；需清理后重新计数

核心原则：**API 返回成功 ≠ 事情真的做成了**。正确性必须以 `FindResource` 回读校验为准。

## 无 CRT 实现

不链接任何 CRT，以下事项自行解决：

| 问题 | 处理 |
|---|---|
| 没有 `main` / 启动代码 | 自行实现 `WinMainCRTStartup`，`--entry` 指向它 |
| 没有 `printf` / `strlen` / `memcpy` | 自写 `mcopy` / `mfill` / `wlen` / `wcopy` 等；格式化用 `wsprintfW` |
| 没有 `malloc` / `free` | 直接用 `HeapAlloc` / `HeapFree` |
| 没有 `rand` / `srand` | 自写 xorshift64 |
| GCC 生成 `memcpy`/`memset` 调用 | 提供同名全局实现 |
| 栈帧 > 4KB 引用 `___chkstk_ms` | 内联汇编自行实现 |

最终导入表 9 个系统 DLL，不含任何 `msvcrt` / `api-ms-win-crt`。

## 合规边界

只对**自己有权修改**的文件操作；修改会使原数字签名失效；生成的文件名/公司名使用中性随机值，不冒充真实厂商。
## peview.exe — PE 查看器

集成原 Python 测试脚本功能的 GUI 查看器，纯 C + Win32 API + 无 CRT。

```bat
release\peview.exe
```

GUI 操作：拖入或浏览选择 PE 文件，点击功能按钮查看结果。

| 按钮 | 对应原脚本 | 功能 |
|---|---|---|
| PE 头信息 | `dump_pe.py` | MZ/PE 签名、machine、节数、16 个数据目录、节表 |
| 资源列表 | `list_res.py` | 自写解析器遍历 `.rsrc` 三级目录，列出 type/name/lang/size |
| API 枚举 | `enum_res.py` | 用 Windows `EnumResourceTypesW` 枚举，结果最权威 |
| 目录树 | `dir_dump.py` | dump `.rsrc` 三级目录树结构，显示偏移/名称/ID/DIR/DATA |
| 签名扫描 | `scan_sig.py` | 扫描系统目录，列出有数字签名的 PE 文件 |

### 「资源列表」与「API 枚举」的区别

这两个按钮是一对**同题异解**的对照，都用来列出 PE 内的资源，但走的是两条完全不同的路径：

| 维度 | 资源列表（`list_res.py`） | API 枚举（`enum_res.py`） |
|---|---|---|
| 解析方式 | **自写解析器**，按 PE 规范直接读 `.rsrc` 节字节，遍历三级目录（type → name → lang） | **Windows 加载器**，`LoadLibraryExW(LOAD_LIBRARY_AS_DATAFILE)` 把 PE 当资源模块加载，再 `EnumResourceTypesW` / `EnumResourceNamesW` / `EnumResourceLanguagesW` 三层回调 |
| 是否加载模块 | 否，纯文件 I/O | 是，需 `LoadLibraryEx` |
| 对损坏/非常规 PE | 只要 `.rsrc` 节在就能解析 | `LoadLibrary` 可能失败 |
| 能看到的资源 | 文件字节里**真实存在**的一切，包括 Windows 不识别的「野」条目 | 只列 **Windows 认识**的条目，系统会过滤/归一化 |
| 结果权威性 | 反映文件**原始字节布局** | 与系统认知**一致**，是权威结果 |
| 能否枚举自身 | 可以解析任意文件，包括正在运行的 exe | 不能加载正在运行的的自己（共享段冲突） |

一句话：**资源列表看的是「文件里写了什么」，API 枚举看的是「Windows 认为它有什么」**。两者并列，正是为了暴露这层差异——当 Windows 对某个资源条目做了归一化、隐藏或拒绝识别时，对比两份输出就能立刻定位。

导入表 5 个系统 DLL（comdlg32/GDI32/KERNEL32/SHELL32/USER32），无任何 CRT。