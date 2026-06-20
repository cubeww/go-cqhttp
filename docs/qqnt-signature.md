# QQNT 签名机制与偏移适配

本文记录本项目内置 QQNT 签名的工作方式，以及更新 QQ 版本后如何重新寻找 `wrapper.node` 里的签名函数偏移。

## 当前状态

当前内置签名只支持 Linux/WSL + cgo。默认配置：

```yaml
sign-servers:
  - url: 'builtin'
    offset: '0x5BD3EA1'
    token: ''
```

`builtin` 表示从当前工作目录加载 `wrapper.node`。也可以显式指定目录：

```yaml
sign-servers:
  - url: 'builtin:/path/to/qqnt-runtime'
    offset: '0x5BD3EA1'
    token: ''
```

当前本地测试版本：

- QQ Linux 包版本：`3.2.29-49738`
- `wrapper.node` SHA256：`6bbf46e77eb284932404a79452e3861c3e9d134aef5022a6393b63605001bdf5`
- 签名函数偏移：`0x5BD3EA1`

目录名不一定等于 QQ 包版本，后续适配时以 `QQ/resources/app/package.json` 里的 `version`、`buildVersion` 和 `wrapper.node` 哈希为准。

## 签名调用链

LagrangeGo 在发送部分敏感包时会调用 `sign.Provider`。本项目的实现路径是：

```text
LagrangeGo -> cmd/gocq/sign.go -> internal/sign/native -> dlopen(wrapper.node) -> module_base + offset
```

内置 signer 的核心工作：

1. 读取 `sign-servers`。
2. 如果 `url` 是 `builtin`，初始化 native signer。
3. `dlopen` 加载当前目录或指定目录下的 `wrapper.node`。
4. 用 `dl_iterate_phdr` 找到 `wrapper.node` 的运行时基址。
5. 用 `module_base + offset` 得到签名函数地址。
6. 调用签名函数并把结果转换成 LagrangeGo 需要的 `sec_sign/sec_token/sec_extra`。

签名函数原型按当前版本观察为：

```c
long long sign_func(
    const char* cmd,
    const unsigned char* src,
    int src_len,
    int seq,
    unsigned char* out
);
```

输出缓冲区大小为 `0x300`，布局是：

```text
out + 0x000: token 数据
out + 0x0ff: token 长度
out + 0x100: extra 数据
out + 0x1ff: extra 长度
out + 0x200: sign 数据
out + 0x2ff: sign 长度
```

简单 smoke test 里 `wtlogin.login` 的测试包通常能得到 `sign=32`，`token/extra` 可能为 0，这是正常的。

## 运行依赖

`wrapper.node` 是 QQ/Electron 的 Linux ELF native addon，不能由 Windows 进程直接加载，所以内置签名必须运行 Linux/WSL 版 go-cqhttp。

运行目录至少需要：

```text
go-cqhttp
config.yml
wrapper.node
libbugly.so
libcrbase.so
libssh2.so.1
libunwind.so.8
libunwind-x86_64.so.8
```

检查缺库：

```bash
ldd ./wrapper.node | grep 'not found'
```

本项目的内置 signer 已经在主程序里导出 `qq_magic_napi_register`，所以运行目录不需要额外放置 `libsymbols.so`。

## 协议版本与签名偏移

协议版本和签名偏移是两件事：

- 协议版本在 `cmd/gocq/main.go` 的 `defaultLinuxAppInfo()`。
- 签名偏移在配置文件 `sign-servers[].offset`，默认值在 `internal/sign/native`。

更新 QQ 版本时通常两者都要检查：

1. 从 `QQ/resources/app/package.json` 读取：
   - `version`
   - `buildVersion`
   - `appid.linux`
2. 更新 `defaultLinuxAppInfo()`：
   - `CurrentVersion`
   - `BuildVersion`
   - `SubAppID`
   - `AppClientVersion`
   - `PackageSign`
3. 用 IDA 重新确认 `wrapper.node` 签名函数偏移。
4. 更新 `config.yml` 里的 `offset`。

## 如何寻找新版偏移

### 1. 准备文件

从新版 QQ Linux 包或安装目录取出：

```text
resources/app/wrapper.node
resources/app/package.json
resources/app/libbugly.so
resources/app/libcrbase.so
resources/app/libssh2.so.1
resources/app/libunwind.so.8
resources/app/libunwind-x86_64.so.8
```

先记录版本和哈希：

```bash
sha256sum wrapper.node
cat package.json | grep -E '"version"|"buildVersion"|"linux"'
```

### 2. 用 IDA 打开 wrapper.node

用 IDA 打开 Linux x64 ELF `wrapper.node`，等待自动分析完成，启用 Hex-Rays 反编译。

先从字符串入手，搜索这些特征：

```text
trpc.o3.ecdh_access.EcdhAccess.SsoEstablishShareKey
trpc.o3.ecdh_access.EcdhAccess.SsoSecureAccess
LLL
```

其中两个 `EcdhAccess` 字符串通常能定位 `sec_extra` 构造逻辑；`LLL` 相关逻辑通常在真正生成 `sec_sign` 的路径附近。

### 3. 找到内部签名计算函数

从上述字符串的 xref 往上追调用链，重点找这些特征：

- 输入里有 `cmd` 字符串。
- 输入里有包体指针和长度。
- 输入里有 `seq`。
- 会调用内部 VM/模板逻辑生成签名。
- 会返回或写出 token、extra、sign 三段数据。

当前版本里曾观察到的关键路径：

```text
签名入口 wrapper
  -> sec_sign 计算函数
  -> sec_extra 构造函数
  -> token 获取函数
  -> LLL 签名 VM
```

这些函数名不是二进制原始名字，是分析时重命名出来的。新版里地址会变，但结构一般相近。

### 4. 找到最终 wrapper 函数

最终要找的不是底层 VM，而是适合直接调用的外层 wrapper。候选函数应满足：

- 参数形态接近：

```c
(const char* cmd, const unsigned char* src, int src_len, int seq, unsigned char* out)
```

- 函数内或其直接调用链会写 `out` 缓冲区。
- 写入布局符合：

```text
out[0x0ff] = token_len
out[0x1ff] = extra_len
out[0x2ff] = sign_len
```

如果反编译里能看到类似 `out + 0x100`、`out + 0x200`、`0xFF`、`0x1FF`、`0x2FF` 的访问，这是很强的候选信号。

### 5. 计算 offset

内置 signer 运行时使用：

```c
sign = module_base + offset;
```

所以 offset 应该是函数地址相对 ELF image base 的偏移。

IDA 里可以用 Python 计算：

```python
import idaapi
ea = here()
print(hex(ea - idaapi.get_imagebase()))
```

如果 IDA 的 image base 是 0，函数地址本身就是 offset。当前版本得到的是：

```text
0x5BD3EA1
```

### 6. 验证 offset

先把新版 `wrapper.node` 和依赖库放到运行目录，然后配置：

```yaml
sign-servers:
  - url: 'builtin'
    offset: '0x新偏移'
    token: ''
```

也可以临时用环境变量覆盖：

```bash
export SIGN_OFFSET=0x新偏移
```

跑 smoke test：

```bash
cd /path/to/go-cqhttp
export SIGN_WRAPPER_DIR=/path/to/runtime-dir
go test -v ./internal/sign/native -run TestSignSmoke -count=1
```

成功时一般能看到：

```text
token=0 extra=0 sign=32
```

## 常见问题

### dlopen wrapper.node failed

通常是缺依赖库。检查：

```bash
ldd ./wrapper.node | grep 'not found'
```

从 QQ 的 `resources/app` 目录复制缺失的 `.so` 到运行目录。

### Missing qq_magic_napi_register

内置 signer 不应出现这个问题。确认当前二进制导出了符号：

```bash
readelf -Ws ./go-cqhttp | grep qq_magic_napi_register
```

如果没有，说明不是用当前 cgo 版本编译出来的二进制。

### 一调用就崩溃

优先怀疑 offset 错误，或者找到的是内部函数而不是外层 wrapper。重新检查函数参数和 `out` 缓冲区写入布局。

### 能签名但登录提示版本低

这通常不是 offset 问题，而是协议 AppInfo 没更新。检查：

- 日志里的 `使用协议`
- `cmd/gocq/main.go` 的 `defaultLinuxAppInfo()`
- `QQ/resources/app/package.json`

### 新版 offset 找不到

按顺序排查：

1. 确认 IDA 自动分析已完成。
2. 从 `EcdhAccess` 字符串 xref 进入。
3. 找生成 `extra/sign/token` 的调用链。
4. 往上追到有 5 参数并写 `out[0x0ff/0x1ff/0x2ff]` 的函数。
5. 用 smoke test 验证，不要只看反编译猜测。

## 适配新版清单

每次更新 QQ 版本时按这个清单走：

1. 复制新版 `wrapper.node` 和依赖 `.so`。
2. 记录 `package.json` 版本和 `wrapper.node` SHA256。
3. 更新 `defaultLinuxAppInfo()`。
4. 用 IDA 找新版签名函数 offset。
5. 更新 `config.yml` 的 `sign-servers[].offset`。
6. 跑 native smoke test。
7. 重新编译 Linux 版 go-cqhttp。
8. 启动后确认日志里的 `使用协议` 和配置中的 offset。
