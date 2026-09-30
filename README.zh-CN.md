# XSec 工作区

XSec 是一个跨平台数据加密工作区，包含：

- `crates/xsec`：核心加密和密钥保护库；
- `crates/xsec-cli`：基于 `xsec` 的命令行工具。

## 构建和测试

```text
cargo check --workspace
cargo test --workspace
```

工作区目前包含两个 crate：`xsec` 是可复用的加密库，`xsec-cli` 是面向
dotenv 文件的命令行前端。库的 system protector 已提供 Windows、macOS 和
Linux backend；Windows 使用 TPM 2.0，macOS 使用 Secure Enclave，Linux 默认使用系统
密钥环，也可启用 TPM 后端。密钥环不提供硬件隔离或用户在场验证。平台提示框和安全
硬件行为必须在对应的真实平台上验证。详见 [`crates/xsec/README.zh-CN.md`](crates/xsec/README.zh-CN.md)。

## CLI 快速开始

Cargo 包名是 `xsec-cli`，安装后的可执行文件名是 `xsec`。

```text
cargo run -p xsec-cli --bin xsec -- init
cargo run -p xsec-cli --bin xsec -- encrypt -i .env -o .xsec
cargo run -p xsec-cli --bin xsec -- run -f .xsec -- your-command
```

读取、设置或删除单个变量：

```text
cargo run -p xsec-cli --bin xsec -- get API_TOKEN -f .xsec
cargo run -p xsec-cli --bin xsec -- set API_TOKEN -f .xsec
cargo run -p xsec-cli --bin xsec -- del API_TOKEN -f .xsec
```

加密环境文件会保留 dotenv 结构。受保护的值使用保留格式
`xsec:<base64url-no-padding>`。

```text
.env                明文输入，不应提交
.xsec               加密后的 dotenv 环境文件
.xsec.production    加密后的生产环境文件
.xsec.keys          受保护的 DEK metadata，不应提交
```

初始化后，支持的平台可以添加 system protector：

```text
cargo run -p xsec-cli --bin xsec -- protector add system --identity your-project-id
```

包级说明见 [`crates/xsec/README.md`](crates/xsec/README.md) 和
[`crates/xsec-cli/README.md`](crates/xsec-cli/README.md)。默认入口为英文版
[`README.md`](README.md)。

## 安全范围

XSec 的安全性依赖应用程序和操作系统安全边界可信。它不提供防回滚、多设备
同步，或自动 DEK 轮换与密文迁移。不要提交 `.env`、`.xsec.keys` 或其他明文
和密钥存储文件。
