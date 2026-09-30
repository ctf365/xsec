# xsec-cli

`xsec-cli` 使用 `xsec` 库加密 dotenv 文件中的每个值，并将解密后的值注入子进程，不创建明文临时文件。

Cargo 包名是 `xsec-cli`，安装后的可执行文件名是 `xsec`。

## 文件布局

```text
.env                明文输入，不应提交
.xsec               默认加密环境文件
.xsec.production    加密后的生产环境文件
.xsec.keys          受保护的 DEK 存储，不应提交
.xsec.keys.lock     独占存储锁，不应提交
```

`.xsec` 保留 dotenv 文件的变量名、注释、顺序和空行，受保护的值使用
`xsec:<base64url-no-padding>` 格式。`.xsec.keys` 包含被包装的 DEK 和
protector metadata；丢失它将无法恢复加密值，应妥善备份并通过合适的密钥管理渠道提供。

## 用法

初始化密码保护的存储：

```text
xsec init
printf '%s' "$XSEC_PASSWORD" | xsec init --password
```

加密并运行：

```text
xsec encrypt -i .env -o .xsec
xsec run -f .xsec -- your-command
```

解密到标准输出或文件：

```text
xsec decrypt -i .xsec --stdout
xsec decrypt -i .xsec -o .env
```

读取、设置或删除变量：

```text
xsec get API_TOKEN -f .xsec
xsec set API_TOKEN -f .xsec
xsec set API_TOKEN "$API_TOKEN" -f .xsec
xsec del API_TOKEN -f .xsec
```

在支持的平台上，可以添加 system protector：

```text
xsec protector add system --identity your-project-id
xsec run --protector system --identity your-project-id -- your-command
```

使用 system protector 解锁时，需要提供添加 protector 时使用的相同 `--identity`。不要使用绝对路径生成 identity，否则移动项目会改变它。

Linux 默认使用系统密钥环。启用 `system-protector-linux-tpm` feature 后，可在 TPM 2.0
可用时使用原生 TPM。Linux 的 D-Bus/TPM 开发库要求及密钥环较低的硬件保护等级见
XSec crate 文档。

## 运行时行为

- 默认情况下，已有进程环境变量优先；`--override` 可覆盖它们。
- 缺失存储、认证失败和不支持的 system protection 都会直接失败，不会回退到明文 `.env`。
- 输出文件原子写入；Unix 新文件使用仅所有者可访问的权限。
- 密码、明文和密文不会写入诊断信息。
- 每个加密值使用新 nonce，并绑定变量名进行认证。
- `set` 和 `del` 保留无关注释、顺序、多行值以及 LF/CRLF 换行格式。
- 修改命令会重新读取文件并拒绝检测到的并发变更。

## Protector 管理

查看当前配置的 protector（不会解锁 storage）：

```text
xsec protector list
```

使用另一个 protector 授权后删除 protector：

```text
xsec protector remove system
```

需要时可使用 `--unlock-with <password|system>` 选择解锁方式，并使用
`--password` 从标准输入读取密码。选择 `system` 时还需提供添加时使用的 identity。
最后一个 protector 不能删除；密码 protector
的替换或删除在实现 DEK 轮换和密文迁移前会被拒绝。

## 存储和恢复注意事项

`.xsec.keys` 是加密值的密钥管理状态，不是可以随意删除的缓存。应通过受保护的
密钥管理渠道备份，并与 `.env`、`.xsec` 分开保存。能够读取 metadata 的攻击者可以
离线猜测密码，因此应使用强密码，不要把密码放进命令行参数或 shell 历史。

英文默认版本见 [`README.md`](README.md)。
