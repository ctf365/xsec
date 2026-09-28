# XSec

XSec 是一个跨平台数据加密库。它生成并管理数据加密密钥（DEK），使用密码或调用方提供的系统/KMS 保护器包装 DEK，并提供稳定的 AES-256-GCM 加解密接口。

业务密文由调用方保存；`XSecStorage` 只保存 XSec 自身的 metadata。

## 特性

- 随机 DEK 与随机 nonce 的 AES-256-GCM 数据加密
- 与密文头一起认证的用户 AAD
- Argon2id 密码保护器（固定安全参数，阻塞计算由 Tokio 调度）
- canonical binary metadata 与 HKDF/HMAC-SHA256 整体认证
- Metadata 使用 `XSecMD` 标识，业务密文使用 `XSecCT` 标识
- 可扩展的异步 `XSecStorage` 和 `XSecProtector`
- 敏感密钥与解密结果使用 `SecretBox` / `Zeroizing`
- `file-storage` 默认 feature 提供单 blob 原子文件存储，并在 Storage 生命周期内持有独占文件锁
- Storage 后端错误统一归一化为 `XSecStorageError`，不向核心层暴露具体 I/O 错误
- Protector 后端错误统一归一化为 `XSecProtectorError`，不向核心层暴露平台 SDK 错误
- `password-protector` 默认 feature 提供 Argon2id 密码保护器

## Feature 和平台说明

默认启用 `file-storage` 和 `password-protector`。`system-protector` 默认关闭，
启用后只控制是否编译并导出 `XSecSystemProtector`，不会给 `XSec` 增加专属方法。
启用时，system protector 根据目标平台选择 backend：

| 平台 | 系统保护方式 |
| --- | --- |
| Windows | Windows Hello credential 签名 |
| macOS | Secure Enclave 和 Keychain 访问控制 |
| Linux | 仅当前进程会话内的受保护内存；不保证用户在场验证或持久化 |
| 其他目标 | 返回 `Unavailable` |

真实提示框、credential、entitlement、桌面 agent 和安全硬件必须在目标设备上
测试；交叉编译成功不等于运行时验证通过。

`XSecStorage` 和 `XSecProtector` 只定义抽象接口。具体实现位于对应子模块，并通过 feature 按需编译：`storage/file.rs`、`protector/password.rs`。

## 快速开始

```rust
use secrecy::SecretBox;
use xsec::{XSec, XSecFileStorage, XSecPasswordProtector, XSecResult};

#[tokio::main]
async fn main() -> XSecResult<()> {
    let storage = XSecFileStorage::new("data/account.xsec.keys");
    let password = SecretBox::new(Box::new(b"correct horse battery staple".to_vec()));
    let protector = XSecPasswordProtector::new(password);
    let mut xsec = XSec::create(storage).await?;
    xsec.add_key_protector(&protector).await?;
    xsec.unlock(&protector).await?;
    let ciphertext = xsec.encrypt_with_aad(b"alice@example.com", b"user:123/profile/email")?;
    xsec.lock()?;
    xsec.unlock(&protector).await?;
    let plaintext = xsec.decrypt_with_aad(&ciphertext, b"user:123/profile/email")?;
    assert_eq!(plaintext.as_slice(), b"alice@example.com");
    Ok(())
}
```

完整格式、安全边界和 API 契约以当前源码和测试为准；工作区入口见
[`../../README.md`](../../README.md)。

## 生命周期

一个 `XSec` 实例拥有一个 storage，并经过以下状态：

```text
new → load → uninitialized → create → unlocked ↔ locked
                                  └──────────────→ destroyed
```

新 storage 使用 `create`，已有 metadata 使用 `unlock`。只有 unlocked 状态可以
加解密。`lock` 会清理内存中的 DEK；`destroy` 删除当前 metadata，但不能清理
备份或快照。

`XSecStorage` 只保存 XSec metadata，业务密文由调用方负责保存。`XSecProtector`
负责包装和解包 DEK；自定义 protector 属于受信任代码，不得记录或长期保存明文密钥。

`encrypt_with_aad` 会认证调用方提供的上下文，但不会加密它。应使用记录 ID、字段名
等稳定且非秘密的标识。每次加密都会生成新的 nonce。

## 安全边界

- 密码强度决定 metadata 被窃取后的离线猜测难度。
- `create` 返回锁定状态且尚未持久化的实例，不生成或暂存 DEK；首次添加密钥保护器时才生成 DEK 并保存 metadata。之后必须使用已添加的保护器解锁。
- `destroy` 删除当前 Storage 中的 metadata，但不保证磁盘、备份或快照已物理擦除。
- v1 不提供完整存储快照的防回滚、数据密钥轮换或多端同步。为避免制造虚假的
  撤销语义，普通 protector 的替换和移除会返回
  `ProtectorChangeRequiresKeyRotation`；Windows 和 macOS 的 system protector 可通过销毁
  持久平台密钥安全移除。Linux 的 session-only protector 不支持这种跨快照撤销。
- 第三方 `XSecProtector` 能接触明文 DEK，必须视为受信任代码。
- 丢失 storage metadata 会导致受保护数据无法恢复，除非存在有效备份。

## License

Apache-2.0
