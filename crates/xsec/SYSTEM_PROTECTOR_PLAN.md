# XSec System Protector 修改方案

本文档用于后续会话实施 XSec system protector 修改。方案只针对
`crates/xsec`，不涉及 `xsec-cli`。

## 1. 范围与约束

不修改以下公共方法的签名：

```rust
XSec::create()
XSec::unlock()
XSec::add_key_protector()
XSec::replace_key_protector()
XSec::remove_key_protector()
XSec::destroy()
```

不改变 XSec 通用状态机。`xsec.rs` 只允许调整删除、替换和销毁 protector
后的资源清理、失败回滚及相关错误处理。

System protector 的平台方案：

| 平台 | 实现 |
| --- | --- |
| Windows | Windows Hello 签名结果与 KEK 密码学绑定 |
| macOS | Secure Enclave 私钥、生物识别访问控制和 ECDH |
| Linux | session-only 进程内安全内存 protector |
| 其他平台 | 返回 `Unsupported` |

不引入 broker、后台服务、daemon、Windows Service 或自定义 IPC。

Cargo feature `system-protector` 默认关闭。启用后仅编译并导出
`XSecSystemProtector` 及其平台后端，不添加仅供该 feature 使用的 `XSec` 公共方法。
未实现平台在 feature 启用时导出不可用的占位 protector，调用返回
`XSecProtectorError::Unavailable`。

## 2. 共同安全模型

业务数据继续使用随机 DEK 加密，system protector 只负责包装和解包 DEK：

```text
业务数据
  ↓
DEK 加密
  ↓
System Protector
  ↓
Wrapped DEK payload
```

System protector 不得：

- 持久化明文 DEK；
- 在日志中输出 DEK、KEK、签名或共享秘密；
- 使用固定 nonce；
- 在认证失败后回退到更弱实现；
- 把普通应用层布尔授权描述成密钥访问控制；
- 把 `identity_hash` 描述成应用签名认证。

## 3. Protector 资源删除接口

给 `XSecProtector` 增加默认 `delete()` 方法：

```rust
pub trait XSecProtector {
    fn kind(&self) -> &'static str;

    async fn wrap_key<'a>(
        &'a self,
        key: &'a SecretBox<[u8; 32]>,
    ) -> XSecProtectorResult<Vec<u8>>;

    async fn unwrap_key<'a>(
        &'a self,
        payload: &'a [u8],
    ) -> XSecProtectorResult<SecretBox<[u8; 32]>>;

    async fn delete(&self) -> XSecProtectorResult<()> {
        Ok(())
    }
}
```

规则：

- 无外部资源的 protector 使用默认空实现；
- system protector 覆盖 `delete()`；
- `delete()` 必须幂等；
- 平台资源已经不存在时视为成功；
- `delete()` 不得删除其他 protector 实例的资源；
- `delete()` 完成后清零当前实例持有的敏感内存。

## 4. 资源生命周期

### 4.1 删除 system protector

删除顺序：

```text
从旧 payload 恢复旧 XSecSystemProtector
→ 生成不含旧 record 的新 metadata
→ 原子保存新 metadata
→ 更新内存 metadata
→ 调用旧 protector.delete()
```

不能先删除平台密钥再保存 metadata，否则保存失败后旧 metadata 会引用已删除的
密钥。

如果 metadata 已经提交，但 `delete()` 失败：

- 不回滚已经提交的新 metadata；
- 不恢复旧 protector record；
- 返回明确的资源清理错误；
- 后续清理必须能够安全重试。

建议增加 `XSecProtectorError::ResourceCleanupFailed`，表示逻辑变更已经提交，但旧
平台资源未完成清理。

### 4.2 替换 system protector

不修改 `replace_key_protector()` 的公共签名。内部支持替换时：

```text
从旧 payload 恢复旧 system protector
→ 新 system protector 创建独立平台资源
→ 新 protector 包装当前 DEK
→ 原子保存新 metadata
→ 更新内存 metadata
→ old_protector.delete()
```

如果新 metadata 保存失败：

- 删除本次创建的新平台资源；
- 保留旧 metadata 和旧平台资源；
- 保持 XSec 当前解锁状态；
- 返回原始保存错误。

如果新 metadata 保存成功但旧资源删除失败：

- 新 protector 已经生效；
- 旧 protector 不再出现在当前 metadata；
- 不回滚 metadata；
- 返回 `ResourceCleanupFailed` 或将清理记录为可重试操作。

普通 password protector 和没有外部资源的 protector 使用默认 `delete()`。

## 5. 独立平台资源 ID

每个 system protector 平台资源使用独立随机 ID：

```text
protector_id = random 128 or 256 bits
```

平台资源名称使用固定 XSec 命名空间、平台标识和 `protector_id`。规则：

- `protector_id` 在首次 `wrap_key()` 时生成；
- `protector_id` 写入 payload；
- `from_payload()` 恢复该 ID；
- `unwrap_key()` 只能使用 payload 指定的资源；
- `delete()` 只能删除该 ID 对应的资源；
- 相同 identity 创建的两个 system protector 不得共享平台密钥；
- `identity_hash` 继续用于命名空间和错配检测，但不能单独作为平台资源 ID；
- `protector_id` 不是秘密，但必须受到 payload 完整性保护。

这可以避免替换时新旧 protector 引用同一个平台资源，导致删除旧资源时误删新资源。

## 6. Payload 格式

各平台可以保留独立格式，但至少包含或认证：

```text
magic
format_version
platform
protector_id
identity_hash
algorithm
authentication_policy
platform_specific_fields
salt
nonce
wrapped_dek
authentication_tag
```

要求：

- 每次包装使用新 nonce；
- HKDF 使用独立随机 salt；
- header 作为 AEAD AAD；
- 修改版本、平台、资源 ID、identity、算法或认证策略后必须无法解包；
- Windows、macOS 和 Linux payload 不能跨平台解析；
- 其他平台 payload 返回 `Incompatible`；
- 不支持版本返回 `Unsupported`；
- 损坏或长度错误返回 `InvalidData`。

## 7. Windows 实现

### 7.1 保留 Windows Hello 签名派生 KEK

保留当前密码学方向：

```text
Windows Hello credential
→ RequestSignAsync(persistent challenge)
→ Windows Hello 用户验证
→ signature
→ SHA-256(signature)
→ HKDF-SHA256
→ KEK
→ AES-256-GCM 解包 DEK
```

它属于生物识别或 Windows Hello 与 KEK 密码学绑定的方案，因为签名结果是得到 KEK
的必要输入，而不是可跳过的布尔授权。

保留该设计的前提：

- Hello 私钥不可直接导出；
- 每次解锁都执行 `RequestSignAsync`；
- 跳过签名操作不能得到 KEK；
- 签名及 KEK 不缓存、不持久化；
- 相同 credential 和 challenge 的签名结果在目标环境中稳定；
- credential 的用户和应用隔离边界经过单独验证。

### 7.2 Windows 资源命名

credential 名称改为基于独立资源 ID：

```text
credential_name = "xsec-system-" + hex(protector_id)
```

identity hash 写入 envelope 并参与 AAD，但不再作为唯一 credential 名称。
`from_payload()` 恢复 identity hash、protector ID、credential 名称、persistent
challenge 及其他 envelope 字段。

### 7.3 Windows 包装

```text
生成 protector ID
→ 创建对应 KeyCredential
→ 生成随机 persistent challenge
→ RequestSignAsync(challenge)
→ SHA-256(signature)
→ HKDF-SHA256(signature_hash, random_salt, context)
→ 得到 KEK
→ 使用随机 nonce 包装 DEK
→ 签名和 KEK 立即清零
→ 返回 payload
```

HKDF context 绑定：

```text
xsec
windows
system-protector
format-version
protector-id
identity-hash
```

如果 metadata 保存失败，上层调用新 protector 的 `delete()` 清理已经创建的
credential。

### 7.4 Windows 解包

```text
解析并验证 payload
→ 使用 protector ID 打开 credential
→ RequestSignAsync(stored challenge)
→ SHA-256 + HKDF 派生 KEK
→ AEAD 解包 DEK
→ 清零签名和 KEK
```

要求：

- 解锁时不得自动创建 credential；
- credential 不存在时返回 `KeyNotFound` 或 `KeyInvalidated`；
- 不得回退到软件密钥；
- 不得从 Credential Manager 读取独立 KEK；
- 不缓存签名或 KEK；
- 用户取消返回 `AuthenticationCancelled`；
- 签名失败返回 `AuthenticationFailed`。

### 7.5 Windows 删除

`delete()` 使用 protector ID 定位 KeyCredential，然后调用
`KeyCredentialManager::DeleteAsync`。`NotFound` 视为成功。不得根据调用方重新提供的
identity 删除资源。

### 7.6 Windows 安全边界

文档必须明确：

- Windows Hello 可能接受 PIN，不保证一定是指纹或人脸；
- `identity_hash` 不是进程签名验证；
- 应用级隔离需要在目标应用模型和真实签名包中验证；
- 相同 challenge 的签名稳定性必须通过真实设备验证；
- 编译和普通单元测试不能证明跨进程或跨重启稳定性；
- 签名结果属于 KEK 派生材料，必须按秘密处理。

必须保留并扩展人工或 ignored 测试：

1. 同一 credential 和 challenge 连续签名稳定；
2. 新进程重新打开 credential 后签名稳定；
3. Windows 重启后签名稳定；
4. 错误签名不能解包；
5. 其他 credential 的签名不能解包；
6. 不执行 `RequestSignAsync` 无法构造有效 KEK；
7. 用户取消后不能解包；
8. 删除 credential 后不能解包；
9. 相同 identity 的两个 protector 使用不同 credential；
10. 删除其中一个不影响另一个；
11. 未授权应用能否打开 credential 需要独立验证。

如果真实目标环境不满足签名稳定性，必须返回不兼容或不支持，不能静默创建新格式或
新 credential。

## 8. macOS 实现

### 8.1 保留现有密码学路径

继续使用：

```text
Secure Enclave 永久私钥
+ kSecAccessControlPrivateKeyUsage
+ kSecAccessControlBiometryCurrentSet
+ ECDH
+ HKDF
+ AES-256-GCM
```

不改为 Keychain 保存明文 KEK。

### 8.2 macOS 资源命名

key tag 改为从独立 protector ID 派生。identity hash 继续写入 payload 并参与完整性
认证，但不作为唯一 key tag。

### 8.3 macOS 包装

```text
生成 protector ID
→ 创建 Secure Enclave 私钥
→ 设置 biometryCurrentSet 和 privateKeyUsage
→ 生成临时对端密钥
→ Secure Enclave 私钥执行 ECDH
→ HKDF 派生 KEK
→ 包装 DEK
→ 清零共享秘密和 KEK
→ 返回 payload
```

Secure Enclave 不可用时返回明确错误，不得创建软件永久私钥或普通 Keychain secret
作为回退。

### 8.4 macOS 解包

```text
解析 payload
→ 使用 protector ID 定位 Secure Enclave 私钥
→ 验证公钥摘要
→ 通过 SecAccessControl 触发生物识别
→ ECDH
→ HKDF 派生 KEK
→ 解包 DEK
→ 清零共享秘密和 KEK
```

要求：

- `unwrap_key()` 不得创建缺失私钥；
- 私钥缺失返回 `KeyNotFound` 或 `KeyInvalidated`；
- 生物集合变化导致密钥不可用时返回 `KeyInvalidated`；
- 用户取消返回 `AuthenticationCancelled`；
- 不缓存 ECDH 结果。

### 8.5 macOS 删除与应用身份

`delete()` 使用 payload 恢复的 protector ID 生成 key tag 并执行 `SecItemDelete`。
`item not found` 视为成功，只能删除当前 protector ID 对应的私钥。

必须区分：

- XSec identity：业务命名空间；
- protector ID：平台资源唯一标识；
- 应用身份：由代码签名、entitlement 和 Keychain access group 强制。

真实设备验证：

1. 每次 ECDH 使用都触发要求的生物认证；
2. 其他未授权签名应用不能打开私钥；
3. 复制 metadata 后，其他应用不能使用对应私钥；
4. 直接调用 ECDH 仍会由系统认证或拒绝；
5. 生物识别集合变化后旧 protector 失效。

## 9. Linux 实现

### 9.1 移除 polkit

删除 polkit 授权调用、zbus polkit 代理、对应 action ID、polkit 错误映射，以及仅为
polkit 服务的依赖和测试。

Linux 不再声称提供：

- 生物识别或用户在场验证；
- 系统安全存储；
- 当前用户或应用身份隔离；
- 跨进程或重启恢复。

### 9.2 保留 session-only 安全内存 protector

Linux system protector 定位为：

```text
当前进程
+ 当前 protector 实例
+ 安全内存中的 session key
```

能力说明：

```text
session-only: true
persistent: false
user-presence: false
user-bound: false
app-identity-bound: false
secure-memory: true
```

### 9.3 Linux 包装

```text
生成随机 protector ID
→ 生成随机 session KEK
→ KEK 保存到 SecureArray
→ 使用随机 nonce 包装 DEK
→ payload 保存 protector ID、identity hash 和 wrapped DEK
```

要求：

- session KEK 只存在内存；
- 不写入 metadata、文件、Secret Service 或环境变量；
- 新建 session key 前清零实例中已有旧 key；
- 新 key 创建后，旧 payload 返回 `KeyInvalidated`。

### 9.4 Linux 解包

```text
解析 payload
→ 验证 identity hash
→ 验证 protector ID
→ 从当前实例的 SecureArray 临时复制 KEK
→ 解包 DEK
→ 清零临时副本
```

只有仍持有 session key 的同一个 protector 实例才能解包。`from_payload()` 只能恢复
identity hash、protector ID 和格式信息，不能恢复 session KEK；由 payload 重建的实例
调用 `unwrap_key()` 返回 `KeyNotFound`。

### 9.5 Linux 删除

`delete()` 锁定内部状态、取出并清零 session key，然后将状态设为 `None`。重复调用
成功，`Drop` 时也必须确保 key 清零。

文档必须明确：Linux session-only system protector 不能作为持久 storage 的唯一恢复
方式。XSec 核心不为此增加特殊限制，由调用方决定是否同时配置持久 protector。

## 10. 错误语义

System protector 应正确区分：

- `Unsupported`：平台不支持；
- `NotConfigured`：系统认证能力没有配置；
- `UserVerificationRequired`：需要用户验证；
- `AuthenticationCancelled`：用户取消；
- `AuthenticationFailed`：验证失败；
- `KeyNotFound`：平台资源或 Linux session key 不存在；
- `KeyInvalidated`：资源 ID、公钥或认证策略不再匹配；
- `Incompatible`：payload 属于其他平台；
- `InvalidData`：payload 格式错误或被破坏；
- `ResourceCleanupFailed`：metadata 已提交，但旧资源清理失败；
- `Internal`：无法安全分类的内部错误。

禁止在 `KeyNotFound` 时自动创建密钥，也不得将用户取消、平台不支持和资源不存在统一
映射为 `Internal`。

## 11. 测试要求

### 11.1 共同测试

1. 相同 identity 的两个 system protector 使用不同 protector ID；
2. 两个 protector 的平台资源互不影响；
3. 删除其中一个不影响另一个；
4. 重复 `delete()` 成功；
5. 错误 identity 或 protector ID 不能解包；
6. payload 篡改不能解包；
7. 不同平台 payload 返回 `Incompatible`；
8. 不支持版本返回 `Unsupported`；
9. 每次包装使用不同 nonce 和 salt；
10. KEK、签名和共享秘密不进入日志或 payload。

### 11.2 Windows 测试

1. 保留签名稳定性测试；
2. 增加跨进程和重启稳定性人工测试；
3. 错误签名和其他 credential 签名不能解包；
4. 不执行 Hello 签名不能解包；
5. 删除 credential 后返回 `KeyNotFound` 或 `KeyInvalidated`；
6. 新旧 protector 使用不同 credential 名称；
7. 删除旧 credential 不影响新 protector；
8. 用户取消正确映射；
9. 应用身份隔离单独标记为真实设备验证。

### 11.3 macOS 测试

1. 私钥缺失时不自动创建；
2. 错误公钥摘要和资源 ID 不能解包；
3. Secure Enclave 失败时不回退软件私钥；
4. 生物密钥失效正确映射；
5. 删除旧私钥不影响新 protector；
6. 真实设备验证每次 ECDH 认证；
7. 真实签名应用验证应用身份隔离。

### 11.4 Linux 测试

1. 同一实例能够 wrap 和 unwrap；
2. `from_payload()` 创建的新实例不能 unwrap，返回 `KeyNotFound`；
3. 新建 session key 后旧 payload 返回 `KeyInvalidated`；
4. `delete()` 后无法 unwrap；
5. 重复 `delete()` 成功；
6. `Drop` 清零 session key；
7. 错误 key ID 返回 `KeyInvalidated`；
8. 不再发生 polkit 或 D-Bus 调用；
9. 不再依赖 polkit 相关 crate；
10. payload 中不存在 session KEK。

### 11.5 XSec 集成测试

在不修改公共方法签名的前提下验证：

1. 删除 system protector 时调用其 `delete()`；
2. metadata 保存失败时不提前删除旧平台资源；
3. 新 system protector 创建后 metadata 保存失败会清理新资源；
4. 替换 system protector 后清理旧资源；
5. 清理旧资源不会删除新资源；
6. 普通 protector 使用默认 `delete()` 不改变现有行为；
7. `destroy()` 调用 system protector 的 `delete()`；
8. 资源已不存在时删除和 destroy 仍可幂等完成。

## 12. 文档要求

更新 XSec crate 中 system protector 相关的中英文文档，明确：

- Windows 使用 Hello 签名结果派生 KEK；
- Windows Hello 可能使用 PIN，不保证严格生物识别；
- Windows 签名稳定性和应用隔离需要真实设备验证；
- macOS 使用 Secure Enclave、`biometryCurrentSet` 和 ECDH；
- Linux 只是 session-only 安全内存 protector；
- Linux 不提供用户在场、持久化、用户隔离或应用身份隔离；
- `identity_hash` 只用于命名空间和错配检测；
- `protector_id` 用于唯一定位平台资源；
- `delete()` 用于清理 protector 持有的平台或会话资源；
- 编译和单元测试不能证明真实生物识别或设备安全边界。

## 13. 允许与禁止修改的文件

允许修改：

```text
crates/xsec/src/protector/mod.rs
crates/xsec/src/protector/system/**
crates/xsec/Cargo.toml
crates/xsec/README.md
crates/xsec/README.zh-CN.md
Cargo.lock
```

`system-protector` feature 默认关闭，只控制是否编译并导出
`XSecSystemProtector`。它不修改 `XSec` 的公共方法，也不增加仅system protector
可用的 `XSec` 方法。需要使用system protector时，调用方通过通用
`XSecProtector`接口执行初始化、解锁和资源生命周期操作。

Linux的实现和文档测试可以在 `crates/xsec/src/protector/system/linux/**` 内调整。

禁止修改：

```text
crates/xsec-cli/**
```

同时不要修改 password protector 密码学、业务密文格式、storage 公共接口、XSec 公共
方法、通用状态机、`crates/xsec/tests/**` 中与本feature无关的测试和用户已有无关工作树
改动。

## 14. 验证

完成后分别执行并报告：

```text
cargo fmt -- --check
cargo check -p xsec
cargo test -p xsec
cargo check -p xsec --features system-protector
cargo test -p xsec --features system-protector
git diff --check
```

如果 feature 或 workspace 配置需要调整，报告实际完整命令。能够使用目标工具链时，再
分别执行 Windows、macOS 和 Linux 目标编译。

最终报告必须分别列出：

1. portable core 静态检查；
2. Windows 编译；
3. macOS 编译；
4. Linux 编译；
5. Windows Hello 真实设备测试；
6. macOS Secure Enclave 真实设备测试；
7. Windows 签名跨进程和重启稳定性；
8. 应用身份隔离；
9. 绕过认证的直接访问测试。

没有执行真实设备测试的项目必须标记为未验证，不能由编译或单元测试推断成功。
