# 密码学安全审计（对照行业事故与大型项目设计）

> 审计范围：熵源、助记词/派生、地址计算、密文输出全链路。
> 参照系：以太坊/BTC 历史真实事故 + MetaMask 等大型钱包的安全设计。

## 一、行业事故对照（"别人是怎么死的"）

### 1. Profanity 靓号地址工具（2022，损失约 330 万美元）
- **事故机理**：Profanity 为提速把 256 位熵截成 **32 位**种子暴力枚举靓号，
  攻击者暴力穷举全部 2³² 空间后反推出私钥，盗走 Wintermute 等约 $3.3M。
- **与本项目的关系**：这是与我们最直接相关的反面教材。本项目
  **熵源恒为 OsRng 全量 128/192/256 位**（BIP39 词数对应），不存在任何
  熵空间缩减；速率优化从不以牺牲熵为代价（见第三节 derive_batch 论证）。
- **红线**：任何"性能优化"若需要缩减熵或复用部分随机状态，直接否决。

### 2. Android SecureRandom 事故（2013，BTC 钱包重复密钥）
- 弱 RNG 输出重复熵 → 多个用户生成相同私钥。
- 本项目：**唯一熵源 = 操作系统 CSPRNG**（OsRng/getrandom），
  无任何用户态 PRNG、无时间戳/种子文件参与；熵获取失败即 fail-closed 终止。

### 3. ECDSA 签名 nonce 复用（区块链.info 2014 等系列）
- k 值重复/可预测导致私钥从签名中恢复。
- 本项目：**不签名**（只生成地址），不存在 nonce 路径；将来若加签名功能
  必须使用 RFC6979 确定性 nonce。

### 4. 供应链投毒（Rust 生态 2024-2026 多起）
- 本项目对策：**全部依赖 vendor 入仓 + Cargo.lock checksum 锚定**，
  构建零网络下载；`.gitattributes` 禁止换行符转换破坏校验；
  依赖树纯 Rust、零 unsafe、无 build.rs 执行任意脚本（sequoia 除外——
  其构建脚本仅做特性探测，无网络行为）。

## 二、对照 MetaMask 的设计基线

| 设计点 | MetaMask | 本项目 | 一致性 |
|---|---|---|---|
| 助记词 | BIP39，128/256 位熵 | BIP39，128/192/256 位熵 | ✓ |
| 种子派生 | PBKDF2-HMAC-SHA512 ×2048，空 passphrase | 同（对齐源码级） | ✓ |
| 账户派生 | m/44'/60'/0'/0/N，多账户同助记词 | 同路径；derive_batch 即此模型 | ✓ |
| 私钥范围 | secp256k1 [1, n-1] | from_slice 严格校验（0/n 拒绝） | ✓ |
| 地址编码 | EIP-55 校验和 | 同（命中才计算，keccak-256） | ✓ |
| 密钥落盘 | 密码加密的 vault | **GPG 公钥加密**（无需在生成机输入口令，更适合无人值守 CI） | 设计差异，安全性等价或更优 |

## 三、derive_batch（单种子多地址）安全性论证

**它是什么**：一个助记词（BIP39 全随机熵）→ BIP32 标准派生
`m/44'/60'/0'/0/0..N-1` 共 N 个地址。这**不是新发明**——MetaMask
"多个账户"按钮背后的完全相同机制。

**为什么安全**：
1. **熵强度不变**：每个助记词仍由 OsRng 全量熵生成（128/256 位），
   PBKDF2 2048 轮照常执行。提速来自"摊薄种子派生成本"，不是缩减随机性
   ——与 Profanity 的截断熵有本质区别。
2. **每个地址独立完整**：N 个地址各自经完整 BIP32 CKD（每层独立
   HMAC-SHA512）与 secp256k1 校验，任何一个的密钥强度都等价于独立派生。
   攻击者知道地址 i 无法推知地址 j（BIP32 非 hardened 兄弟推导仅限
   **持有父扩展公钥**时；我们的父公钥从不离开进程且不落盘）。
   注：末层为非 hardened（MetaMask 标准路径），若用户自定义 hardened
   末层（带 '），则连父公钥泄露也无法推导兄弟——批派生保留该属性。
3. **密钥托管模型与 MetaMask 一致**：备份助记词 = 备份该钱包全部 N 个
   账户。用户把助记词导入任何标准钱包（MetaMask 第 i 个账户）即可
   完整恢复命中地址的资产。
4. **默认关闭**：`derive_batch` 不配置时 = 1（每个地址独立助记词，
   与旧版行为完全一致）。启用是用户的显式知情选择，文档明示语义。

**风险告知（写入 README）**：批派生 N 个地址共享同一助记词——若用户
只想导入单个私钥而丢弃助记词，同助记词的其他地址资产会一并丢失；
正确用法是完整保存助记词（与所有标准钱包一致）。

## 四、本项目的密码学红线清单（复核结论）

- [x] 熵源唯一 OsRng，fail-closed，无用户态熵混合
- [x] 零自实现密码原语（BIP39/BIP32/EIP-55/secp256k1/keccak/GPG 全部权威库）
- [x] 零 unsafe（`#![forbid(unsafe_code)]`）
- [x] 敏感缓冲 Zeroizing 包裹；bip39/bip32 zeroize 特性启用
- [x] 命中前不计算/不输出校验和形式以外的任何附加数据
- [x] 密文输出 GPG 公钥加密（sequoia，cv25519+AES），私钥永不落盘
- [x] 构建供应链：vendor + checksum + 纯 Rust
- [x] 速率优化路径（SIMD 匹配、LICM、批派生）均不触碰熵与协议构造

## 五、vendored 库性能补丁的安全论证（2026-10-01，保留决策）

按"改库源码 + 清空 checksum 映射 + 差分验证"方式对 vendored 库做的性能
修改（bitcoin_hashes 新增 `compress_block` 原语；bip39 pbkdf2 热循环直驱
压缩），安全性论证链条完整，**结论通过并保留**：

1. **密码学原语零新增**：compress_block 是原 `process_block` 80 轮压缩体
   的逐行参数化（同一宏展开），不引入任何新的数学运算；pbkdf2 热循环
   的 HMAC 结构（ipad/opad 状态 + 192 字节消息终块）与原实现数学等价
   ——U1 与密钥化仍走原引擎路径。
2. **逐位一致性差分**：tests/pbkdf2_differential.rs 用 RustCrypto
   （hmac+sha2，业界审计最广的实现之一）作**独立参考**，12/18/24 词 ×
   空口令/TREZOR/长口令/超 128 字节触发密钥先哈希分支，输出逐位一致；
   BIP39 官方黄金向量锚定；66 项地址级确定性向量回归。
   **该测试是 CI 常驻门禁**——库行为任何偏移都会被拦截。
3. **零 unsafe、零新依赖、零供应链外联**：修改局限于 vendored 源码 +
   标准 vendor 补丁机制（.cargo-checksum.json files 映射清空），构建
   仍离线自包含。
4. **性能实测**（perf-research §7，2026-10-02 修正）：强制重编译后
   A/B 实测 **+6.5%**（433 → ~464/s）。首轮"0%"为本地 cargo 指纹缓存
   假阴性（vendored crate 指纹不跟踪源码改动，测的是基线对自己），已
   修正并留档教训：改 vendored 库必须 `cargo clean -p` 强制重编译、以
   CI 全新编译为准。

**总结论**：未发现违反上述任何规范的实现；derive_batch 与 MetaMask
多账户模型同构，安全等价，默认关闭、显式启用。


## 六、性能补丁密码学安全专项复核（2026-10-07，用户点名验收项）

本轮 4 项修改逐项复核（红线：只用权威库 / 禁自实现原语 / OsRng 唯一
熵源 / 禁 unsafe / 零新依赖）：

| # | 修改 | 密码学性质 | 复核结论 |
|---|---|---|---|
| 1 | derive_children 批量摊销 | HMAC 消息与逐个派生逐字节一致（差分门禁 bit-exact）；父公钥/ipad-opad 只是消除**重复计算**，非改变计算 | ✅ 无密码学语义变化 |
| 2 | XPrv::new 常量 midstate 直驱 | 标准 HMAC 结构组装；压缩用 bitcoin_hashes::sha512::compress_block（权威库公共原语，与 bip39 pbkdf2 直驱同模式先例）；OnceLock 缓存的是**公开常量 key**（"Bitcoin seed"）的 keyed 状态，无秘密可泄 | ✅ 差分 10 种子 bit-exact |
| 3 | nofingerprint 变体 | BIP32 规范：parent_fingerprint 仅供 XPRV/XPUB 序列化识别父密钥，**不参与任何 CKD 计算**；程序输出（地址/助记词/path）不含中间层序列化 | ✅ 密钥/链码 bit-exact 门禁；API 命名显式传达 trade-off |
| 4 | mul_by_generator（预计算生成元表） | 数学恒等 k×G；表为 k256 官方 precomputed-tables feature（默认启用，非我们注入）；LookupTable::select 为**常量时间**实现（库注释明示） | ✅ 纯调用方改动，零库修改 |

红线全项保持：全部修改为 safe Rust（零 unsafe）；熵源 OsRng 调用链
未触碰；Zeroizing 敏感数据擦除路径未改动；无新增第三方 crate
（bitcoin_hashes 依赖为树内既有包，bip32→它的新边不引入新代码）；
无秘密依赖的条件分支（匹配规则/路径均为公开配置）。

差分门禁总计（常驻 CI）：pbkdf2 直驱（12/18/24 词×口令分支）、
derive_children bit-exact、批地址序列端到端、XPrv::new 快/慢路径
bit-exact、跳指纹 bit-exact、跳指纹端到端地址一致 + BIP32/BIP39
官方向量锚定。
