//! generator.rs —— 助记词生成 + BIP32 派生 + secp256k1 + 地址计算
//!
//! 单次"生成-检查"流水线（规格 generation_pipeline）：
//! 1. `OsRng`（rand::rngs::OsRng）产生 16 / 24 / 32 字节熵（对应 12/18/24 词）；
//! 2. `bip39::Mnemonic::from_entropy_in(Language::English, entropy)`
//!    —— 英文词表（BIP39 标准词表）；
//! 3. `Mnemonic -> seed(空 passphrase，与 MetaMask 对齐) -> XPrv -> 按 path 逐层派生`
//!    （bip32 crate，rust-bitcoin 官方生态）；
//! 4. `k256::SecretKey::from_slice` 校验私钥在 [1, n-1] 范围内
//!    （0 与 ≥n 被拒绝）；
//! 5. 私钥 → 公钥（secp256k1 点乘，k256）；
//! 6. 对未压缩公钥（64 字节 x||y，无 04 前缀）做 Keccak-256（tiny-keccak）；
//! 7. 取后 20 字节作为地址，小写 hex 编码到栈上 [u8; 40]（零堆分配）；
//! 8. 匹配器判定：命中进入 GPG 加密流程，未命中丢弃全部敏感数据。
//!
//! 安全红线：
//! - 生产路径只允许 OsRng（[`Generator::try_once`]）；
//!   [`Generator::derive_and_match`] 仅用于确定性测试注入熵；
//! - 敏感缓冲（熵/种子/助记词）全部 Zeroizing 包裹；
//!   bip39/bip32 内部状态在启用 zeroize 特性后 drop 时擦除；
//! - 任何 console 输出禁止包含助记词/私钥明文。

use std::time::{SystemTime, UNIX_EPOCH};

use bip32::{ChildNumber, XPrv};
use bip39::{Language, Mnemonic};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::SecretKey;
use rand::rngs::OsRng;
use rand::TryRngCore;
use tiny_keccak::{Hasher, Keccak};
use zeroize::Zeroizing;

use crate::error::VanityError;
use crate::matcher::Matcher;

/// 最大熵长（24 词 = 256 位）
const MAX_ENTROPY: usize = 32;

/// 一次命中的完整记录。
///
/// 仅在匹配命中后构造；调用方加密落盘后应尽快让其释放
/// （敏感字段 Zeroizing 包裹，drop 时擦除）。
#[derive(Debug)]
pub struct HitRecord {
    /// EIP-55 大小写校验和地址（含 0x 前缀）
    pub address: String,
    /// 派生路径（原样取自配置）
    pub path: String,
    /// 助记词短语（敏感：Zeroizing 防止释放后残留）
    pub mnemonic: Zeroizing<String>,
    /// 命中时间（UTC，RFC3339 格式，Z 结尾）
    pub created: String,
}

/// 生成器上下文：每个工作线程独立持有一份，避免锁竞争
/// （对应规格算法层优化要求）。
#[derive(Debug)]
pub struct Generator {
    /// 助记词词数（12 / 18 / 24）
    word_count: u8,
    /// 对应熵长（16 / 24 / 32 字节）
    entropy_len: usize,
    /// 派生路径（原样字符串，用于命中记录）
    path: String,
    /// 预解析的 BIP32 子索引（LICM：路径对 Generator 是循环不变量，
    /// 原先在每轮 `derive_and_match` 里重复 `ChildNumber::new` 解析校验；
    /// 外提到构造期一次完成。原始索引由 Config 持有，此处仅保留解析结果）
    path_cns: Vec<ChildNumber>,
    /// 大小写敏感：每轮额外计算 EIP-55 校验和形式参与匹配
    case_sensitive: bool,
    /// 每个助记词派生的地址数（BIP32 末层连续索引，MetaMask 多账户同款设计）：
    /// 1 次昂贵的 BIP39 种子派生（2048 轮 PBKDF2）+ N 次廉价的末层派生，
    /// 单核吞吐约提升 N/(1+N/15) 倍（实测见 docs/performance.md）。
    /// 默认 1：每个地址独立助记词（旧行为）。
    derive_batch: u32,
}

impl Generator {
    /// 构造生成器。
    ///
    /// `path` / `path_indices` 来自 [`crate::config::Config`]（已校验）；
    /// `case_sensitive` 为 true 时每次尝试额外计算 EIP-55 校验和形式。
    pub fn new(
        word_count: u8,
        path: &str,
        path_indices: &[u32],
        case_sensitive: bool,
    ) -> Result<Self, VanityError> {
        let entropy_len = match word_count {
            12 => 16,
            18 => 24,
            24 => 32,
            other => {
                return Err(VanityError::config(
                    format!(
                        "word_count {other} is invalid for mnemonic generation; expected 12/18/24."
                    ),
                    format!("word_count {other} 非法，助记词生成仅支持 12/18/24 词。"),
                ))
            }
        };
        // LICM 外提：路径固定，构造期一次性解析 ChildNumber（含合法性校验）
        let mut path_cns = Vec::with_capacity(path_indices.len());
        for &idx in path_indices {
            let hardened = (idx & 0x8000_0000) != 0;
            let cn = ChildNumber::new(idx & 0x7FFF_FFFF, hardened).map_err(|e| {
                VanityError::config(
                    format!("invalid BIP32 child number {idx:#010x}: {e}"),
                    format!("非法 BIP32 子索引 {idx:#010x}：{e}"),
                )
            })?;
            path_cns.push(cn);
        }
        Ok(Self {
            word_count,
            entropy_len,
            path: path.to_string(),
            path_cns,
            case_sensitive,
            derive_batch: 1,
        })
    }

    /// 设置每个助记词派生的地址数（构造器风格，默认 1）。
    ///
    /// 当 batch 大于 1 时要求派生路径至少含一层索引：末层按 0,1,2… 连续派生
    /// （保留原末层的 hardened 属性）。
    pub fn with_derive_batch(mut self, batch: u32) -> Self {
        self.derive_batch = batch.max(1);
        self
    }

    /// 词数
    pub fn word_count(&self) -> u8 {
        self.word_count
    }

    /// 单次"生成-检查"（生产路径）：OsRng 产生熵后进入核心管线。
    ///
    /// 返回 `Some(HitRecord)` 表示命中；未命中时所有敏感数据已擦除。
    /// 熵源失败时 fail-closed：显式报错终止，绝不降级到弱熵源。
    pub fn try_once(
        &mut self,
        matcher: &Matcher,
    ) -> Result<(Vec<HitRecord>, u32), VanityError> {
        // 1. OsRng 熵（Zeroizing 包裹；只暴露前 entropy_len 字节给管线）
        let mut entropy = Zeroizing::new([0u8; MAX_ENTROPY]);
        OsRng
            .try_fill_bytes(&mut entropy.as_mut()[..self.entropy_len])
            .map_err(|e| {
                VanityError::internal(
                    format!("OS entropy source failure: {e}. Refusing to generate mnemonics with a degraded entropy source."),
                    format!("操作系统熵源获取失败：{e}。拒绝以降级熵源生成助记词，程序终止。"),
                )
            })?;
        self.derive_and_match(&entropy[..self.entropy_len], matcher)
    }

    /// 核心管线：熵 → 助记词 → 种子 → BIP32 派生 → 公钥 → Keccak → 匹配。
    ///
    /// `entropy` 长度必须为 16/24/32 字节（对应 12/18/24 词）。
    /// 公开仅供确定性测试注入固定熵；生产路径请使用 [`Generator::try_once`]。
    pub fn derive_and_match(
        &mut self,
        entropy: &[u8],
        matcher: &Matcher,
    ) -> Result<(Vec<HitRecord>, u32), VanityError> {
        // 防御：熵长必须与词数严格一致（测试注入路径同样受限）
        if entropy.len() != self.entropy_len {
            return Err(VanityError::internal(
                format!(
                    "entropy length {} does not match word_count {} (expected {} bytes)",
                    entropy.len(),
                    self.word_count,
                    self.entropy_len
                ),
                format!(
                    "熵长度 {} 与词数 {} 不一致（期望 {} 字节）",
                    entropy.len(),
                    self.word_count,
                    self.entropy_len
                ),
            ));
        }

        // 2. 助记词（英文词表；bip39 内部校验熵长）
        let mnemonic = Mnemonic::from_entropy_in(Language::English, entropy).map_err(|e| {
            VanityError::internal(
                format!("bip39 mnemonic generation failed: {e}"),
                format!("BIP39 助记词生成失败：{e}"),
            )
        })?;

        // 3. 种子（空 passphrase，与 MetaMask 行为对齐；内部 2048 轮 PBKDF2-HMAC-SHA512）
        let seed = Zeroizing::new(mnemonic.to_seed(""));

        // 4. BIP32 派生（hardened 位 = 0x8000_0000）；
        //    ChildNumber 已在构造期预解析（LICM 外提），热路径直接复用。
        //    derive_batch > 1 时：倒数第二层结果在同一助记词内复用，
        //    末层按 0,1,2… 连续派生（一次昂贵的种子派生摊薄到 N 个地址）
        let mut xprv = XPrv::new(seed.as_ref()).map_err(|e| {
            VanityError::internal(
                format!("bip32 master key derivation failed: {e}"),
                format!("BIP32 主密钥派生失败：{e}"),
            )
        })?;
        // 父层统一只派生到倒数第二层：末层交给逐地址循环（batch=1 时
        // 子索引 = 原末层索引，行为与旧版完全一致）
        let parent_cns = &self.path_cns[..self.path_cns.len().saturating_sub(1)];
        for &cn in parent_cns {
            xprv = xprv.derive_child(cn).map_err(|e| {
                VanityError::internal(
                    format!("bip32 child derivation failed: {e}"),
                    format!("BIP32 子密钥派生失败：{e}"),
                )
            })?;
        }
        // 末层：派生 derive_batch 个连续子索引（保留原末层 hardened 属性）
        let last = self.path_cns.last();
        let (last_idx, last_hardened) = match last {
            Some(cn) => (cn.index(), cn.is_hardened()),
            // 路径无索引（"m"）：批次恒为 1，走单次路径
            None => (0, false),
        };

        // 5..9 逐地址：末层派生 → 私钥 → 公钥 → Keccak → 匹配 →（命中）记录
        let mut hits = Vec::new();
        let batch = if self.path_cns.is_empty() {
            1 // 路径无索引（"m"）时无从批量
        } else {
            self.derive_batch
        };
        // 末层批量派生：derive_children 摊销同父重复计算（父公钥 ×2、
        // fingerprint、HMAC ipad/opad 状态每批一次），每 child 的 HMAC
        // 消息与逐个 derive_child 逐字节一致（差分门禁见测试
        // bip32_批量派生与逐个派生_bit_exact_一致 / 批派生地址序列与逐路径一致）。
        // batch=1（默认，单助记词→单地址主用途）时同样走该路径，行为不变。
        let child_xprvs: Vec<XPrv> = if self.path_cns.is_empty() {
            (0..batch).map(|_| xprv.clone()).collect()
        } else {
            let children: Result<Vec<ChildNumber>, VanityError> = (0..batch)
                .map(|i| {
                    ChildNumber::new(last_idx + i, last_hardened).map_err(|e| {
                        VanityError::internal(
                            format!("invalid BIP32 child number {:#010x}: {e}", last_idx + i),
                            format!("非法 BIP32 子索引 {:#010x}：{e}", last_idx + i),
                        )
                    })
                })
                .collect();
            xprv.derive_children(&children?).map_err(|e| {
                VanityError::internal(
                    format!("bip32 child derivation failed: {e}"),
                    format!("BIP32 子密钥派生失败：{e}"),
                )
            })?
        };
        for (i, child_xprv) in child_xprvs.into_iter().enumerate() {
            let i = i as u32;

            // 6. 私钥范围检查 [1, n-1]：from_slice 拒绝 0 与 ≥n
            let sk = SecretKey::from_slice(child_xprv.to_bytes().as_slice()).map_err(|e| {
                VanityError::internal(
                    format!("derived private key rejected by secp256k1: {e}"),
                    format!("派生私钥未通过 secp256k1 范围检查：{e}"),
                )
            })?;

            // 7. 公钥（未压缩 65 字节：04 || x || y，取 x||y 共 64 字节）
            let point = sk.public_key().as_affine().to_encoded_point(false);
            let xy = point.as_bytes().get(1..65).ok_or_else(|| {
                VanityError::internal("unexpected SEC1 encoding length", "SEC1 编码长度异常")
            })?;

            // 8. Keccak-256 → 后 20 字节 → 小写 hex 到栈上缓冲（零堆分配）
            let mut digest = [0u8; 32];
            let mut keccak = Keccak::v256();
            keccak.update(xy);
            keccak.finalize(&mut digest);
            let mut hex40 = [0u8; 40];
            hex::encode_to_slice(&digest[12..32], hex40.as_mut()).map_err(|e| {
                VanityError::internal(
                    format!("hex encoding failed: {e}"),
                    format!("地址 hex 编码失败：{e}"),
                )
            })?;

            // 9. 匹配判定（front → back → middle 分层剪枝）
            //    大小写敏感模式：额外计算 EIP-55 校验和形式（栈上缓冲，零堆分配）
            let matched = if self.case_sensitive {
                let mut checksum = [0u8; 40];
                eip55_into(&hex40, &mut checksum);
                matcher.matches(&hex40, Some(&checksum))
            } else {
                matcher.matches(&hex40, None)
            };
            if !matched {
                continue; // 未命中：跳过该地址，敏感数据随迭代结束擦除
            }

            // 10. 命中：计算 EIP-55 校验和并构造记录
            //     path 标注命中地址的真实派生索引（同助记词的第 i 个账户）
            let address = eip55_checksum_address(&hex40);
            let mnemonic_phrase = Zeroizing::new(mnemonic.to_string());
            let record_path = if batch > 1 {
                self.path_with_child(last_idx + i, last_hardened)
            } else {
                self.path.clone()
            };
            hits.push(HitRecord {
                address,
                path: record_path,
                mnemonic: mnemonic_phrase,
                created: iso8601_utc_now(),
            });
        }
        // 敏感数据显式擦除由 Zeroizing/bip39 zeroize 特性在作用域结束时完成
        Ok((hits, batch))
    }

    /// 命中地址的完整派生路径字符串（末层索引替换为实际账户索引）
    fn path_with_child(&self, idx: u32, hardened: bool) -> String {
        let base_end = self.path.rfind('/').map_or(0, |p| p + 1);
        format!(
            "{}{}{}",
            &self.path[..base_end],
            idx,
            if hardened { "'" } else { "" }
        )
    }
}

/// 计算 EIP-55 大小写校验和地址（输入为 40 字节小写 hex，输出含 0x）。
///
/// 仅在匹配命中后调用（对应规格 matching_rules 第 6 条）。
pub fn eip55_checksum_address(hex40_lower: &[u8]) -> String {
    let mut digest = [0u8; 32];
    eip55_digest(hex40_lower, &mut digest);

    let mut out = String::with_capacity(42);
    out.push_str("0x");
    for (i, &b) in hex40_lower.iter().enumerate() {
        let nibble = nibble_at(&digest, i);
        let mut c = b as char;
        if nibble >= 8 {
            c = c.to_ascii_uppercase();
        }
        out.push(c);
    }
    out
}

/// EIP-55 校验和形式的栈上版本（无堆分配），供大小写敏感匹配热循环使用
fn eip55_into(hex40_lower: &[u8], out: &mut [u8; 40]) {
    let mut digest = [0u8; 32];
    eip55_digest(hex40_lower, &mut digest);
    for (i, &b) in hex40_lower.iter().enumerate() {
        let nibble = nibble_at(&digest, i);
        out[i] = if nibble >= 8 {
            b.to_ascii_uppercase()
        } else {
            b
        };
    }
}

/// keccak256(小写 hex 字符串) —— EIP-55 的大小写来源
fn eip55_digest(hex40_lower: &[u8], digest: &mut [u8; 32]) {
    let mut keccak = Keccak::v256();
    keccak.update(hex40_lower);
    keccak.finalize(digest);
}

/// EIP-55：第 i 个 hex 字符对应摘要的第 i 个 nibble（高位在前）
#[inline]
fn nibble_at(digest: &[u8; 32], i: usize) -> u8 {
    if i % 2 == 0 {
        digest[i / 2] >> 4
    } else {
        digest[i / 2] & 0x0f
    }
}

/// 当前 UTC 时间的 RFC3339 字符串（如 2026-09-25T12:00:00Z）
pub(crate) fn iso8601_utc_now() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    iso8601_utc(secs)
}

/// 当前 UTC 时间的文件名时间戳（如 20260925_120000）
pub(crate) fn yyyymmdd_hhmmss_now() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let iso = iso8601_utc(secs);
    // "2026-09-25T12:00:00Z" → "20260925_120000"
    let s: String = iso.chars().filter(|c| c.is_ascii_digit()).collect();
    format!("{}_{}", &s[..8], &s[8..14])
}

/// Unix 秒 → RFC3339/ISO-8601 UTC（无外部时间依赖，Hinnant 民用历算法）
fn iso8601_utc(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (hh, mm, ss) = (rem / 3_600, (rem % 3_600) / 60, rem % 60);

    // civil_from_days（Howard Hinnant，公有领域算法）
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097); // [0, 146096]
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let y = if m <= 2 { y + 1 } else { y };

    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 官方测试向量（Trezor vectors.json，entropy 全零）的助记词
    const MNEMONIC_12: &str = "abandon abandon abandon abandon abandon abandon \
                               abandon abandon abandon abandon abandon about";
    const MNEMONIC_18: &str = "abandon abandon abandon abandon abandon abandon \
                               abandon abandon abandon abandon abandon abandon \
                               abandon abandon abandon abandon abandon agent";
    const MNEMONIC_24: &str = "abandon abandon abandon abandon abandon abandon \
                               abandon abandon abandon abandon abandon abandon \
                               abandon abandon abandon abandon abandon abandon \
                               abandon abandon abandon abandon abandon art";

    /// 默认派生路径 m/44'/60'/0'/0/0 的解析结果
    const DEFAULT_INDICES: [u32; 5] = [
        0x8000_002C,
        0x8000_003C,
        0x8000_0000,
        0,
        0,
    ];

    #[test]
    fn bip39_12词_官方向量_种子() {
        let m = Mnemonic::from_entropy_in(Language::English, &[0u8; 16]).unwrap();
        assert_eq!(m.to_string(), MNEMONIC_12);
        // Trezor 官方向量（passphrase = "TREZOR"）
        assert_eq!(
            hex::encode(m.to_seed("TREZOR")),
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553\
             1f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
        );
        // 空 passphrase（与本项目/MetaMask 行为一致），Python hashlib 交叉验证
        assert_eq!(
            hex::encode(m.to_seed("")),
            "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1\
             9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
        );
    }

    #[test]
    fn bip39_18词_官方向量_种子() {
        let m = Mnemonic::from_entropy_in(Language::English, &[0u8; 24]).unwrap();
        assert_eq!(m.to_string(), MNEMONIC_18);
        // Python hashlib.pbkdf2_hmac 独立交叉验证（空 passphrase）
        assert_eq!(
            hex::encode(m.to_seed("")),
            "4975bb3d1faf5308c86a30893ee903a976296609db223fd717e227da5a813a34\
             dc1428b71c84a787fc51f3b9f9dc28e9459f48c08bd9578e9d1b170f2d7ea506"
        );
    }

    #[test]
    fn bip39_24词_官方向量_种子() {
        let m = Mnemonic::from_entropy_in(Language::English, &[0u8; 32]).unwrap();
        assert_eq!(m.to_string(), MNEMONIC_24);
        // Python hashlib.pbkdf2_hmac 独立交叉验证（空 passphrase）
        assert_eq!(
            hex::encode(m.to_seed("")),
            "408b285c123836004f4b8842c89324c1f01382450c0d439af345ba7fc49acf70\
             5489c6fc77dbd4e3dc1dd8cc6bc9f043db8ada1e243c4a0eafb290d399480840"
        );
    }

    /// 确定性派生：24 词全 abandon @ m/44'/60'/0'/0/0
    /// 期望值来自独立 Python 实现（hashlib + 手写 BIP32 CKD + secp256k1 +
    /// pycryptodome keccak，锚定 EIP-55 官方向量），与 bip32/k256 双向互验。
    #[test]
    fn 确定性派生_24词全abandon_默认路径地址() {
        let mut g = Generator::new(24, "m/44'/60'/0'/0/0", &DEFAULT_INDICES, false).unwrap();
        let m = Matcher::new(false, None, None, None); // 全条件匹配器，必然命中
        let (hits, _) = g.derive_and_match(&[0u8; 32], &m).unwrap();
        let hit = &hits[0];
        assert_eq!(hit.address, "0xF278cF59F82eDcf871d630F28EcC8056f25C1cdb");
        assert_eq!(hit.path, "m/44'/60'/0'/0/0");
        assert_eq!(*hit.mnemonic, MNEMONIC_24);
        assert!(hit.created.ends_with('Z') && hit.created.len() == 20);
    }

    /// 12 词 / 18 词确定性地址（同一独立实现交叉验证）
    #[test]
    fn 确定性派生_12词与18词() {
        let m = Matcher::new(false, None, None, None);

        let mut g12 = Generator::new(12, "m/44'/60'/0'/0/0", &DEFAULT_INDICES, false).unwrap();
        let (hits12, _) = g12.derive_and_match(&[0u8; 16], &m).unwrap();
        let hit12 = &hits12[0];
        assert_eq!(hit12.address, "0x9858EfFD232B4033E47d90003D41EC34EcaEda94");

        let mut g18 = Generator::new(18, "m/44'/60'/0'/0/0", &DEFAULT_INDICES, false).unwrap();
        let (hits18, _) = g18.derive_and_match(&[0u8; 24], &m).unwrap();
        let hit18 = &hits18[0];
        assert_eq!(hit18.address, "0x197A1bEE163923815Ba58EaD0F14B3Fcd8C5926d");
    }

    /// 路径差异化：0/217 与极深路径 0/2147483647（边界测试要求）
    #[test]
    fn 确定性派生_路径差异化与极深路径() {
        let m = Matcher::new(false, None, None, None);

        let mut g217 =
            Generator::new(24, "m/44'/60'/0'/0/217", &[0x8000_002C, 0x8000_003C, 0x8000_0000, 0, 217], false)
                .unwrap();
        let (hits, _) = g217.derive_and_match(&[0u8; 32], &m).unwrap();
        let hit = &hits[0];
        assert_eq!(hit.address, "0xCaCFFdD18ecD36cac714cC9457fc508008f222b2");

        let mut gdeep = Generator::new(
            24,
            "m/44'/60'/0'/0/2147483647",
            &[0x8000_002C, 0x8000_003C, 0x8000_0000, 0, 2_147_483_647],
            false,
        )
        .unwrap();
        let (hits_deep, _) = gdeep.derive_and_match(&[0u8; 32], &m).unwrap();
        let hit = &hits_deep[0];
        assert_eq!(hit.address, "0xeD0092C60c525E6DB9c131F5971Ed5Fed05E496C");
    }

    /// BIP32 官方测试向量 1（锚定 bip32 crate 的主密钥与 hardened 派生）
    #[test]
    fn bip32_官方向量1_锚定() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let root = XPrv::new(&seed).unwrap();
        assert_eq!(
            hex::encode(root.to_bytes()),
            "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35"
        );
        let h0 = root
            .derive_child(ChildNumber::new(0, true).unwrap())
            .unwrap();
        assert_eq!(
            hex::encode(h0.to_bytes()),
            "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea"
        );
        let h0n1 = h0
            .derive_child(ChildNumber::new(1, false).unwrap())
            .unwrap();
        assert_eq!(
            hex::encode(h0n1.to_bytes()),
            "3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368"
        );
    }

    /// 差分门禁：vendored bip32 新增的 derive_children（批量摊销路径：
    /// 父公钥/fingerprint/HMAC ipad-opad 每批一次）与逐个 derive_child
    /// 必须 bit-exact 一致。覆盖非 hardened / hardened / 混合 / 大索引 /
    /// 重复索引 / 单元素 / 空 / 深层再派生。
    #[test]
    fn bip32_批量派生与逐个派生_bit_exact_一致() {
        let seed = [0x42u8; 64];
        let master = XPrv::new(seed).unwrap();
        let cases: &[Vec<(u32, bool)>] = &[
            vec![(0, false), (1, false), (2, false), (3, false), (7, false)],
            vec![(0, true), (1, true), (2, true)],
            vec![(0, false), (0xFF, true), (100_000_000, false), (0, false), (1, true)],
            vec![(7, false)],
            vec![],
        ];
        for seq in cases {
            let children: Vec<ChildNumber> = seq
                .iter()
                .map(|&(n, h)| ChildNumber::new(n, h).unwrap())
                .collect();
            let batch = master.derive_children(&children).unwrap();
            assert_eq!(batch.len(), children.len());
            for (i, &cn) in children.iter().enumerate() {
                let one = master.derive_child(cn).unwrap();
                assert_eq!(
                    batch[i].to_bytes().as_ref(),
                    one.to_bytes().as_ref(),
                    "child #{i} ({cn:?}) 私钥不一致"
                );
            }
        }
        // 深层再派生（确保链码/attrs 无误，同路径序列批量结果可继续正确派生）
        let batch = master
            .derive_children([ChildNumber::new(0, false).unwrap()].as_slice())
            .unwrap();
        let deep_batch = batch[0]
            .derive_children(&[ChildNumber::new(5, false).unwrap()].as_slice())
            .unwrap();
        let deep_one = master
            .derive_child(ChildNumber::new(0, false).unwrap())
            .unwrap()
            .derive_child(ChildNumber::new(5, false).unwrap())
            .unwrap();
        assert_eq!(deep_batch[0].to_bytes().as_ref(), deep_one.to_bytes().as_ref());
    }

    /// 端到端差分：批派生（derive_children 路径）产出的地址序列与
    /// 逐路径单派生完全一致（同助记词、逐个索引）。
    #[test]
    fn 批派生地址序列与逐路径一致() {
        let m = Matcher::new(false, None, None, None); // 全命中
        let entropy = [0x11u8; 32];
        // 批 4：末层 0..3 连续
        let mut g_batch = Generator::new(24, "m/44'/60'/0'/0/0", &DEFAULT_INDICES, false)
            .unwrap()
            .with_derive_batch(4);
        let (hits_batch, n) = g_batch.derive_and_match(&entropy, &m).unwrap();
        assert_eq!(n, 4);
        // 逐路径：i=0..3（注意 path_indices 才是实际派生层，path 仅显示用）
        for i in 0..4u32 {
            let indices = [0x8000_002C, 0x8000_003C, 0x8000_0000, 0, i];
            let path = format!("m/44'/60'/0'/0/{i}");
            let mut g = Generator::new(24, &path, &indices, false).unwrap();
            let (hits_one, _) = g.derive_and_match(&entropy, &m).unwrap();
            assert_eq!(
                hits_batch[i as usize].address, hits_one[0].address,
                "批量第 {i} 个地址与单派生不一致"
            );
        }
    }

    /// 同熵同参数必须可重现（确定性要求）
    #[test]
    fn 同熵两次派生结果一致() {
        let m = Matcher::new(false, None, None, None);
        let mut a = Generator::new(24, "m/44'/60'/0'/0/0", &DEFAULT_INDICES, false).unwrap();
        let mut b = Generator::new(24, "m/44'/60'/0'/0/0", &DEFAULT_INDICES, false).unwrap();
        let (ra, _) = a.derive_and_match(&[7u8; 32], &m).unwrap();
        let (rb, _) = b.derive_and_match(&[7u8; 32], &m).unwrap();
        assert_eq!(ra[0].address, rb[0].address);
    }

    /// 私钥边界：0 与 n（曲线阶）必须被拒绝；n-1 是合法私钥（BIP32 语义：
    /// 有效范围 [1, n-1] 闭区间，规格 generation_pipeline 同款表述）
    #[test]
    fn 私钥边界检查() {
        assert!(SecretKey::from_slice(&[0u8; 32]).is_err(), "0 必须被拒绝");
        let n = hex::decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")
            .unwrap();
        assert!(SecretKey::from_slice(&n).is_err(), "n 必须被拒绝");
        let n_minus_1 =
            hex::decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140")
                .unwrap();
        assert!(SecretKey::from_slice(&n_minus_1).is_ok(), "n-1 是合法私钥");
    }

    /// EIP-55 官方测试向量（EIP-55 规范附录样例）
    #[test]
    fn eip55_官方样例() {
        let cases = [
            ("5aaeb6053f3e94c9b9a09f33669435e7ef1beaed", "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"),
            ("fb6916095ca1df60bb79ce92ce3ea74c37c5d359", "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359"),
            ("dbf03b407c01e7cd3cbea99509d93f8dddc8c6fb", "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB"),
            ("d1220a0cf47c7b9be7a2e6ba89f429762e7b9adb", "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb"),
            // 全大写 / 全小写形式的官方样例
            ("52908400098527886e0f7030069857d2e4169ee7", "0x52908400098527886E0F7030069857D2E4169EE7"),
            ("de709f2102306220921060314715629080e2fb77", "0xde709f2102306220921060314715629080e2fb77"),
        ];
        for (lower, expected) in cases {
            assert_eq!(eip55_checksum_address(lower.as_bytes()), expected);
        }
    }

    /// RFC3339 UTC 格式化（Python datetime 独立验证）
    #[test]
    fn utc时间格式化() {
        assert_eq!(iso8601_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso8601_utc(1_700_000_000), "2023-11-14T22:13:20Z");
        assert_eq!(iso8601_utc(1_790_342_666), "2026-09-25T13:24:26Z");
        // 闰日
        assert_eq!(iso8601_utc(951_782_400), "2000-02-29T00:00:00Z");
    }

    /// 生产路径冒烟：OsRng 循环 50 次不命中、无 panic（front=ffff 剪枝）
    #[test]
    fn try_once_osrng_冒烟() {
        let m = Matcher::new(false, Some(b"ffff".to_vec()), None, None);
        let mut g = Generator::new(24, "m/44'/60'/0'/0/0", &DEFAULT_INDICES, false).unwrap();
        for _ in 0..50 {
            let (r, _) = g.try_once(&m).unwrap();
            assert!(r.is_empty(), "ffff 前缀在 50 次内命中概率约 2^-196，不应命中");
        }
    }

    /// derive_batch 批派生：同一助记词派生 0..3 四个连续地址，
    /// 与独立实例逐路径派生的结果完全一致（确定性交叉验证）
    #[test]
    fn derive_batch_批派生与逐路径一致() {
        let m = Matcher::new(false, None, None, None);
        let entropy = [5u8; 32];
        // 批派生：一个助记词 → 4 个地址
        let mut g = Generator::new(24, "m/44'/60'/0'/0/0", &DEFAULT_INDICES, false)
            .unwrap()
            .with_derive_batch(4);
        let (hits, checked) = g.derive_and_match(&entropy, &m).unwrap();
        assert_eq!(checked, 4);
        assert_eq!(hits.len(), 4, "全条件匹配器应命中全部 4 个派生地址");
        // 逐路径独立派生：m/44'/60'/0'/0/{0..3}
        for i in 0..4u32 {
            let indices = [0x8000_002C, 0x8000_003C, 0x8000_0000, 0, i];
            let mut gi = Generator::new(24, &format!("m/44'/60'/0'/0/{i}"), &indices, false).unwrap();
            let (hi, _) = gi.derive_and_match(&entropy, &m).unwrap();
            assert_eq!(hits[i as usize].address, hi[0].address, "账户 {i} 地址应一致");
            assert_eq!(hits[i as usize].path, format!("m/44'/60'/0'/0/{i}"));
            assert_eq!(*hits[i as usize].mnemonic, *hi[0].mnemonic, "同一助记词");
        }
    }

    /// derive_batch=1（默认）：行为与旧版一致，path 为配置原样
    #[test]
    fn derive_batch_默认1路径原样() {
        let m = Matcher::new(false, None, None, None);
        let mut g = Generator::new(24, "m/44'/60'/0'/0/0", &DEFAULT_INDICES, false).unwrap();
        let (hits, checked) = g.derive_and_match(&[0u8; 32], &m).unwrap();
        assert_eq!(checked, 1);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].path, "m/44'/60'/0'/0/0");
    }

    /// 末层 hardened 路径的批派生：子索引保留 hardened 属性
    #[test]
    fn derive_batch_hardened末层() {
        let m = Matcher::new(false, None, None, None);
        let indices = [0x8000_002C, 0x8000_003C, 0x8000_0000, 0x8000_0005];
        let mut g = Generator::new(24, "m/44'/60'/0'/0/5'", &indices, false)
            .unwrap()
            .with_derive_batch(2);
        let (hits, _) = g.derive_and_match(&[1u8; 32], &m).unwrap();
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].path, "m/44'/60'/0'/0/5'");
        assert_eq!(hits[1].path, "m/44'/60'/0'/0/6'");
    }

    /// 熵长度不匹配：12 词生成器注入 32 字节熵应报内部错误而非 panic
    #[test]
    fn 熵长度不匹配_报错() {
        let mut g = Generator::new(12, "m/44'/60'/0'/0/0", &DEFAULT_INDICES, false).unwrap();
        let m = Matcher::new(false, None, None, None);
        let r = g.derive_and_match(&[0u8; 32], &m);
        assert!(r.is_err(), "bip39 对 32 字节熵会生成 24 词，本项目要求长度与词数一致");
    }
}

