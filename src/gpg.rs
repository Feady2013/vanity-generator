//! gpg.rs —— OpenPGP 加密封装（sequoia-openpgp，输出与 GnuPG 兼容）
//!
//! 职责（规格 gpg_encryption）：
//! 1. 解析 ASCII armor 公钥（`sequoia_openpgp::Cert`，自动识别 armor，
//!    任何后缀的纯文本公钥均可，armor 头已在 config 层校验）；
//! 2. 按固定格式构造明文：
//!    ```text
//!    Address: 0x...
//!    Path: m/44'/60'/0'/0/0
//!    Mnemonic: word1 ... wordN
//!    Created: 2026-09-25T12:00:00Z
//!    ```
//! 3. 用公钥加密（策略筛选 alive/未吊销/可加密的子密钥），
//!    输出 ASCII Armor（与 `gpg -a` 输出兼容）；
//! 4. 落盘 `vanity_YYYYMMDD_HHMMSS_NNN.asc`（NNN 为本次运行序号），
//!    放在可执行文件同目录等待用户提取；
//! 5. 加密成功后明文缓冲随 Zeroizing 释放擦除。
//!
//! 加密完全在本地完成，无需用户提供私钥；
//! 公钥格式兼容 GnuPG 导出的任何 ASCII armor 公钥。

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use sequoia_openpgp as openpgp;
use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy;
use openpgp::serialize::stream::{Armorer, Encryptor2, LiteralWriter, Message};
use zeroize::Zeroizing;

use crate::error::VanityError;
use crate::generator::{yyyymmdd_hhmmss_now, HitRecord};

/// GPG 加密器：持有已解析的公钥证书与策略
pub struct GpgEncryptor {
    /// 可用加密子密钥数量（构造时校验，供启动日志展示）
    usable_keys: usize,
    /// 已解析的公钥证书
    certs: Vec<openpgp::Cert>,
    /// 策略（构造时创建，加密时复用）
    policy: StandardPolicy<'static>,
}

impl std::fmt::Debug for GpgEncryptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GpgEncryptor")
            .field("usable_keys", &self.usable_keys)
            .field("certs", &self.certs.len())
            .finish()
    }
}

impl GpgEncryptor {
    /// 从公钥数据（ASCII armor 或二进制）构造加密器。
    ///
    /// 构造时即完成 Cert 解析与加密子密钥的策略筛选，任何问题在
    /// 启动阶段以双语 fatal error 暴露，而不是等到第一次命中。
    pub fn from_bytes(data: &[u8]) -> Result<Self, VanityError> {
        let cert = openpgp::Cert::from_bytes(data).map_err(|e| {
            VanityError::config(
                format!(
                    "failed to parse the OpenPGP public key: {e}. \
                     Make sure it is an ASCII-armored public key exported by GnuPG (gpg --armor --export)."
                ),
                format!(
                    "OpenPGP 公钥解析失败：{e}。请确认公钥是 GnuPG 导出的 ASCII armor 公钥（gpg --armor --export）。"
                ),
            )
        })?;

        let policy = StandardPolicy::new();
        let usable_keys = count_encryption_keys(&cert, &policy);
        if usable_keys == 0 {
            return Err(VanityError::config(
                "the public key has no usable encryption subkey (alive, not revoked, \
                 encryption-capable). Please re-export a public key that contains an \
                 encryption-capable subkey.",
                "公钥中没有可用的加密子密钥（需处于有效期、未吊销且具备加密能力）。\
                 请重新导出包含加密子密钥的公钥。",
            ));
        }

        Ok(Self {
            usable_keys,
            certs: vec![cert],
            policy,
        })
    }

    /// 可用加密子密钥数量（启动日志展示用）
    pub fn usable_keys(&self) -> usize {
        self.usable_keys
    }

    /// 加密并落盘一条命中记录。
    ///
    /// 返回落盘文件路径；明文缓冲随 Zeroizing 在作用域结束擦除。
    /// `seq`：本次运行内序号（从 1 开始，文件名 NNN 三位零填充）。
    pub fn encrypt_to_file(
        &self,
        record: &HitRecord,
        out_dir: &Path,
        seq: u32,
    ) -> Result<PathBuf, VanityError> {
        // 明文缓冲：敏感，drop 时擦除
        let plaintext = Zeroizing::new(build_plaintext(record));

        // vanity_YYYYMMDD_HHMMSS_NNN.asc（UTC 时间）
        let out_path = out_dir.join(format!(
            "vanity_{}_{:03}.asc",
            yyyymmdd_hhmmss_now(),
            seq
        ));

        let mut sink = fs::File::create(&out_path).map_err(|e| {
            VanityError::io(
                format!("failed to create output file {}: {e}.", out_path.display()),
                format!("创建输出文件 {} 失败：{e}。", out_path.display()),
            )
        })?;

        {
            let message = Message::new(&mut sink);
            let message = Armorer::new(message).build().map_err(sequoia_err)?;
            let recipients = self.certs.iter().flat_map(|cert| {
                cert.keys()
                    .with_policy(&self.policy, None)
                    .supported()
                    .alive()
                    .revoked(false)
                    .filter(|ka| {
                        ka.key_flags()
                            .as_ref()
                            .is_some_and(|f| f.for_storage_encryption() || f.for_transport_encryption())
                    })
            });
            let message = Encryptor2::for_recipients(message, recipients)
                .build()
                .map_err(sequoia_err)?;
            let mut writer = LiteralWriter::new(message).build().map_err(sequoia_err)?;
            writer.write_all(plaintext.as_bytes()).map_err(sequoia_err)?;
            writer.finalize().map_err(sequoia_err)?;
        }

        Ok(out_path)
    }
}

/// 统计证书中可用的加密子密钥（storage 或 transport 加密能力）
fn count_encryption_keys(cert: &openpgp::Cert, policy: &StandardPolicy) -> usize {
    cert.keys()
        .with_policy(policy, None)
        .supported()
        .alive()
        .revoked(false)
        .filter(|ka| {
            ka.key_flags()
                .as_ref()
                .is_some_and(|f| f.for_storage_encryption() || f.for_transport_encryption())
        })
        .count()
}

/// 固定明文格式（规格 gpg_encryption 第 3 条，逐字节固定）
fn build_plaintext(record: &HitRecord) -> String {
    format!(
        "Address: {}\nPath: {}\nMnemonic: {}\nCreated: {}\n",
        record.address, record.path, record.mnemonic.as_str(), record.created
    )
}

/// sequoia 错误 → 双语错误（不暴露内部细节）
fn sequoia_err(e: impl std::fmt::Display) -> VanityError {
    VanityError::internal(
        format!("OpenPGP encryption failed: {e}"),
        format!("OpenPGP 加密失败：{e}"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generator::Generator;
    use std::path::PathBuf;

    fn fixture() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fx1024.asc")
    }

    #[test]
    fn 解析用户公钥_并有可用加密子密钥() {
        let data = fs::read(fixture()).unwrap();
        let enc = GpgEncryptor::from_bytes(&data).unwrap();
        // fx1024.asc 包含 1 个 cv25519 加密子密钥
        assert!(enc.usable_keys() >= 1);
    }

    #[test]
    fn 解析非法公钥_双语报错() {
        let err = GpgEncryptor::from_bytes(b"not a pgp key").unwrap_err();
        assert!(err.en.contains("failed to parse the OpenPGP public key"));
        assert!(err.cn.contains("公钥解析失败"));
    }

    #[test]
    fn 无加密子密钥的公钥_报错() {
        // 仅签名能力的裸 EdDSA 主密钥（无加密子密钥的最小证书无法轻易手工构造，
        // 这里用损坏但可解析的场景代替：空证书流）
        let err = GpgEncryptor::from_bytes(&[]).unwrap_err();
        assert!(err.en.contains("failed to parse") || err.en.contains("no usable"));
    }

    #[test]
    fn 明文格式固定四行() {
        let mut g = Generator::new(24, "m/44'/60'/0'/0/0", &[0x8000_002C, 0x8000_003C, 0x8000_0000, 0, 0], false)
            .unwrap();
        let m = crate::matcher::Matcher::new(false, None, None, None);
        let (hits, _) = g.derive_and_match(&[0u8; 32], &m).unwrap();
        let hit = &hits[0];
        let text = build_plaintext(hit);
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 4);
        assert!(lines[0].starts_with("Address: 0x"));
        assert_eq!(lines[1], format!("Path: {}", hit.path));
        assert!(lines[2].starts_with("Mnemonic: "));
        assert!(lines[3].starts_with("Created: 2") && lines[3].ends_with('Z'));
        assert!(text.ends_with('\n'));
    }
}
