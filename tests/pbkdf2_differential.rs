//! 库差分测试：vendored bip39 的 pbkdf2（直驱压缩热路径补丁）必须与
//! RustCrypto 参考实现（hmac + sha2，独立实现）在任意助记词/口令下
//! 逐位一致。这是"修改库代码做性能优化"的正确性锚。

use bip39::{Language, Mnemonic};
use hmac::{Hmac, Mac};
use sha2::Sha512;

type HmacSha512 = Hmac<Sha512>;

/// 参考 HMAC-SHA512（RustCrypto）
fn hmac_sha512(key: &[u8], msg: &[u8]) -> [u8; 64] {
    let mut mac = HmacSha512::new_from_slice(key).unwrap();
    mac.update(msg);
    mac.finalize().into_bytes().into()
}

/// 参考 BIP39 种子派生（按规范公式逐步实现，与被测库完全独立）
fn reference_seed(mnemonic: &str, passphrase: &str) -> [u8; 64] {
    const ROUNDS: usize = 2048;
    let salt = format!("mnemonic{passphrase}");
    let mut first_msg = salt.clone().into_bytes();
    first_msg.extend_from_slice(&1u32.to_be_bytes());
    let mut u = hmac_sha512(mnemonic.as_bytes(), &first_msg);
    let mut out = u;
    for _ in 1..ROUNDS {
        u = hmac_sha512(mnemonic.as_bytes(), &u);
        for (o, x) in out.iter_mut().zip(u.iter()) {
            *o ^= x;
        }
    }
    out
}

/// 差分：12/18/24 词 × 空/非空口令（覆盖密钥 >128 字节先哈希的分支）
#[test]
fn 种子派生_与_rustcrypto_参考逐位一致() {
    let cases: Vec<(&[u8], &str)> = vec![
        // 12 词（全零熵 → 官方向量 abandon..about）
        (&[0u8; 16][..], ""),
        // 12 词 + 口令
        (&[0x11u8; 16], "TREZOR"),
        // 18 词
        (&[7u8; 24], ""),
        // 24 词（短语 > 128 字节 → 触发密钥先哈希分支）
        (&[9u8; 32], "long-passphrase-测试"),
    ];
    for (entropy, pass) in cases {
        let m = Mnemonic::from_entropy(entropy).expect("熵构造的合法助记词");
        let phrase = m.to_string();
        let seed = m.to_seed(pass);
        let expect = reference_seed(&phrase, pass);
        assert_eq!(
            seed, expect,
            "熵前 4 字节 {:02x?} + 口令 {:?} 的种子与参考实现不一致",
            &entropy[..4],
            pass
        );
    }
}

/// BIP39 官方黄金向量锚定（TREZOR 12 词）
#[test]
fn 黄金种子向量_锚定() {
    let m = Mnemonic::parse_in_normalized(
        Language::English,
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    )
    .unwrap();
    let seed = m.to_seed("TREZOR");
    let hex_seed = hex::encode(seed);
    assert!(
        hex_seed.starts_with("c55257c360c07c72029aebc1b53c05ed"),
        "BIP39 官方向量锚定失败：{hex_seed}"
    );
}
