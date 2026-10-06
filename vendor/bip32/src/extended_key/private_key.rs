//! Extended private keys

use crate::{
    ChildNumber, Depth, Error, ExtendedKey, ExtendedKeyAttrs, ExtendedPublicKey, HmacSha512,
    KeyFingerprint, Prefix, PrivateKey, PrivateKeyBytes, PublicKey, Result, KEY_SIZE,
};
use core::{
    fmt::{self, Debug},
    str::FromStr,
};
use hmac::Mac;
use subtle::{Choice, ConstantTimeEq};
use zeroize::Zeroize;

#[cfg(feature = "alloc")]
use {
    crate::DerivationPath,
    alloc::string::{String, ToString},
    alloc::vec::Vec,
    zeroize::Zeroizing,
};

/// Derivation domain separator for BIP39 keys.
const BIP39_DOMAIN_SEPARATOR: [u8; 12] = [
    0x42, 0x69, 0x74, 0x63, 0x6f, 0x69, 0x6e, 0x20, 0x73, 0x65, 0x65, 0x64,
];

/// Extended private secp256k1 ECDSA signing key.
#[cfg(feature = "secp256k1")]
pub type XPrv = ExtendedPrivateKey<k256::ecdsa::SigningKey>;

/// Extended private keys derived using BIP32.
///
/// Generic around a [`PrivateKey`] type. When the `secp256k1` feature of this
/// crate is enabled, the [`XPrv`] type provides a convenient alias for
/// extended ECDSA/secp256k1 private keys.
#[derive(Clone)]
pub struct ExtendedPrivateKey<K: PrivateKey> {
    /// Derived private key
    private_key: K,

    /// Extended key attributes.
    attrs: ExtendedKeyAttrs,
}

impl<K> ExtendedPrivateKey<K>
where
    K: PrivateKey,
{
    /// Maximum derivation depth.
    pub const MAX_DEPTH: Depth = u8::MAX;

    /// Derive a child key from the given [`DerivationPath`].
    #[cfg(feature = "alloc")]
    pub fn derive_from_path<S>(seed: S, path: &DerivationPath) -> Result<Self>
    where
        S: AsRef<[u8]>,
    {
        path.iter().fold(Self::new(seed), |maybe_key, child_num| {
            maybe_key.and_then(|key| key.derive_child(child_num))
        })
    }

    /// Create the root extended key for the given seed value.
    pub fn new<S>(seed: S) -> Result<Self>
    where
        S: AsRef<[u8]>,
    {
        if ![16, 32, 64].contains(&seed.as_ref().len()) {
            return Err(Error::SeedLength);
        }

        let mut hmac = HmacSha512::new_from_slice(&BIP39_DOMAIN_SEPARATOR)?;
        hmac.update(seed.as_ref());

        let result = hmac.finalize().into_bytes();
        let (secret_key, chain_code) = result.split_at(KEY_SIZE);
        let private_key = PrivateKey::from_bytes(secret_key.try_into()?)?;
        let attrs = ExtendedKeyAttrs {
            depth: 0,
            parent_fingerprint: KeyFingerprint::default(),
            child_number: ChildNumber::default(),
            chain_code: chain_code.try_into()?,
        };

        Ok(ExtendedPrivateKey { private_key, attrs })
    }

    /// Derive a child key for a particular [`ChildNumber`].
    pub fn derive_child(&self, child_number: ChildNumber) -> Result<Self> {
        let depth = self.attrs.depth.checked_add(1).ok_or(Error::Depth)?;
        let (tweak, chain_code) = self
            .private_key
            .derive_tweak(&self.attrs.chain_code, child_number)?;

        // We should technically loop here if the tweak is zero or overflows
        // the order of the underlying elliptic curve group, incrementing the
        // index, however per "Child key derivation (CKD) functions":
        // https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#child-key-derivation-ckd-functions
        //
        // > "Note: this has probability lower than 1 in 2^127."
        //
        // ...so instead, we simply return an error if this were ever to happen,
        // as the chances of it happening are vanishingly small.
        let private_key = self.private_key.derive_child(tweak)?;

        let attrs = ExtendedKeyAttrs {
            parent_fingerprint: self.private_key.public_key().fingerprint(),
            child_number,
            chain_code,
            depth,
        };

        Ok(ExtendedPrivateKey { private_key, attrs })
    }

    /// 批量派生子密钥：语义与对每个 child 单独调用 [`derive_child`] 完全一致
    /// （BIP32 CKD 逐步派生，bit-exact），但摊销了同一父密钥下的重复计算——
    ///
    /// - 父公钥（非 hardened 消息输入 + parent_fingerprint 来源）只计算一次；
    /// - HMAC-SHA512 的 ipad/opad 中间状态（key = 父链码）只构建一次，
    ///   每个 child 从克隆状态继续（消息仍含独立 index）；
    /// - parent_fingerprint / depth 对整批不变。
    ///
    /// 供同一助记词批量派生连续地址（BIP44 多账户）的热路径使用；
    /// 安全性不变：每 child 的 HMAC 消息与逐个派生逐字节相同，
    /// 椭圆曲线运算全部复用原语实现，无任何自实现密码学。
    #[cfg(feature = "alloc")]
    pub fn derive_children(&self, children: &[ChildNumber]) -> Result<Vec<Self>> {
        let depth = self.attrs.depth.checked_add(1).ok_or(Error::Depth)?;
        // 父公钥整批一次（derive_tweak 的非 hardened 输入与 fingerprint 共用）
        let parent_public = self.private_key.public_key();
        let parent_fingerprint = parent_public.fingerprint();
        // HMAC 引擎整批一次（key = 父链码）；hmac::Mac 的 finalize 消费 self，
        // 故每个 child 克隆状态（两个 SHA-512 状态，成本可忽略）
        let base_hmac = HmacSha512::new_from_slice(&self.attrs.chain_code)
            .map_err(|_| Error::Crypto)?;

        let mut derived = Vec::with_capacity(children.len());
        for &child_number in children {
            let mut hmac = base_hmac.clone();
            if child_number.is_hardened() {
                hmac.update(&[0]);
                hmac.update(&self.private_key.to_bytes());
            } else {
                hmac.update(&parent_public.to_bytes());
            }
            hmac.update(&child_number.to_bytes());

            let result = hmac.finalize().into_bytes();
            let (tweak_bytes, chain_code_bytes) = result.split_at(KEY_SIZE);
            let tweak = PrivateKeyBytes::try_from(tweak_bytes)?;
            let chain_code = chain_code_bytes.try_into()?;

            let private_key = self.private_key.derive_child(tweak)?;
            derived.push(ExtendedPrivateKey {
                private_key,
                attrs: ExtendedKeyAttrs {
                    parent_fingerprint,
                    child_number,
                    chain_code,
                    depth,
                },
            });
        }
        Ok(derived)
    }

    /// Borrow the derived private key value.
    pub fn private_key(&self) -> &K {
        &self.private_key
    }

    /// Serialize the derived public key as bytes.
    pub fn public_key(&self) -> ExtendedPublicKey<K::PublicKey> {
        self.into()
    }

    /// Get attributes for this key such as depth, parent fingerprint,
    /// child number, and chain code.
    pub fn attrs(&self) -> &ExtendedKeyAttrs {
        &self.attrs
    }

    /// Serialize the raw private key as a byte array.
    pub fn to_bytes(&self) -> PrivateKeyBytes {
        self.private_key.to_bytes()
    }

    /// Serialize this key as an [`ExtendedKey`].
    pub fn to_extended_key(&self, prefix: Prefix) -> ExtendedKey {
        // Add leading `0` byte
        let mut key_bytes = [0u8; KEY_SIZE + 1];
        key_bytes[1..].copy_from_slice(&self.to_bytes());

        ExtendedKey {
            prefix,
            attrs: self.attrs.clone(),
            key_bytes,
        }
    }

    /// Serialize this key as a self-[`Zeroizing`] `String`.
    #[cfg(feature = "alloc")]
    pub fn to_string(&self, prefix: Prefix) -> Zeroizing<String> {
        Zeroizing::new(self.to_extended_key(prefix).to_string())
    }
}

impl<K> ConstantTimeEq for ExtendedPrivateKey<K>
where
    K: PrivateKey,
{
    fn ct_eq(&self, other: &Self) -> Choice {
        let mut key_a = self.to_bytes();
        let mut key_b = self.to_bytes();

        let result = key_a.ct_eq(&key_b)
            & self.attrs.depth.ct_eq(&other.attrs.depth)
            & self
                .attrs
                .parent_fingerprint
                .ct_eq(&other.attrs.parent_fingerprint)
            & self.attrs.child_number.0.ct_eq(&other.attrs.child_number.0)
            & self.attrs.chain_code.ct_eq(&other.attrs.chain_code);

        key_a.zeroize();
        key_b.zeroize();

        result
    }
}

impl<K> Debug for ExtendedPrivateKey<K>
where
    K: PrivateKey,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // TODO(tarcieri): use `finish_non_exhaustive` when stable
        f.debug_struct("ExtendedPrivateKey")
            .field("private_key", &"...")
            .field("attrs", &self.attrs)
            .finish()
    }
}

/// NOTE: uses [`ConstantTimeEq`] internally
impl<K> Eq for ExtendedPrivateKey<K> where K: PrivateKey {}

/// NOTE: uses [`ConstantTimeEq`] internally
impl<K> PartialEq for ExtendedPrivateKey<K>
where
    K: PrivateKey,
{
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl<K> FromStr for ExtendedPrivateKey<K>
where
    K: PrivateKey,
{
    type Err = Error;

    fn from_str(xprv: &str) -> Result<Self> {
        ExtendedKey::from_str(xprv)?.try_into()
    }
}

impl<K> TryFrom<ExtendedKey> for ExtendedPrivateKey<K>
where
    K: PrivateKey,
{
    type Error = Error;

    fn try_from(extended_key: ExtendedKey) -> Result<ExtendedPrivateKey<K>> {
        if extended_key.prefix.is_private() && extended_key.key_bytes[0] == 0 {
            Ok(ExtendedPrivateKey {
                private_key: PrivateKey::from_bytes(extended_key.key_bytes[1..].try_into()?)?,
                attrs: extended_key.attrs.clone(),
            })
        } else {
            Err(Error::Crypto)
        }
    }
}
