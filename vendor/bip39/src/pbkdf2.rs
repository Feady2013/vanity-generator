use bitcoin_hashes::{hmac, sha512, Hash, HashEngine};

const SALT_PREFIX: &'static str = "mnemonic";

/// Calculate the binary size of the mnemonic.
fn mnemonic_byte_len<M>(mnemonic: M) -> usize
	where M: Iterator<Item = &'static str> + Clone,
{
	let mut len = 0;
	for (i, word) in mnemonic.enumerate() {
		if i > 0 {
			len += 1;
		}
		len += word.len();
	}
	len
}

/// Wrote the mnemonic in binary form into the hash engine.
fn mnemonic_write_into<M>(mnemonic: M, engine: &mut sha512::HashEngine)
	where M: Iterator<Item = &'static str> + Clone,
{
	for (i, word) in mnemonic.enumerate() {
		if i > 0 {
			engine.input(" ".as_bytes());
		}
		engine.input(word.as_bytes());
	}
}

/// Create the pristine sha512 engines for HMAC keying (inner/outer).
/// This is the original `create_hmac_engine` keying logic (borrowed from
/// bitcoin_hashes::hmac::HmacEngine::new), returning the two engines
/// AFTER they have absorbed the ipad/opad blocks — i.e. their midstates
/// are the keyed inner/outer SHA-512 states `si` / `so`.
fn create_keyed_engines<M>(mnemonic: M) -> (sha512::HashEngine, sha512::HashEngine)
	where M: Iterator<Item = &'static str> + Clone,
{
	let mut ipad = [0x36u8; 128];
	let mut opad = [0x5cu8; 128];
	let mut iengine = sha512::Hash::engine();
	let mut oengine = sha512::Hash::engine();

	if mnemonic_byte_len(mnemonic.clone()) > sha512::HashEngine::BLOCK_SIZE {
		let hash = {
			let mut engine = sha512::Hash::engine();
			mnemonic_write_into(mnemonic, &mut engine);
			sha512::Hash::from_engine(engine)
		};

		for (b_i, b_h) in ipad.iter_mut().zip(&hash[..]) {
			*b_i ^= *b_h;
		}
		for (b_o, b_h) in opad.iter_mut().zip(&hash[..]) {
			*b_o ^= *b_h;
		}
	} else {
		// First modify the first elements from the prefix.
		let mut cursor = 0;
		for (i, word) in mnemonic.enumerate() {
			if i > 0 {
				ipad[cursor] ^= ' ' as u8;
				opad[cursor] ^= ' ' as u8;
				cursor += 1;
			}
			for (b_i, b_h) in ipad.iter_mut().skip(cursor).zip(word.as_bytes()) {
				*b_i ^= *b_h;
			}
			for (b_o, b_h) in opad.iter_mut().skip(cursor).zip(word.as_bytes()) {
				*b_o ^= *b_h;
			}
			cursor += word.len();
			assert!(cursor <= sha512::HashEngine::BLOCK_SIZE, "mnemonic_byte_len is broken");
		}
	};

	iengine.input(&ipad[..sha512::HashEngine::BLOCK_SIZE]);
	oengine.input(&opad[..sha512::HashEngine::BLOCK_SIZE]);
	(iengine, oengine)
}

/// midstate [u8; 64] → 状态字 [u64; 8]（大端）
fn midstate_to_u64(mid: [u8; 64]) -> [u64; 8] {
	let mut st = [0u64; 8];
	for (s, c) in st.iter_mut().zip(mid.chunks(8)) {
		*s = u64::from_be_bytes(c.try_into().unwrap());
	}
	st
}

/// 8 个状态字 → 64 字节大端（写入目标切片）
#[inline]
fn u64_array_to_bytes(st: &[u64; 8], out: &mut [u8]) {
	for (c, v) in out.chunks_mut(8).zip(st.iter()) {
		c.copy_from_slice(&v.to_be_bytes());
	}
}

// Method borrowed from rust-bitcoin's endian module.
#[inline]
fn u32_to_array_be(val: u32) -> [u8; 4] {
	let mut res = [0; 4];
	for i in 0..4 {
		res[i] = ((val >> (4 - i - 1) * 8) & 0xff) as u8;
	}
	res
}

#[inline]
fn xor(res: &mut [u8], salt: &[u8]) {
	debug_assert!(salt.len() >= res.len(), "length mismatch in xor");

	res.iter_mut().zip(salt.iter()).for_each(|(a, b)| *a ^= b);
}

/// PBKDF2-HMAC-SHA512 implementation using bitcoin_hashes.
///
/// 性能补丁（保留原算法语义，差分测试锚定）：
/// - U1 与密钥化沿用原引擎路径（每种子一次，任意长度正确）；
/// - U2..Uc 链式迭代改为直驱 [`sha512::compress_block`]：消息恒为
///   64 字节，内外层终块布局（0x80 填充 + 16 字节位长）在循环外
///   预置一次（LICM），消除每轮的引擎克隆/缓冲分支/midstate 转换。
pub(crate) fn pbkdf2<M>(mnemonic: M, unprefixed_salt: &[u8], c: usize, res: &mut [u8])
	where M: Iterator<Item = &'static str> + Clone,
{
	let (iengine, oengine) = create_keyed_engines(mnemonic);
	// 密钥化状态（每种子一次）：内层 ipad 态 / 外层 opad 态
	let si = midstate_to_u64(iengine.midstate());
	let so = midstate_to_u64(oengine.midstate());
	// 原引擎仅用于 U1（任意 salt 长度正确）
	let prf = hmac::HmacEngine::from_inner_engines(iengine, oengine);

	for (i, chunk) in res.chunks_mut(sha512::Hash::LEN).enumerate() {
		for v in chunk.iter_mut() {
			*v = 0;
		}

		let mut salt_u = {
			let mut prfc = prf.clone();
			prfc.input(SALT_PREFIX.as_bytes());
			prfc.input(unprefixed_salt);
			prfc.input(&u32_to_array_be((i + 1) as u32));

			let s = hmac::Hmac::from_engine(prfc).into_inner();
			xor(chunk, &s);
			s
		};

		// 常量尾块：消息恒 64 字节 → 内外层消息总长 = 128 + 64 = 192
		// 字节（1536 bit）。终块布局 [64..128] = 0x80, 0…0, BE128(1536)
		let mut tail = [0u8; 64];
		tail[0] = 0x80;
		tail[62] = 0x06; // 1536 = 0x0600 → BE128 尾字节
		tail[63] = 0x00;

		// U2..Uc：直驱压缩函数的热循环（消息恒 64 字节）
		// 尾块常量部分预置一次，循环内只更新前 64 字节（LICM）
		let mut block = [0u8; 128];
		block[64..].copy_from_slice(&tail);
		for _ in 1..c {
			// 内层终块：U(64) || 常量尾
			block[..64].copy_from_slice(&salt_u);
			let mut st = si;
			sha512::compress_block(&mut st, &block);

			// 外层终块：BE(内层摘要)(64) || 常量尾
			u64_array_to_bytes(&st, &mut block[..64]);
			let mut st2 = so;
			sha512::compress_block(&mut st2, &block);

			// 新 U = BE(外层摘要)
			u64_array_to_bytes(&st2, &mut salt_u);
			xor(chunk, &salt_u);
		}
	}
}
