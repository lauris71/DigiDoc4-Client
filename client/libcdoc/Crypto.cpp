#include "Crypto.h"

#include <openssl/aes.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

#include <cmath>
#include <cstring>

#include "cdoc.h"

#define SCOPE(TYPE, VAR, DATA) std::unique_ptr<TYPE,decltype(&TYPE##_free)> VAR(DATA, TYPE##_free)

namespace libcdoc {

const std::string Crypto::SHA256_MTH = "http://www.w3.org/2001/04/xmlenc#sha256";
const std::string Crypto::SHA384_MTH = "http://www.w3.org/2001/04/xmlenc#sha384";
const std::string Crypto::SHA512_MTH = "http://www.w3.org/2001/04/xmlenc#sha512";
const char *Crypto::KWAES128_MTH = "http://www.w3.org/2001/04/xmlenc#kw-aes128";
const char *Crypto::KWAES192_MTH = "http://www.w3.org/2001/04/xmlenc#kw-aes192";
const char *Crypto::KWAES256_MTH = "http://www.w3.org/2001/04/xmlenc#kw-aes256";
const char *Crypto::AES128CBC_MTH = "http://www.w3.org/2001/04/xmlenc#aes128-cbc";
const char *Crypto::AES192CBC_MTH = "http://www.w3.org/2001/04/xmlenc#aes192-cbc";
const char *Crypto::AES256CBC_MTH = "http://www.w3.org/2001/04/xmlenc#aes256-cbc";
const char *Crypto::AES128GCM_MTH = "http://www.w3.org/2009/xmlenc11#aes128-gcm";
const char *Crypto::AES192GCM_MTH = "http://www.w3.org/2009/xmlenc11#aes192-gcm";
const char *Crypto::AES256GCM_MTH = "http://www.w3.org/2009/xmlenc11#aes256-gcm";
const std::string Crypto::RSA_MTH = "http://www.w3.org/2001/04/xmlenc#rsa-1_5";
const std::string Crypto::CONCATKDF_MTH = "http://www.w3.org/2009/xmlenc11#ConcatKDF";
const std::string Crypto::AGREEMENT_MTH = "http://www.w3.org/2009/xmlenc11#ECDH-ES";

#define isError(e) ((e) < 1)

Crypto::Cipher::Cipher(const EVP_CIPHER *cipher, const std::vector<uint8_t> &key, const std::vector<uint8_t> &iv, bool encrypt)
	: ctx(EVP_CIPHER_CTX_new())
{
	EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
	EVP_CipherInit_ex(ctx, cipher, nullptr, key.data(), iv.empty() ? nullptr : iv.data(), int(encrypt));
}

Crypto::Cipher::~Cipher()
{
	EVP_CIPHER_CTX_free(ctx);
}

bool Crypto::Cipher::updateAAD(const std::vector<uint8_t> &data) const
{
	int len = 0;
	int result = EVP_CipherUpdate(ctx, nullptr, &len, data.data(), int(data.size()));
	return result > 0;
}

bool
Crypto::Cipher::update(uint8_t *data, int size) const
{
	int len = 0;
	int result = EVP_CipherUpdate(ctx, data, &len, data, size);
	return result > 0;
}

bool Crypto::Cipher::result() const
{
	std::vector<uint8_t> result(EVP_CIPHER_CTX_block_size(ctx), 0);
	int len = int(result.size());
	if(EVP_CipherFinal(ctx, result.data(), &len) < 1) return false;
	if(result.size() != len) result.resize(len);
	return true;
}

std::vector<uint8_t>
Crypto::Cipher::tag() const
{
	std::vector<uint8_t> result(tagLen(), 0);
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, int(result.size()), result.data()) > 0)
		return result;
	return {};
}

bool Crypto::Cipher::setTag(const std::vector<uint8_t> &data) const
{
	int result = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, int(data.size()), (void *) data.data());
	return result > 0;
}

int
Crypto::Cipher::blockSize() const
{
	return EVP_CIPHER_CTX_get_block_size(ctx);
}

std::vector<uchar> Crypto::AESWrap(const std::vector<uchar> &key, const std::vector<uchar> &data, bool encrypt)
{
	AES_KEY aes;
	encrypt ?
		AES_set_encrypt_key(key.data(), int(key.size()) * 8, &aes) :
		AES_set_decrypt_key(key.data(), int(key.size()) * 8, &aes);
	std::vector<uchar> result(data.size() + 8);
	int size = encrypt ?
		AES_wrap_key(&aes, nullptr, result.data(), data.data(), data.size()) :
		AES_unwrap_key(&aes, nullptr, result.data(), data.data(), data.size());
	if(size > 0)
		result.resize(size_t(size));
	else
		result.clear();
	return result;
}

const EVP_CIPHER *Crypto::cipher(const std::string &algo)
{
	if(algo == AES128CBC_MTH) return EVP_aes_128_cbc();
	if(algo == AES192CBC_MTH) return EVP_aes_192_cbc();
	if(algo == AES256CBC_MTH) return EVP_aes_256_cbc();
	if(algo == AES128GCM_MTH) return EVP_aes_128_gcm();
	if(algo == AES192GCM_MTH) return EVP_aes_192_gcm();
	if(algo == AES256GCM_MTH) return EVP_aes_256_gcm();
	return nullptr;
}

std::vector<uchar> Crypto::concatKDF(const std::string &hashAlg, uint32_t keyDataLen,
	const std::vector<uchar> &z, const std::vector<uchar> &otherInfo)
{
	std::vector<uchar> key;
	uint32_t hashLen = SHA384_DIGEST_LENGTH;
	if(hashAlg == SHA256_MTH) hashLen = SHA256_DIGEST_LENGTH;
	else if(hashAlg == SHA384_MTH) hashLen = SHA384_DIGEST_LENGTH;
	else if(hashAlg == SHA512_MTH) hashLen = SHA512_DIGEST_LENGTH;
	else return key;

	SHA256_CTX sha256;
	SHA512_CTX sha512;
	std::vector<uchar> hash(hashLen, 0), intToFourBytes(4, 0);
	uint32_t reps = uint32_t(std::ceil(double(keyDataLen) / double(hashLen)));
	for(uint32_t i = 1; i <= reps; i++)
	{
		intToFourBytes[0] = uchar(i >> 24);
		intToFourBytes[1] = uchar(i >> 16);
		intToFourBytes[2] = uchar(i >> 8);
		intToFourBytes[3] = uchar(i >> 0);
		switch(hashLen)
		{
		case SHA256_DIGEST_LENGTH:
			SHA256_Init(&sha256);
			SHA256_Update(&sha256, intToFourBytes.data(), intToFourBytes.size());
			SHA256_Update(&sha256, z.data(), z.size());
			SHA256_Update(&sha256, otherInfo.data(), otherInfo.size());
			SHA256_Final(hash.data(), &sha256);
			break;
		case SHA384_DIGEST_LENGTH:
			SHA384_Init(&sha512);
			SHA384_Update(&sha512, intToFourBytes.data(), intToFourBytes.size());
			SHA384_Update(&sha512, z.data(), z.size());
			SHA384_Update(&sha512, otherInfo.data(), otherInfo.size());
			SHA384_Final(hash.data(), &sha512);
			break;
		case SHA512_DIGEST_LENGTH:
			SHA512_Init(&sha512);
			SHA512_Update(&sha512, intToFourBytes.data(), intToFourBytes.size());
			SHA512_Update(&sha512, otherInfo.data(), otherInfo.size());
			SHA512_Final(hash.data(), &sha512);
			break;
		default: return key;
		}
		key.insert(key.cend(), hash.cbegin(), hash.cend());
	}
	key.resize(size_t(keyDataLen));
	return key;
}

std::vector<uchar> Crypto::concatKDF(const std::string &hashAlg, uint32_t keyDataLen, const std::vector<uchar> &z,
	const std::vector<uchar> &AlgorithmID, const std::vector<uchar> &PartyUInfo, const std::vector<uchar> &PartyVInfo)
{
#ifndef NDEBUG
	printf("Ksr %s\n", Crypto::toHex(z).c_str());
	printf("AlgorithmID %s\n", Crypto::toHex(AlgorithmID).c_str());
	printf("PartyUInfo %s\n", Crypto::toHex(PartyUInfo).c_str());
	printf("PartyVInfo %s\n", Crypto::toHex(PartyVInfo).c_str());
#endif
	std::vector<uchar> otherInfo;
	otherInfo.insert(otherInfo.cend(), AlgorithmID.cbegin(), AlgorithmID.cend());
	otherInfo.insert(otherInfo.cend(), PartyUInfo.cbegin(), PartyUInfo.cend());
	otherInfo.insert(otherInfo.cend(), PartyVInfo.cbegin(), PartyVInfo.cend());
	return concatKDF(hashAlg, keyDataLen, z, otherInfo);
}

std::vector<uchar> Crypto::encrypt(const std::string &method, const Key &key, std::istream &in)
{
	const EVP_CIPHER *c = cipher(method);
	SCOPE(EVP_CIPHER_CTX, ctx, EVP_CIPHER_CTX_new());
	EVP_CipherInit(ctx.get(), c, key.key.data(), key.iv.data(), 1);

	in.seekg(0, std::istream::end);
	std::istream::pos_type pos = in.tellg();
	std::vector<uchar> result((pos < 0 ? 0 : (unsigned long)pos) + size_t(EVP_CIPHER_CTX_block_size(ctx.get())), 0);
	in.clear();
	in.seekg(0);

	std::vector<char> buf(10 * 1024, 0);
	int sizeIn = 0, sizeTotal = 0;
	while (in)
	{
		in.read(buf.data(), std::streamsize(buf.size()));
		if (in.gcount() > 0)
		{
			EVP_CipherUpdate(ctx.get(), &result[sizeTotal], &sizeIn, (const uchar*)buf.data(), int(in.gcount()));
			sizeTotal += sizeIn;
		}
	}
	EVP_CipherFinal(ctx.get(), &result[size_t(sizeTotal)], &sizeIn);
	result.resize(size_t(sizeTotal + sizeIn));
	result.insert(result.cbegin(), key.iv.cbegin(), key.iv.cend());
	if(EVP_CIPHER_mode(c) == EVP_CIPH_GCM_MODE)
	{
		std::vector<uchar> tag(16, 0);
		EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, int(tag.size()), tag.data());
		result.insert(result.cend(), tag.cbegin(), tag.cend());
#ifndef NDEBUG
		printf("GCM TAG %s\n", Crypto::toHex(tag).c_str());
#endif
	}
	return result;
}

std::vector<uint8_t>
Crypto::encrypt(EVP_PKEY *pub, int padding, const std::vector<uint8_t> &data)
{
	SCOPE(EVP_PKEY_CTX, ctx, EVP_PKEY_CTX_new(pub, nullptr));
	size_t size = 0;
	if(isError(EVP_PKEY_encrypt_init(ctx.get())) ||
		isError(EVP_PKEY_CTX_set_rsa_padding(ctx.get(), padding)) ||
		isError(EVP_PKEY_encrypt(ctx.get(), nullptr, &size, data.data(), data.size())))
		return {};
	if(padding == RSA_PKCS1_OAEP_PADDING) {
		if(isError(EVP_PKEY_CTX_set_rsa_oaep_md(ctx.get(), EVP_sha256())) ||
			isError(EVP_PKEY_CTX_set_rsa_mgf1_md(ctx.get(), EVP_sha256())))
			return {};
	}
	std::vector<uint8_t> result(int(size), 0);
	if(isError(EVP_PKEY_encrypt(ctx.get(), result.data(), &size,
			data.data(), data.size())))
		return {};
	return result;
}

std::vector<uchar> Crypto::decrypt(const std::string &method, const std::vector<uchar> &key, const std::vector<uchar> &data)
{
	const EVP_CIPHER *cipher = Crypto::cipher(method);
	size_t dataSize = data.size();
	std::vector<uchar> iv(data.cbegin(), data.cbegin() + EVP_CIPHER_iv_length(cipher));
	dataSize -= iv.size();

#ifndef NDEBUG
	printf("iv %s\n", Crypto::toHex(iv).c_str());
	printf("transport %s\n", Crypto::toHex(key).c_str());
#endif

	SCOPE(EVP_CIPHER_CTX, ctx, EVP_CIPHER_CTX_new());
	int err = EVP_CipherInit(ctx.get(), cipher, key.data(), iv.data(), 0);

	if (EVP_CIPHER_mode(cipher) == EVP_CIPH_GCM_MODE)
	{
		std::vector<uchar> tag(data.cend() - 16, data.cend());
		EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, int(tag.size()), tag.data());
		dataSize -= tag.size();
#ifndef NDEBUG
		printf("GCM TAG %s\n", Crypto::toHex(tag).c_str());
#endif
	}

	int size = 0;
	std::vector<uchar> result(dataSize + size_t(EVP_CIPHER_CTX_block_size(ctx.get())), 0);
	err = EVP_CipherUpdate(ctx.get(), result.data(), &size, &data[iv.size()], int(dataSize));

	int size2 = 0;
	err = EVP_CipherFinal(ctx.get(), result.data() + size, &size2);
	result.resize(size_t(size + size2));
	return result;
}

std::vector<uchar> Crypto::decodeBase64(const uchar *data)
{
	std::vector<uchar> result;
	if (!data)
		return result;
	result.resize(strlen((const char*)data));
	SCOPE(EVP_ENCODE_CTX, ctx, EVP_ENCODE_CTX_new());
	EVP_DecodeInit(ctx.get());
	int size1 = 0, size2 = 0;
	if(EVP_DecodeUpdate(ctx.get(), result.data(), &size1, data, int(result.size())) == -1)
	{
		result.clear();
		return result;
	}
	if(EVP_DecodeFinal(ctx.get(), result.data(), &size2) == 1)
		result.resize(size_t(size1 + size2));
	else
		result.clear();
	return result;
}

std::vector<uchar> Crypto::deriveSharedSecret(EVP_PKEY *pkey, EVP_PKEY *peerPKey)
{
	std::vector<uchar> sharedSecret;
	size_t sharedSecretLen = 0;
	SCOPE(EVP_PKEY_CTX, ctx, EVP_PKEY_CTX_new(pkey, nullptr));
	if(!ctx ||
		EVP_PKEY_derive_init(ctx.get()) <= 0 ||
		EVP_PKEY_derive_set_peer(ctx.get(), peerPKey) <= 0 ||
		EVP_PKEY_derive(ctx.get(), nullptr, &sharedSecretLen) <= 0)
		return sharedSecret;
	sharedSecret.resize(sharedSecretLen);
	if(EVP_PKEY_derive(ctx.get(), sharedSecret.data(), &sharedSecretLen) <= 0)
		sharedSecret.clear();
	return sharedSecret;
}

Crypto::Key Crypto::generateKey(const std::string &method)
{
	const EVP_CIPHER *c = cipher(method);
#ifdef WIN32
	RAND_screen();
#else
	RAND_load_file("/dev/urandom", 1024);
#endif
	Key key = {
		std::vector<uchar>(size_t(EVP_CIPHER_key_length(c)), 0),
		std::vector<uchar>(size_t(EVP_CIPHER_iv_length(c)), 0)
	};
	uchar salt[PKCS5_SALT_LEN], indata[128];
	RAND_bytes(salt, sizeof(salt));
	RAND_bytes(indata, sizeof(indata));
	EVP_BytesToKey(c, EVP_sha256(), salt, indata, sizeof(indata), 1, key.key.data(), key.iv.data());
	return key;
}

uint32_t Crypto::keySize(const std::string &algo)
{
	if(algo == KWAES128_MTH) return 16;
	if(algo == KWAES192_MTH) return 24;
	if(algo == KWAES256_MTH) return 32;
	return 0;
}

std::vector<uint8_t>
Crypto::hkdf(const std::vector<uint8_t> &key, const std::vector<uint8_t> &salt, const std::vector<uint8_t> &info, int len, int mode)
{
	SCOPE(EVP_PKEY_CTX, ctx, EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr));
	std::vector<uint8_t> out(len, 0);
	auto outlen = out.size();
	if(!ctx ||
		isError(EVP_PKEY_derive_init(ctx.get())) ||
		isError(EVP_PKEY_CTX_hkdf_mode(ctx.get(), mode)) ||
		isError(EVP_PKEY_CTX_set_hkdf_md(ctx.get(), EVP_sha256())) ||
		isError(EVP_PKEY_CTX_set1_hkdf_key(ctx.get(), key.data(), int(key.size()))) ||
		isError(EVP_PKEY_CTX_set1_hkdf_salt(ctx.get(), salt.data(), int(salt.size()))) ||
		isError(EVP_PKEY_CTX_add1_hkdf_info(ctx.get(), info.data(), int(info.size()))) ||
		isError(EVP_PKEY_derive(ctx.get(), out.data(), &outlen)))
		return {};
	return out;
}

std::vector<uint8_t>
Crypto::expand(const std::vector<uint8_t> &key, const std::vector<uint8_t> &info, int len)
{
	return hkdf(key, {}, info, len, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY);
}

std::vector<uint8_t>
Crypto::extract(const std::vector<uint8_t> &key, const std::vector<uint8_t> &salt, int len)
{
	return hkdf(key, salt, {}, len, EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY);
}

std::vector<uint8_t>
Crypto::sign_hmac(const std::vector<uint8_t> &key, const std::vector<uint8_t> &data)
{
	EVP_PKEY *pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, nullptr, key.data(), int(key.size()));
	size_t req = 0;
	SCOPE(EVP_MD_CTX, ctx, EVP_MD_CTX_new());
	if(!ctx ||
		isError(EVP_DigestSignInit(ctx.get(), nullptr, EVP_sha256(), nullptr, pkey)) ||
		isError(EVP_DigestSignUpdate(ctx.get(), data.data(), data.size())) ||
		isError(EVP_DigestSignFinal(ctx.get(), nullptr, &req)))
		return {};
	std::vector<uint8_t> sig(int(req), 0);
	if(isError(EVP_DigestSignFinal(ctx.get(), sig.data(), &req)))
		sig.clear();
	return sig;
}

std::vector<uint8_t>
Crypto::pbkdf2_sha256(const std::vector<uint8_t>& pw, const std::vector<uint8_t>& salt, uint32_t iter)
{
	std::vector<uint8_t> key(32, 0);
	PKCS5_PBKDF2_HMAC(reinterpret_cast<const char *>(pw.data()), pw.size(),
					  (const unsigned char *) salt.data(), int(salt.size()),
					  iter, EVP_sha256(), int(key.size()), (unsigned char *)key.data());
	return key;
}

std::unique_ptr<EVP_PKEY, void (*)(EVP_PKEY *)>
Crypto::fromRSAPublicKeyDer(const std::vector<uint8_t> &der)
{
	const uint8_t *p = der.data();
	EVP_PKEY *key = d2i_PublicKey(EVP_PKEY_RSA, nullptr, &p, long(der.size()));
	return std::unique_ptr<EVP_PKEY, void (*)(EVP_PKEY *)>(key, EVP_PKEY_free);
}

std::unique_ptr<EVP_PKEY, void (*)(EVP_PKEY *)>
Crypto::fromECPublicKeyDer(const std::vector<uint8_t> &der, int curveName)
{
	EVP_PKEY *params = nullptr;
	if(SCOPE(EVP_PKEY_CTX, ctx, EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr));
		!ctx ||
		isError(EVP_PKEY_paramgen_init(ctx.get())) ||
		isError(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx.get(), curveName)) ||
		isError(EVP_PKEY_CTX_set_ec_param_enc(ctx.get(), OPENSSL_EC_NAMED_CURVE)) ||
		isError(EVP_PKEY_paramgen(ctx.get(), &params)))
		return std::unique_ptr<EVP_PKEY, void (*)(EVP_PKEY *)>(nullptr, EVP_PKEY_free);
	const uint8_t *p = der.data();
	EVP_PKEY *key = d2i_PublicKey(EVP_PKEY_EC, &params, &p, long(der.size()));
	return std::unique_ptr<EVP_PKEY, void (*)(EVP_PKEY *)>(key, EVP_PKEY_free);
}

std::unique_ptr<EVP_PKEY, void (*)(EVP_PKEY *)>
Crypto::genECKey(EVP_PKEY *params)
{
	EVP_PKEY *key = nullptr;
	SCOPE(EVP_PKEY_CTX, ctx, EVP_PKEY_CTX_new(params, nullptr));
	SCOPE(EVP_PKEY, result, nullptr);
	if(ctx &&
		!isError(EVP_PKEY_keygen_init(ctx.get())) &&
		!isError(EVP_PKEY_keygen(ctx.get(), &key)))
		result.reset(key);
	return result;
}

std::vector<uint8_t>
Crypto::toPublicKeyDer(EVP_PKEY *key)
{
	if(!key) return {};
	std::vector<uint8_t> der(i2d_PublicKey(key, nullptr), 0);
	auto *p = der.data();
	if(i2d_PublicKey(key, &p) != der.size()) der.clear();
	return der;
}

std::vector<uint8_t>
Crypto::random(uint32_t len)
{
	std::vector<uint8_t> out(len, 0);
	if(isError(RAND_bytes(out.data(), len)))
		out.clear();
	return out;
}

int
Crypto::xor_data(std::vector<uint8_t>& dst, const std::vector<uint8_t> &lhs, const std::vector<uint8_t> &rhs)
{
	if(lhs.size() != rhs.size()) return CRYPTO_ERROR;
	dst.resize(lhs.size());
	for(size_t i = 0; i < lhs.size(); ++i) dst[i] = lhs[i] ^ rhs[i];
	return OK;
}

std::string Crypto::toBase64(const uchar *data, size_t len)
{
	std::string result(((len + 2) / 3) * 4, 0);
	int size = EVP_EncodeBlock((uchar*)&result[0], data, int(len));
	result.resize(size_t(size));
	return result;
}

X509* Crypto::toX509(const std::vector<uchar> &data)
{
	const uchar *p = data.data();
	return d2i_X509(nullptr, &p, int(data.size()));
}

}; // namespace libcdoc
