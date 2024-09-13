#pragma once

#include <cstdint>
#include <iomanip>
#include <memory>
#include <string>
#include <sstream>
#include <vector>

typedef unsigned char uchar;
typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX;
typedef struct evp_cipher_st EVP_CIPHER;
typedef struct evp_pkey_st EVP_PKEY;
typedef struct x509_st X509;

namespace libcdoc {

class Crypto
{
public:
	struct Cipher {
		struct evp_cipher_ctx_st *ctx;
		Cipher(const EVP_CIPHER *cipher, const std::vector<uint8_t> &key, const std::vector<uint8_t> &iv, bool encrypt = true);
		~Cipher();
		bool updateAAD(const std::vector<uint8_t> &data) const;
		bool update(uint8_t *data, int size) const;
		bool result() const;
		static constexpr int tagLen() { return 16; }
		std::vector<uint8_t> tag() const;
		bool setTag(const std::vector<uint8_t> &data) const;
		int blockSize() const;
	};

	static const std::string SHA256_MTH, SHA384_MTH, SHA512_MTH;
	static const char *KWAES128_MTH, *KWAES192_MTH, *KWAES256_MTH;
	static const char *AES128CBC_MTH, *AES192CBC_MTH, *AES256CBC_MTH, *AES128GCM_MTH, *AES192GCM_MTH, *AES256GCM_MTH;
	static const std::string RSA_MTH, CONCATKDF_MTH, AGREEMENT_MTH;

	struct Key { std::vector<uchar> key, iv; };

	static std::vector<uchar> AESWrap(const std::vector<uchar> &key, const std::vector<uchar> &data, bool encrypt);
	static const EVP_CIPHER *cipher(const std::string &algo);
	static std::vector<uchar> concatKDF(const std::string &hashAlg, uint32_t keyDataLen, const std::vector<uchar> &z, const std::vector<uchar> &otherInfo);
	static std::vector<uchar> concatKDF(const std::string &hashAlg, uint32_t keyDataLen, const std::vector<uchar> &z,
		const std::vector<uchar> &AlgorithmID, const std::vector<uchar> &PartyUInfo, const std::vector<uchar> &PartyVInfo);
	static std::vector<uchar> encrypt(const std::string &method, const Key &key, std::istream &in);
	static std::vector<uchar> decrypt(const std::string &method, const std::vector<uchar> &key, const std::vector<uchar> &data);
	static std::vector<uchar> encrypt(EVP_PKEY *pub, int padding, const std::vector<uchar> &data);
	static std::vector<uchar> decodeBase64(const uchar *data);
	static std::vector<uchar> deriveSharedSecret(EVP_PKEY *pkey, EVP_PKEY *peerPKey);
	static Key generateKey(const std::string &method);
	static uint32_t keySize(const std::string &algo);

	static std::vector<uint8_t> hkdf(const std::vector<uint8_t> &key, const std::vector<uint8_t> &salt, const std::vector<uint8_t> &info, int len = 32, int mode = 0);
	static std::vector<uint8_t> expand(const std::vector<uint8_t> &key, const std::vector<uint8_t> &info, int len = 32);
	static std::vector<uint8_t> extract(const std::vector<uint8_t> &key, const std::vector<uint8_t> &salt, int len = 32);
	static std::vector<uint8_t> sign_hmac(const std::vector<uint8_t> &key, const std::vector<uint8_t> &data);

	static std::vector<uint8_t> pbkdf2_sha256(const std::vector<uint8_t>& pw, const std::vector<uint8_t>& salt, uint32_t iter);

	static std::unique_ptr<EVP_PKEY, void (*)(EVP_PKEY *)> fromRSAPublicKeyDer(const std::vector<uint8_t> &der);
	static std::unique_ptr<EVP_PKEY, void (*)(EVP_PKEY *)> fromECPublicKeyDer(const std::vector<uint8_t> &der, int curveName);
	static std::unique_ptr<EVP_PKEY, void (*)(EVP_PKEY *)> genECKey(EVP_PKEY *params);
	static std::vector<uint8_t> toPublicKeyDer(EVP_PKEY *key);

	static std::vector<uint8_t> random(uint32_t len = 32);
	static std::vector<uint8_t> xor_data(const std::vector<uint8_t> &a, const std::vector<uint8_t> &b);
	static std::string toBase64(const uchar *data, size_t len);

	template <typename F>
	static std::string toHex(const F &data)
	{
		std::stringstream os;
		os << std::hex << std::uppercase << std::setfill('0');
		for(const auto &i: data)
			os << std::setw(2) << (static_cast<int>(i) & 0xFF);
		return os.str();
	}
	static X509* toX509(const std::vector<uchar> &data);
};

}; // namespace libcdoc
