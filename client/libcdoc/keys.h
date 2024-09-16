#ifndef KEYS_H
#define KEYS_H

#include <memory>
#include <string>
#include <vector>

namespace libcdoc {

#if 0
struct EncKey {
	enum Type {
		SYMMETRIC_KEY,
		PUBLIC_KEY,
		CERTIFICATE,
	};

	enum PKType {
		ECC,
		RSA
	};

	Type type;
	std::string label;

	bool isSymmetric() const { return type == Type::SYMMETRIC_KEY; }
	bool isPKI() const { return (type == Type::CERTIFICATE) || (type == Type::PUBLIC_KEY); }
	bool isCertificate() const { return (type == Type::CERTIFICATE); }

	bool isTheSameRecipient(const EncKey &other) const;
	bool isTheSameRecipient(const std::vector<uint8_t>& public_key) const;

protected:
	EncKey(Type _type) : type(_type) {};
private:
	bool operator==(const EncKey &other) const { return false; }
};

// Symmetric key (plain or PBKDF)

struct EncKeySymmetric : public EncKey {
	std::vector<uint8_t> salt;
	// PBKDF
	std::vector<uint8_t> pw_salt;
	// 0 symmetric key, >0 password
	int32_t kdf_iter;

	EncKeySymmetric(const std::vector<uint8_t>& _salt) : EncKey(Type::SYMMETRIC_KEY), salt(_salt), kdf_iter(0) {}
	EncKeySymmetric(const std::vector<uint8_t>& _salt, const std::vector<uint8_t>& _pw_salt, int32_t _kdf_iter) : EncKey(Type::SYMMETRIC_KEY), salt(_salt), pw_salt(_pw_salt), kdf_iter(_kdf_iter) {}

	// Get salt bitstring for HKDF expand method
	std::string getSaltForExpand() const;
};

// Base PKI key

struct EncKeyPKI : public EncKey {
	// Recipient's public key
	PKType pk_type;
	std::vector<uint8_t> rcpt_key;

protected:
	EncKeyPKI(Type _type) : EncKey(_type), pk_type(PKType::ECC) {};
	EncKeyPKI(Type _type, PKType _pk_type, const std::vector<uint8_t>& _rcpt_key) : EncKey(_type), pk_type(_pk_type), rcpt_key(_rcpt_key) {};
	EncKeyPKI(Type _type, PKType _pk_type, const uint8_t *key_data, size_t key_len) : EncKey(_type), pk_type(_pk_type), rcpt_key(key_data, key_data + key_len) {};
};

// Public key with additonal information

struct EncKeyCert : public EncKeyPKI {
	std::vector<uint8_t> cert;

	EncKeyCert(const std::string& label, const std::vector<uint8_t> &cert);

	void setCert(const std::vector<uint8_t> &_cert);

protected:
	EncKeyCert() : EncKeyPKI(EncKey::Type::CERTIFICATE) {};
};
#endif

struct CKey
{
public:
	enum Type {
		SYMMETRIC_KEY,
		PUBLIC_KEY,
		CERTIFICATE,
		CDOC1,
		SERVER
	};

	enum PKType {
		ECC,
		RSA
	};

	enum DecryptionStatus {
		CANNOT_DECRYPT,
		CAN_DECRYPT,
		NEED_KEY
	};

	Type type;
	std::string label;

	// Decryption data
	std::vector<uint8_t> encrypted_fmk;

	// Recipients public key
	// QByteArray key;

	bool isSymmetric() const { return type == Type::SYMMETRIC_KEY; }
	bool isPKI() const { return (type == Type::CERTIFICATE) || (type == Type::CDOC1) || (type == Type::PUBLIC_KEY) || (type == Type::SERVER); }
	bool isCertificate() const { return (type == Type::CERTIFICATE) || (type == Type::CDOC1); }
	bool isCDoc1() const { return type == Type::CDOC1; }

	bool isTheSameRecipient(const CKey &key) const;
	bool isTheSameRecipient(const std::vector<uint8_t>& public_key) const;

protected:
	CKey(Type _type) : type(_type) {};
private:
	bool operator==(const CKey &other) const { return false; }
};

// Symmetric key (plain or PBKDF)
// Usage:
// CDoc2:encrypt/decrypt LT

struct CKeySymmetric : public CKey {
	std::vector<uint8_t> salt;
	// PBKDF
	std::vector<uint8_t> pw_salt;
	// 0 symmetric key, >0 password
	int32_t kdf_iter;

	CKeySymmetric(const std::vector<uint8_t>& _salt) : CKey(Type::SYMMETRIC_KEY), salt(_salt), kdf_iter(0) {}
	CKeySymmetric(const std::vector<uint8_t>& _salt, const std::vector<uint8_t>& _pw_salt, int32_t _kdf_iter) : CKey(Type::SYMMETRIC_KEY), salt(_salt), pw_salt(_pw_salt), kdf_iter(_kdf_iter) {}

	// Get salt bitstring for HKDF expand method
	std::string getSaltForExpand() const;
};

// Base PKI key
// Usage:
// CDoc2:encrypt

struct CKeyPKI : public CKey {
	// Recipient's public key
	PKType pk_type;
	std::vector<uint8_t> rcpt_key;

	// Get salt bitstring for HKDF expand method
	std::string getSaltForExpand(const std::vector<uint8_t>& key_material) const;
protected:
	CKeyPKI(Type _type) : CKey(_type), pk_type(PKType::ECC) {};
	CKeyPKI(Type _type, PKType _pk_type, const std::vector<uint8_t>& _rcpt_key) : CKey(_type), pk_type(_pk_type), rcpt_key(_rcpt_key) {};
	CKeyPKI(Type _type, PKType _pk_type, const uint8_t *key_data, size_t key_len) : CKey(_type), pk_type(_pk_type), rcpt_key(key_data, key_data + key_len) {};
};

// Public key with additonal information
// Usage:
// CDoc1:encrypt

struct CKeyCert : public CKeyPKI {
	std::vector<uint8_t> cert;

	CKeyCert(const std::string& label, const std::vector<uint8_t> &cert) : CKeyCert(CKey::Type::CERTIFICATE, label, cert) {};

	void setCert(const std::vector<uint8_t> &_cert);

protected:
	CKeyCert(Type _type) : CKeyPKI(_type) {};
	CKeyCert(Type _type, const std::string& label, const std::vector<uint8_t> &_cert);
};

// CDoc2 PKI key with key material
// Usage:
// CDoc2: decrypt

struct CKeyPublicKey : public libcdoc::CKeyPKI {
	// Either ECC public key or RSA encrypted kek
	std::vector<uint8_t> key_material;

	CKeyPublicKey(PKType _pk_type, const std::vector<uint8_t>& _rcpt_key) : CKeyPKI(Type::PUBLIC_KEY, _pk_type, _rcpt_key) {};
	CKeyPublicKey(PKType _pk_type, const uint8_t *_key_data, size_t _key_len) : CKeyPKI(Type::PUBLIC_KEY, _pk_type, _key_data, _key_len) {};
};

// CDoc2 PKI key with server info
// Usage:
// CDoc2: decrypt

struct CKeyServer : public libcdoc::CKeyPKI {
	// Server info
	std::string keyserver_id, transaction_id;

	static std::shared_ptr<CKeyServer> fromKey(const std::vector<uint8_t> _key, PKType _pk_type);
protected:
	CKeyServer(const std::vector<uint8_t>& _rcpt_key, PKType _pk_type) : CKeyPKI(Type::SERVER, _pk_type, _rcpt_key) {};
	CKeyServer(const uint8_t *_key_data, size_t _key_size, PKType _pk_type) : CKeyPKI(Type::SERVER, _pk_type, _key_data, _key_size) {};
};

// CDoc1 decryption key (with additional information from file)
// Usage:
// CDoc1:decrypt

struct CKeyCDoc1 : public libcdoc::CKeyCert {

	std::vector<uint8_t> publicKey;
	std::string concatDigest, method;
	std::vector<uint8_t> AlgorithmID, PartyUInfo, PartyVInfo;

	CKeyCDoc1() : CKeyCert(Type::CDOC1) {};
};

typedef CKey EncKey;
typedef CKeyCert EncKeyCert;
typedef CKeySymmetric EncKeySymmetric;
typedef CKeyPKI EncKeyPKI;

} // namespace libcdoc

#endif // KEYS_H
