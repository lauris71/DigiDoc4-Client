#define __CDOC2_CPP__

#include <fstream>
#include <iostream>

#include "openssl/evp.h"
#include <openssl/x509.h>

#include "certificate.h"
#include "Crypto.h"
#include "tar.h"
#include "utils.h"
#include "zstream.h"
#include "header_generated.h"

#include "cdoc2.h"

const std::string CDoc2Reader::LABEL = "CDOC\x02";
const std::string CDoc2Reader::CEK = "CDOC20cek";
const std::string CDoc2Reader::HMAC = "CDOC20hmac";
const std::string CDoc2Reader::KEK = "CDOC20kek";
const std::string CDoc2Reader::KEKPREMASTER = "CDOC20kekpremaster";
const std::string CDoc2Reader::PAYLOAD = "CDOC20payload";
const std::string CDoc2Reader::SALT = "CDOC20salt";

// Get salt bitstring for HKDF expand method

static std::string
getSaltForExpand(const std::string& label)
{
	return CDoc2Reader::KEK + cdoc20::header::EnumNameFMKEncryptionMethod(cdoc20::header::FMKEncryptionMethod::XOR) + label;
}

// Get salt bitstring for HKDF expand method
std::string
getSaltForExpand(const std::vector<uint8_t>& key_material, const std::vector<uint8_t>& rcpt_key)
{
	return CDoc2Reader::KEK + cdoc20::header::EnumNameFMKEncryptionMethod(cdoc20::header::FMKEncryptionMethod::XOR) +
			std::string(rcpt_key.cbegin(), rcpt_key.cend()) +
			std::string(key_material.cbegin(), key_material.cend());
}

CDoc2Reader::~CDoc2Reader()
{
	for (libcdoc::Lock *lock : locks) {
		delete lock;
	}
}


const libcdoc::Lock *
CDoc2Reader::getDecryptionLock(const std::vector<uint8_t>& cert)
{
	libcdoc::Certificate cc(cert);
	std::vector<uint8_t> other_key = cc.getPublicKey();
	for (const libcdoc::Lock *lock : locks) {
		if (lock->hasTheSameKey(other_key)) return lock;
	}
	return nullptr;
}

int
CDoc2Reader::getFMK(std::vector<uint8_t>& fmk, const libcdoc::Lock *lock)
{
	std::vector<uint8_t> kek;
	if (lock->isSymmetric()) {
		// Symmetric key
		const libcdoc::LockSymmetric &sk = static_cast<const libcdoc::LockSymmetric&>(*lock);
		std::string info_str = getSaltForExpand(sk.label);
		crypto->getKEK(kek, sk.salt, sk.pw_salt, sk.kdf_iter, sk.label, info_str);
	} else {
		// Public/private key
		const libcdoc::LockPKI &pki = static_cast<const libcdoc::LockPKI&>(*lock);
		std::vector<uint8_t> key_material;
		if(lock->type == libcdoc::Lock::Type::SERVER) {
			const libcdoc::LockServer &sk = static_cast<const libcdoc::LockServer&>(*lock);
			int result = network->fetchKey(key_material, sk.keyserver_id, sk.transaction_id);
			if (result < 0) {
				setLastError(network->getLastErrorStr(result));
				return result;
			}
		} else if (lock->type == libcdoc::Lock::PUBLIC_KEY) {
			const libcdoc::LockPublicKey& pk = static_cast<const libcdoc::LockPublicKey&>(*lock);
			key_material = pk.key_material;
		}
#ifndef NDEBUG
		std::cerr << "Public key: " << libcdoc::Crypto::toHex(pki.rcpt_key) << std::endl;
		std::cerr << "Key material: " << libcdoc::Crypto::toHex(key_material) << std::endl;
#endif
		if (pki.pk_type == libcdoc::Lock::PKType::RSA) {
			int result = crypto->decryptRSA(kek, key_material, true);
			if (result < 0) {
				setLastError(crypto->getLastErrorStr(result));
				return result;
			}
		} else {
			std::vector<uint8_t> kek_pm;
			int result = crypto->deriveHMACExtract(kek_pm, key_material, std::vector<uint8_t>(KEKPREMASTER.cbegin(), KEKPREMASTER.cend()), KEY_LEN);
			if (result < 0) {
				setLastError(crypto->getLastErrorStr(result));
				return result;
			}
#ifndef NDEBUG
			std::cerr << "Key kekPm: " << libcdoc::Crypto::toHex(kek_pm) << std::endl;
#endif
			std::string info_str = getSaltForExpand(key_material, pki.rcpt_key);
#ifndef NDEBUG
			std::cerr << "info" << libcdoc::Crypto::toHex(std::vector<uint8_t>(info_str.cbegin(), info_str.cend())) << std::endl;
#endif
			kek = libcdoc::Crypto::expand(kek_pm, std::vector<uint8_t>(info_str.cbegin(), info_str.cend()), KEY_LEN);
		}
	}
#ifndef NDEBUG
	std::cerr << "kek: " << libcdoc::Crypto::toHex(kek) << std::endl;
#endif

	if(kek.empty()) {
		setLastError(t_("Failed to derive key"));
		return false;
	}
	if (libcdoc::Crypto::xor_data(fmk, lock->encrypted_fmk, kek) != libcdoc::OK) {
		setLastError(t_("Failed to decrypt/derive fmk"));
		return libcdoc::CRYPTO_ERROR;
	}
	std::vector<uint8_t> hhk = libcdoc::Crypto::expand(fmk, std::vector<uint8_t>(HMAC.cbegin(), HMAC.cend()));
#ifndef NDEBUG
	std::cerr << "xor: " << libcdoc::Crypto::toHex(lock->encrypted_fmk) << std::endl;
	std::cerr << "fmk: " << libcdoc::Crypto::toHex(fmk) << std::endl;
	std::cerr << "hhk: " << libcdoc::Crypto::toHex(hhk) << std::endl;
	std::cerr << "hmac: " << libcdoc::Crypto::toHex(headerHMAC) << std::endl;
#endif
	if(libcdoc::Crypto::sign_hmac(hhk, header_data) != headerHMAC) {
		setLastError(t_("CDoc 2.0 hash mismatch"));
		return libcdoc::HASH_MISMATCH;
	}
	setLastError({});
	return libcdoc::OK;
}

int
CDoc2Reader::decrypt(const std::vector<uint8_t>& fmk, libcdoc::MultiDataConsumer *consumer)
{
	if (!_at_nonce) {
		int result = _src->seek(_nonce_pos);
		if (result != libcdoc::OK) {
			setLastError(_src->getLastErrorStr(result));
			return libcdoc::IO_ERROR;
		}
	}
	_at_nonce = false;

	std::vector<uint8_t> cek = libcdoc::Crypto::expand(fmk, std::vector<uint8_t>(CEK.cbegin(), CEK.cend()));
	std::vector<uint8_t> nonce(NONCE_LEN);
	if (_src->read(nonce.data(), NONCE_LEN) != NONCE_LEN) {
		setLastError("Error reading nonce");
		return libcdoc::IO_ERROR;
	}
#ifndef NDEBUG
	std::cerr << "cek: " << libcdoc::Crypto::toHex(cek) << std::endl;
	std::cerr << "nonce: " << libcdoc::Crypto::toHex(nonce) << std::endl;
#endif
	libcdoc::Crypto::Cipher dec(EVP_chacha20_poly1305(), cek, nonce, false);
	std::vector<uint8_t> aad(PAYLOAD.cbegin(), PAYLOAD.cend());
	aad.insert(aad.end(), header_data.cbegin(), header_data.cend());
	aad.insert(aad.end(), headerHMAC.cbegin(), headerHMAC.cend());
	if(!dec.updateAAD(aad)) {
		setLastError("OpenSSL error");
		return libcdoc::UNSPECIFIED_ERROR;
	}

	TaggedSource tgs(_src, false, 16);
	libcdoc::CipherSource csrc(&tgs, false, &dec);
	libcdoc::ZSource zsrc(&csrc);

	bool warning = false;
	if (!libcdoc::TAR::files(&zsrc, warning, consumer)) {
		setLastError("Error in decoding stream");
		return libcdoc::IO_ERROR;
	}
	if(warning) {
		setLastError(t_("CDoc contains additional payload data that is not part of content"));
	}

#ifndef NDEBUG
	std::cerr << "tag: " << libcdoc::Crypto::toHex(tgs.tag) << std::endl;
#endif
	dec.setTag(tgs.tag);
	if (!dec.result()) {
		setLastError("Stream tag does not match");
		return libcdoc::UNSPECIFIED_ERROR;
	}
	setLastError({});
	return libcdoc::OK;
}


CDoc2Reader::CDoc2Reader(libcdoc::DataSource *src, bool take_ownership)
	: CDocReader(2), _src(src), _owned(take_ownership)
{

	using namespace cdoc20::recipients;
	using namespace cdoc20::header;

	setLastError(t_("Invalid CDoc 2.0 header"));

	uint8_t in[LABEL.size()];
	if (_src->read(in, LABEL.size()) != LABEL.size()) return;
	if (LABEL.compare(0, LABEL.size(), (const char *) in)) return;

	// Read 32-bit header length in big endian order
	uint8_t c[4];
	if (_src->read(c, 4) != 4) return;
	uint32_t header_len = (c[0] << 24) | (c[1] << 16) | c[2] << 8 | c[3];
	header_data.resize(header_len);
	if (_src->read(header_data.data(), header_len) != header_len) return;
	headerHMAC.resize(KEY_LEN);
	if (_src->read(headerHMAC.data(), KEY_LEN) != KEY_LEN) return;

	_nonce_pos = LABEL.size() + 4 + header_len + KEY_LEN;
	_at_nonce = true;

	flatbuffers::Verifier verifier(reinterpret_cast<const uint8_t*>(header_data.data()), header_data.size());
	if(!VerifyHeaderBuffer(verifier)) return;
	const auto *header = GetHeader(header_data.data());
	if(!header) return;
	if(header->payload_encryption_method() != PayloadEncryptionMethod::CHACHA20POLY1305) return;
	const auto *recipients = header->recipients();
	if(!recipients) return;

	setLastError({});

	for(const auto *recipient: *recipients){
		if(recipient->fmk_encryption_method() != FMKEncryptionMethod::XOR)
		{
			std::cerr << "Unsupported FMK encryption method: skipping" << std::endl;
			continue;
		}
		auto fillRecipientPK = [&] (libcdoc::Lock::PKType pk_type, auto key) {
			libcdoc::LockPublicKey *k = new libcdoc::LockPublicKey(pk_type, key->recipient_public_key()->data(), key->recipient_public_key()->size());
			k->label = recipient->key_label()->str();
			k->encrypted_fmk.assign(recipient->encrypted_fmk()->cbegin(), recipient->encrypted_fmk()->cend());
			return k;
		};
		switch(recipient->capsule_type())
		{
		case Capsule::ECCPublicKeyCapsule:
			if(const auto *key = recipient->capsule_as_ECCPublicKeyCapsule()) {
				if(key->curve() != EllipticCurve::secp384r1) {
					std::cerr << "Unsupported ECC curve: skipping" << std::endl;
					continue;
				}
				libcdoc::LockPublicKey *k = fillRecipientPK(libcdoc::Lock::PKType::ECC, key);
				k->key_material.assign(key->sender_public_key()->cbegin(), key->sender_public_key()->cend());
				std::cerr << "Load PK: " << libcdoc::Crypto::toHex(k->rcpt_key) << std::endl;
				locks.push_back(k);
			}
			break;
		case Capsule::RSAPublicKeyCapsule:
			if(const auto *key = recipient->capsule_as_RSAPublicKeyCapsule())
			{
				libcdoc::LockPublicKey *k = fillRecipientPK(libcdoc::Lock::PKType::RSA, key);
				k->key_material.assign(key->encrypted_kek()->cbegin(), key->encrypted_kek()->cend());
				locks.push_back(k);
			}
			break;
		case Capsule::KeyServerCapsule:
			if (const KeyServerCapsule *server = recipient->capsule_as_KeyServerCapsule()) {
				KeyDetailsUnion details = server->recipient_key_details_type();
				libcdoc::LockServer *ckey = nullptr;
				switch (details) {
				case KeyDetailsUnion::EccKeyDetails:
					if(const EccKeyDetails *eccDetails = server->recipient_key_details_as_EccKeyDetails()) {
						if(eccDetails->curve() == EllipticCurve::secp384r1) {
							ckey = libcdoc::LockServer::fromKey(std::vector<uint8_t>(eccDetails->recipient_public_key()->cbegin(), eccDetails->recipient_public_key()->cend()), libcdoc::Lock::PKType::ECC);
						} else {
							std::cerr << "Unsupported elliptic curve key type" << std::endl;
						}
					} else {
						std::cerr << "Invalid file format" << std::endl;
					}
					break;
				case KeyDetailsUnion::RsaKeyDetails:
					if(const RsaKeyDetails *rsaDetails = server->recipient_key_details_as_RsaKeyDetails()) {
						ckey = libcdoc::LockServer::fromKey(std::vector<uint8_t>(rsaDetails->recipient_public_key()->cbegin(), rsaDetails->recipient_public_key()->cend()), libcdoc::Lock::PKType::RSA);
					} else {
						std::cerr << "Invalid file format" << std::endl;
					}
					break;
				default:
					std::cerr << "Unsupported Key Server Details: skipping" << std::endl;
				}
				if (ckey) {
					ckey->label = recipient->key_label()->c_str();
					ckey->encrypted_fmk.assign(recipient->encrypted_fmk()->cbegin(), recipient->encrypted_fmk()->cend());
					ckey->keyserver_id = server->keyserver_id()->str();
					ckey->transaction_id = server->transaction_id()->str();
					locks.push_back(ckey);
				}
			} else {
				std::cerr << "Invalid file format" << std::endl;
			}
			break;
		case Capsule::SymmetricKeyCapsule:
			if(const auto *capsule = recipient->capsule_as_SymmetricKeyCapsule())
			{
				libcdoc::LockSymmetric *key = new libcdoc::LockSymmetric(std::vector<uint8_t>(capsule->salt()->cbegin(), capsule->salt()->cend()));
				key->label = recipient->key_label()->str();
				key->encrypted_fmk.assign(recipient->encrypted_fmk()->cbegin(), recipient->encrypted_fmk()->cend());
				locks.push_back(key);
			}
			break;
		case Capsule::PBKDF2Capsule:
			if(const auto *capsule = recipient->capsule_as_PBKDF2Capsule()) {
				KDFAlgorithmIdentifier kdf_id = capsule->kdf_algorithm_identifier();
				if (kdf_id != KDFAlgorithmIdentifier::PBKDF2WithHmacSHA256) {
					std::cerr << "Unsupported KDF algorithm: skipping" << std::endl;
					continue;
				}
				auto salt = capsule->salt();
				auto pw_salt = capsule->password_salt();
				int32_t kdf_iter = capsule->kdf_iterations();
				libcdoc::LockSymmetric *key = new libcdoc::LockSymmetric(std::vector<uint8_t>(salt->cbegin(), salt->cend()));
				key->label = recipient->key_label()->str();
				key->encrypted_fmk.assign(recipient->encrypted_fmk()->cbegin(), recipient->encrypted_fmk()->cend());
				key->pw_salt.assign(pw_salt->cbegin(), pw_salt->cend());
				key->kdf_iter = kdf_iter;
				locks.push_back(key);
			}
			break;
		default:
			std::cerr << "Unsupported Key Details: skipping" << std::endl;
		}
	}
}

CDoc2Reader::CDoc2Reader(const std::string &path)
	: CDoc2Reader(new libcdoc::IStreamSource(path), true)
{
}

bool
CDoc2Reader::isCDoc2File(const std::string& path)
{
	std::ifstream fb(path);
	char in[LABEL.size()];
	if (!fb.read(in, LABEL.size()) || (fb.gcount() != LABEL.size())) return false;
	if (LABEL.compare(0, LABEL.size(), in)) return false;
	return true;
}

struct CDoc2Writer::Private {
	Private(libcdoc::DataConsumer *_dst) : dst(_dst) {
		fmk = libcdoc::Crypto::extract(libcdoc::Crypto::random(CDoc2Reader::KEY_LEN), std::vector<uint8_t>(CDoc2Reader::SALT.cbegin(), CDoc2Reader::SALT.cend()));
		cek = libcdoc::Crypto::expand(fmk, std::vector<uint8_t>(CDoc2Reader::CEK.cbegin(), CDoc2Reader::CEK.cend()));
		hhk = libcdoc::Crypto::expand(fmk, std::vector<uint8_t>(CDoc2Reader::HMAC.cbegin(), CDoc2Reader::HMAC.cend()));
		nonce = libcdoc::Crypto::random(CDoc2Reader::NONCE_LEN);
		cipher = std::make_unique<libcdoc::Crypto::Cipher>(EVP_chacha20_poly1305(), cek, nonce, true);
		libcdoc::CipherConsumer *ccons = new libcdoc::CipherConsumer(dst, false, cipher.get());
		libcdoc::ZConsumer *zcons = new libcdoc::ZConsumer(ccons, true);
		tar = std::make_unique<libcdoc::TarConsumer>(zcons, true);
	}
	~Private() {
		std::fill(fmk.begin(), fmk.end(), 0);
		std::fill(cek.begin(), cek.end(), 0);
		std::fill(hhk.begin(), hhk.end(), 0);
		cipher.reset();
		tar.reset();
	}
	libcdoc::DataConsumer *dst;
	std::vector<uint8_t> fmk;
	std::vector<uint8_t> cek;
	std::vector<uint8_t> hhk;
	std::vector<uint8_t> nonce;
	std::unique_ptr<libcdoc::Crypto::Cipher> cipher;
	std::unique_ptr<libcdoc::TarConsumer> tar;
	std::vector<libcdoc::Recipient> recipients;
	bool header_written = false;
};

CDoc2Writer::CDoc2Writer()
	: CDocWriter(2)
{
}

CDoc2Writer::~CDoc2Writer()
{
}

int
CDoc2Writer::encrypt(libcdoc::DataConsumer& dst, libcdoc::MultiDataSource& src, const std::vector<libcdoc::Recipient>& keys)
{
	last_error.clear();
	priv = std::make_unique<Private>(&dst);
#ifndef NDEBUG
	std::cerr << "fmk: " << libcdoc::Crypto::toHex(priv->fmk) << std::endl;
	std::cerr << "cek: " << libcdoc::Crypto::toHex(priv->cek) << std::endl;
	std::cerr << "hhk: " << libcdoc::Crypto::toHex(priv->hhk) << std::endl;
#endif
	int result = encryptInternal(src, keys);
	priv.reset();
	return result;
}

int
CDoc2Writer::encryptInternal(libcdoc::MultiDataSource& src, const std::vector<libcdoc::Recipient>& keys)
{
	std::vector<uint8_t> header;
	int result = buildHeader(header, keys, priv->fmk);
	if (result < 0) return result;

	result = writeHeader(header, priv->hhk);
	if (result < 0) return result;

	std::string name;
	int64_t size;
	while (src.next(name, size)) {
		if (priv->tar->open(name, size) < 0) return libcdoc::IO_ERROR;
		if (priv->tar->writeAll(src) < 0) return libcdoc::IO_ERROR;
	}
	if (priv->tar->close() < 0) return libcdoc::IO_ERROR;
	priv->tar.reset();
//	if(!libcdoc::TAR::save(zcons, src)) {
//		setLastError("Error packing encrypted stream");
//		return libcdoc::IO_ERROR;
//	}
	if(!priv->cipher->result()) {
		setLastError("Encryption error");
		return libcdoc::CRYPTO_ERROR;
	}
	std::vector<uint8_t> tag = priv->cipher->tag();
#ifndef NDEBUG
	std::cerr << "tag" << libcdoc::Crypto::toHex(tag) << std::endl;
#endif
	priv->dst->write(tag.data(), tag.size());
	priv->dst->close();
	return libcdoc::OK;
}

int
CDoc2Writer::writeHeader(const std::vector<uint8_t>& header, const std::vector<uint8_t>& hhk)
{
	std::vector<uint8_t> headerHMAC = libcdoc::Crypto::sign_hmac(hhk, header);
#ifndef NDEBUG
	std::cerr << "hmac" << libcdoc::Crypto::toHex(headerHMAC) << std::endl;
	std::cerr << "nonce" << libcdoc::Crypto::toHex(priv->nonce) << std::endl;
#endif

	std::vector<uint8_t> aad(CDoc2Reader::PAYLOAD.cbegin(), CDoc2Reader::PAYLOAD.cend());
	aad.insert(aad.end(), header.cbegin(), header.cend());
	aad.insert(aad.end(), headerHMAC.cbegin(), headerHMAC.cend());
	priv->cipher->updateAAD(aad);
	uint32_t hs = uint32_t(header.size());
	uint8_t header_len[] {uint8_t(hs >> 24), uint8_t((hs >> 16) & 0xff), uint8_t((hs >> 8) & 0xff), uint8_t(hs & 0xff)};

	priv->dst->write((const uint8_t *) CDoc2Reader::LABEL.data(), CDoc2Reader::LABEL.size());
	priv->dst->write((const uint8_t *) &header_len, 4);
	priv->dst->write(header.data(), header.size());
	priv->dst->write(headerHMAC.data(), headerHMAC.size());
	priv->dst->write(priv->nonce.data(), priv->nonce.size());
	return libcdoc::OK;
}

int
CDoc2Writer::buildHeader(std::vector<uint8_t>& header, const std::vector<libcdoc::Recipient>& keys, const std::vector<uint8_t>& fmk)
{
	flatbuffers::FlatBufferBuilder builder;
	std::vector<flatbuffers::Offset<cdoc20::header::RecipientRecord>> recipients;

	std::vector<uint8_t> xor_key(CDoc2Reader::KEY_LEN);
	for(const libcdoc::Recipient& key: keys) {
		if (key.isPKI()) {
			const libcdoc::Recipient& pki = key;
			if(pki.pk_type == libcdoc::Recipient::PKType::RSA) {
				std::vector<uint8_t> kek = libcdoc::Crypto::random(CDoc2Reader::KEY_LEN);
				if (libcdoc::Crypto::xor_data(xor_key, fmk, kek) != libcdoc::OK) {
					setLastError("Internal error");
					return libcdoc::CRYPTO_ERROR;
				}
				auto publicKey = libcdoc::Crypto::fromRSAPublicKeyDer(pki.rcpt_key);
				if(!publicKey) {
					setLastError("Invalid RSA key");
					return libcdoc::CRYPTO_ERROR;
				}
				std::vector<uint8_t> encrytpedKek = libcdoc::Crypto::encrypt(publicKey.get(), RSA_PKCS1_OAEP_PADDING, kek);
	#ifndef NDEBUG
				std::cerr << "publicKeyDer" << libcdoc::Crypto::toHex(pki.rcpt_key) << std::endl;
				std::cerr << "kek" << libcdoc::Crypto::toHex(kek) << std::endl;
				std::cerr << "xor" << libcdoc::Crypto::toHex(xor_key) << std::endl;
				std::cerr << "encrytpedKek" << libcdoc::Crypto::toHex(encrytpedKek) << std::endl;
	#endif
				if(!conf->getBoolean(libcdoc::Configuration::USE_KEYSERVER)) {
					auto rsaPublicKey = cdoc20::recipients::CreateRSAPublicKeyCapsule(builder,
																					  builder.CreateVector(pki.rcpt_key),
																					  builder.CreateVector(encrytpedKek));
					auto offs = cdoc20::header::CreateRecipientRecord(builder,
																	  cdoc20::recipients::Capsule::RSAPublicKeyCapsule,
																	  rsaPublicKey.Union(),
																	  builder.CreateString(pki.label),
																	  builder.CreateVector(xor_key),
																	  cdoc20::header::FMKEncryptionMethod::XOR);
					recipients.push_back(offs);
				} else {
					std::pair<std::string,std::string> serverinfo;
					int result = network->sendKey(serverinfo, pki.rcpt_key, std::vector<uint8_t>(encrytpedKek.cbegin(), encrytpedKek.cend()), "rsa");
					if (result < 0) {
						setLastError(network->getLastErrorStr(result));
						return libcdoc::IO_ERROR;
					}
					auto rsaKeyServer = cdoc20::recipients::CreateRsaKeyDetails(builder,
																				builder.CreateVector(pki.rcpt_key));
					auto keyServer = cdoc20::recipients::CreateKeyServerCapsule(builder,
																				cdoc20::recipients::KeyDetailsUnion::RsaKeyDetails,
																				rsaKeyServer.Union(),
																				builder.CreateString(serverinfo.first),
																				builder.CreateString(serverinfo.second));
					auto offs = cdoc20::header::CreateRecipientRecord(builder,
																	  cdoc20::recipients::Capsule::KeyServerCapsule,
																	  keyServer.Union(),
																	  builder.CreateString(pki.label),
																	  builder.CreateVector(xor_key),
																	  cdoc20::header::FMKEncryptionMethod::XOR);
					recipients.push_back(offs);
				}
			} else {
				auto publicKey = libcdoc::Crypto::fromECPublicKeyDer(pki.rcpt_key, NID_secp384r1);
				if(!publicKey) {
					setLastError("Invalid ECC key");
					return libcdoc::CRYPTO_ERROR;
				}
				auto ephKey = libcdoc::Crypto::genECKey(publicKey.get());
				std::vector<uint8_t> sharedSecret = libcdoc::Crypto::deriveSharedSecret(ephKey.get(), publicKey.get());
				std::vector<uint8_t> ephPublicKeyDer = libcdoc::Crypto::toPublicKeyDer(ephKey.get());
				std::vector<uint8_t> kekPm = libcdoc::Crypto::extract(sharedSecret, std::vector<uint8_t>(CDoc2Reader::KEKPREMASTER.cbegin(), CDoc2Reader::KEKPREMASTER.cend()));
				std::string info_str = CDoc2Reader::KEK +
						cdoc20::header::EnumNameFMKEncryptionMethod(cdoc20::header::FMKEncryptionMethod::XOR) +
						std::string(pki.rcpt_key.cbegin(), pki.rcpt_key.cend()) +
						std::string(ephPublicKeyDer.cbegin(), ephPublicKeyDer.cend());

				std::vector<uint8_t> kek = libcdoc::Crypto::expand(kekPm, std::vector<uint8_t>(info_str.cbegin(), info_str.cend()), fmk.size());
				if (libcdoc::Crypto::xor_data(xor_key, fmk, kek) != libcdoc::OK) {
					setLastError("Internal error");
					return libcdoc::CRYPTO_ERROR;
				}
	#ifndef NDEBUG
				std::cerr << "info" << libcdoc::Crypto::toHex(std::vector<uint8_t>(info_str.cbegin(), info_str.cend())) << std::endl;
				std::cerr << "publicKeyDer" << libcdoc::Crypto::toHex(pki.rcpt_key) << std::endl;
				std::cerr << "ephPublicKeyDer" << libcdoc::Crypto::toHex(ephPublicKeyDer) << std::endl;
				std::cerr << "sharedSecret" << libcdoc::Crypto::toHex(sharedSecret) << std::endl;
				std::cerr << "kekPm" << libcdoc::Crypto::toHex(kekPm) << std::endl;
				std::cerr << "kek" << libcdoc::Crypto::toHex(kek) << std::endl;
				std::cerr << "xor" << libcdoc::Crypto::toHex(xor_key) << std::endl;
	#endif
				if(!conf->getBoolean(libcdoc::Configuration::USE_KEYSERVER)) {
					auto eccPublicKey = cdoc20::recipients::CreateECCPublicKeyCapsule(builder,
																					  cdoc20::recipients::EllipticCurve::secp384r1,
																					  builder.CreateVector(pki.rcpt_key),
																					  builder.CreateVector(ephPublicKeyDer));
					auto offs = cdoc20::header::CreateRecipientRecord(builder,
																	  cdoc20::recipients::Capsule::ECCPublicKeyCapsule,
																	  eccPublicKey.Union(),
																	  builder.CreateString(pki.label),
																	  builder.CreateVector(xor_key),
																	  cdoc20::header::FMKEncryptionMethod::XOR);
					recipients.push_back(offs);
				} else {
					std::pair<std::string,std::string> serverinfo;
					int result = network->sendKey(serverinfo, pki.rcpt_key, ephPublicKeyDer, "ecc_secp384r1");
					if (result < 0) {
						setLastError(network->getLastErrorStr(result));
						return libcdoc::IO_ERROR;
					}
					auto eccKeyServer = cdoc20::recipients::CreateEccKeyDetails(builder,
																				cdoc20::recipients::EllipticCurve::secp384r1,
																				builder.CreateVector(pki.rcpt_key));
					auto keyServer = cdoc20::recipients::CreateKeyServerCapsule(builder,
																				cdoc20::recipients::KeyDetailsUnion::EccKeyDetails,
																				eccKeyServer.Union(),
																				builder.CreateString(serverinfo.first),
																				builder.CreateString(serverinfo.second));
					auto offs = cdoc20::header::CreateRecipientRecord(builder,
																	  cdoc20::recipients::Capsule::KeyServerCapsule,
																	  keyServer.Union(),
																	  builder.CreateString(pki.label),
																	  builder.CreateVector(xor_key),
																	  cdoc20::header::FMKEncryptionMethod::XOR);
					recipients.push_back(offs);
				}
			}
		} else if (key.isSymmetric()) {
			const libcdoc::Recipient& sk = key;
			std::string info_str = getSaltForExpand(sk.label);
			std::vector<uint8_t> kek(32);
			std::vector<uint8_t> salt;
			crypto->random(salt, 32);
			std::vector<uint8_t> pw_salt;
			crypto->random(pw_salt, 32);
			crypto->getKEK(kek, salt, pw_salt, sk.kdf_iter, sk.label, info_str);
			if (sk.kdf_iter > 0) {
				// PasswordKeyMaterial_i = PBKDF2(Password_i, PasswordSalt_i)
//				std::vector<uint8_t> key_material = libcdoc::Crypto::pbkdf2_sha256(secret, sk.pw_salt, sk.kdf_iter);
		#ifndef NDEBUG
//				std::cerr << "Key material: " << libcdoc::Crypto::toHex(key_material) << std::endl;
		#endif \
				// KEK_i = HKDF(KeyMaterialSalt_i, PasswordKeyMaterial_i)
				//QByteArray info = KEK + cdoc20::header::EnumNameFMKEncryptionMethod(cdoc20::header::FMKEncryptionMethod::XOR) + secret;
//				std::vector<uint8_t> tmp = libcdoc::Crypto::extract(key_material, sk.salt, 32);
//				std::vector<uint8_t> kek = libcdoc::Crypto::expand(tmp, std::vector<uint8_t>(info_str.cbegin(), info_str.cend()), 32);

				if (libcdoc::Crypto::xor_data(xor_key, fmk, kek) != libcdoc::OK) {
					setLastError("Internal error");
					return libcdoc::CRYPTO_ERROR;
				}

				auto capsule = cdoc20::recipients::CreatePBKDF2Capsule(builder,
																	   builder.CreateVector(salt),
																	   builder.CreateVector(pw_salt),
																	   cdoc20::recipients::KDFAlgorithmIdentifier::PBKDF2WithHmacSHA256,
																	   sk.kdf_iter);
				auto offs = cdoc20::header::CreateRecipientRecord(builder,
																  cdoc20::recipients::Capsule::PBKDF2Capsule,
																  capsule.Union(),
																  builder.CreateString(sk.label),
																  builder.CreateVector(xor_key),
																  cdoc20::header::FMKEncryptionMethod::XOR);
				recipients.push_back(offs);
			} else {
				// KeyMaterialSalt_i = CSRNG()
//				std::vector<uint8_t> salt = libcdoc::Crypto::random();
				// KeyMaterialSalt_i = CSRNG()
				// KEK_i = HKDF(KeyMaterialSalt_i, S_i)
				//QByteArray info = KEK + cdoc20::header::EnumNameFMKEncryptionMethod(cdoc20::header::FMKEncryptionMethod::XOR) + QByteArray(label.data(), label.size());
//				std::vector<uint8_t> tmp = libcdoc::Crypto::extract(std::vector<uint8_t>(secret.cbegin(), secret.cend()), salt, 32);
//				std::vector<uint8_t> kek = libcdoc::Crypto::expand(tmp, std::vector<uint8_t>(info_str.cbegin(), info_str.cend()), 32);

				if (libcdoc::Crypto::xor_data(xor_key, fmk, kek) != libcdoc::OK) {
					setLastError("Internal error");
					return libcdoc::CRYPTO_ERROR;
				}

				auto capsule = cdoc20::recipients::CreateSymmetricKeyCapsule(builder,
																			 builder.CreateVector(salt));
				auto offs = cdoc20::header::CreateRecipientRecord(builder,
																  cdoc20::recipients::Capsule::SymmetricKeyCapsule,
																  capsule.Union(),
																  builder.CreateString(sk.label),
																  builder.CreateVector(xor_key),
																  cdoc20::header::FMKEncryptionMethod::XOR);
				recipients.push_back(offs);
			}
		} else {
			setLastError("Invalid recipient type");
			return libcdoc::UNSPECIFIED_ERROR;
		}
	}

	auto offset = cdoc20::header::CreateHeader(builder, builder.CreateVector(recipients),
											   cdoc20::header::PayloadEncryptionMethod::CHACHA20POLY1305);
	builder.Finish(offset);

	header.assign(builder.GetBufferPointer(), builder.GetBufferPointer() + builder.GetSize());
	return libcdoc::OK;
}

int
CDoc2Writer::beginEncryption(libcdoc::DataConsumer& dst)
{
	if (priv) {
		setLastError("Encryption workflow already started");
		return libcdoc::WORKFLOW_ERROR;
	}
	last_error.clear();
	priv = std::make_unique<Private>(&dst);
	return libcdoc::OK;
}

int
CDoc2Writer::addRecipient(const libcdoc::Recipient& rcpt)
{
	if (!priv) {
		setLastError("Encryption workflow not started");
		return libcdoc::WORKFLOW_ERROR;
	}
	priv->recipients.push_back(rcpt);
	return libcdoc::OK;
}

int
CDoc2Writer::addFile(const std::string& name, size_t size)
{
	if (!priv) {
		setLastError("Encryption workflow not started");
		return libcdoc::WORKFLOW_ERROR;
	}
	if (priv->recipients.empty()) {
		setLastError("No recipients specified");
		return libcdoc::WRONG_ARGUMENTS;
	}
	if (!priv->header_written) {
		std::vector<uint8_t> header;
		int result = buildHeader(header, priv->recipients, priv->fmk);
		if (result < 0) return result;

		result = writeHeader(header, priv->hhk);
		if (result < 0) return result;

		priv->header_written = true;
	}
	int result = priv->tar->open(name, size);
	if (result < 0) {
		setLastError(priv->tar->getLastErrorStr(result));
		return result;
	}
	return libcdoc::OK;
}

int
CDoc2Writer::writeData(const uint8_t *src, size_t size)
{
	if (!priv) {
		setLastError("Encryption workflow not started");
		return libcdoc::WORKFLOW_ERROR;
	}
	if (!priv->header_written) {
		setLastError("No file added");
		return libcdoc::WORKFLOW_ERROR;
	}

	int64_t result = priv->tar->write(src, size);
	if (result != size) {
		setLastError(priv->tar->getLastErrorStr(result));
		return result;
	}

	return libcdoc::OK;
}

int
CDoc2Writer::finishEncryption(bool close_dst)
{
	if (!priv) {
		setLastError("Encryption workflow not started");
		return libcdoc::WORKFLOW_ERROR;
	}
	if (!priv->header_written) {
		setLastError("No file added");
		return libcdoc::WORKFLOW_ERROR;
	}
	int result = priv->tar->close();
	if (result < 0) {
		setLastError(priv->tar->getLastErrorStr(result));
		return result;
	}
	priv->tar.reset();
	if(!priv->cipher->result()) {
		setLastError("Encryption error");
		return libcdoc::CRYPTO_ERROR;
	}
	std::vector<uint8_t> tag = priv->cipher->tag();
#ifndef NDEBUG
	std::cerr << "tag" << libcdoc::Crypto::toHex(tag) << std::endl;
#endif
	priv->dst->write(tag.data(), tag.size());
	if (close_dst) priv->dst->close();

	return libcdoc::OK;
}
