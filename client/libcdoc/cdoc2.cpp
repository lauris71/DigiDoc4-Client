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

libcdoc::CKey::DecryptionStatus
CDoc2Reader::canDecrypt(const libcdoc::Certificate &cert)
{
	std::vector<uint8_t> other_key = cert.getPublicKey();
	libcdoc::CKey::DecryptionStatus status = libcdoc::CKey::DecryptionStatus::CANNOT_DECRYPT;
	for (const std::shared_ptr<const libcdoc::CKey>& key: keys) {
		if (key->isTheSameRecipient(other_key)) return libcdoc::CKey::CAN_DECRYPT;
		if (key->isSymmetric()) status = libcdoc::CKey::DecryptionStatus::NEED_KEY;
	}
	return status;
}

std::shared_ptr<libcdoc::CKey>
CDoc2Reader::getDecryptionKey(const libcdoc::Certificate &cert)
{
	std::vector<uint8_t> other_key = cert.getPublicKey();
	std::shared_ptr<libcdoc::CKey> best = {};
	for (std::shared_ptr<libcdoc::CKey> key: keys) {
		if (key->isTheSameRecipient(other_key)) return key;
		if (key->isSymmetric()) best = key;
	}
	return best;
}

bool
CDoc2Reader::getFMK(std::vector<uint8_t>& fmk, const libcdoc::CKey &key)
{
	setLastError({});
	std::vector<uint8_t> kek;
	if (key.isSymmetric()) {
		// Symmetric key
		const libcdoc::CKeySymmetric &sk = static_cast<const libcdoc::CKeySymmetric&>(key);
		std::string info_str = sk.getSaltForExpand();

		crypto->getKEK(kek, sk.salt, sk.pw_salt, sk.kdf_iter, sk.label, info_str);
	} else {
		// Public/private key
		const libcdoc::CKeyPKI &pki = static_cast<const libcdoc::CKeyPKI&>(key);
		std::vector<uint8_t> key_material;
		if(key.type == libcdoc::CKey::Type::SERVER) {
			const libcdoc::CKeyServer &sk = static_cast<const libcdoc::CKeyServer&>(key);
			std::vector<uint8_t> km = network->fetchKey(this, sk);
			key_material.assign(km.cbegin(), km.cend());
		} else if (key.type == libcdoc::CKey::PUBLIC_KEY) {
			const libcdoc::CKeyPublicKey& pk = static_cast<const libcdoc::CKeyPublicKey&>(key);
			key_material = pk.key_material;
		}
#ifndef NDEBUG
		std::cerr << "Public key: " << libcdoc::Crypto::toHex(pki.rcpt_key) << std::endl;
		std::cerr << "Key material: " << libcdoc::Crypto::toHex(key_material) << std::endl;
#endif
		if (pki.pk_type == libcdoc::CKey::PKType::RSA) {
			int result = crypto->decryptRSA(kek, key_material, true);
			if (result < 0) {
				setLastError(crypto->getLastErrorStr(result));
				return false;
			}
		} else {
			std::vector<uint8_t> kekpm = crypto->deriveHMACExtract(key_material, std::vector<uint8_t>(KEKPREMASTER.cbegin(), KEKPREMASTER.cend()), KEY_LEN);
#ifndef NDEBUG
			std::cerr << "Key kekPm: " << libcdoc::Crypto::toHex(kekpm) << std::endl;
#endif
			std::string info_str = pki.getSaltForExpand(key_material);
#ifndef NDEBUG
			std::cerr << "info" << libcdoc::Crypto::toHex(std::vector<uint8_t>(info_str.cbegin(), info_str.cend())) << std::endl;
#endif
			kek = libcdoc::Crypto::expand(kekpm, std::vector<uint8_t>(info_str.cbegin(), info_str.cend()), KEY_LEN);
		}
	}
#ifndef NDEBUG
	std::cerr << "kek: " << libcdoc::Crypto::toHex(kek) << std::endl;
#endif

	if(kek.empty()) {
		setLastError(t_("Failed to derive key"));
		return false;
	}
	fmk = libcdoc::Crypto::xor_data(key.encrypted_fmk, kek);
	std::vector<uint8_t> hhk = libcdoc::Crypto::expand(fmk, std::vector<uint8_t>(HMAC.cbegin(), HMAC.cend()));
#ifndef NDEBUG
	std::cerr << "xor: " << libcdoc::Crypto::toHex(key.encrypted_fmk) << std::endl;
	std::cerr << "fmk: " << libcdoc::Crypto::toHex(fmk) << std::endl;
	std::cerr << "hhk: " << libcdoc::Crypto::toHex(hhk) << std::endl;
	std::cerr << "hmac: " << libcdoc::Crypto::toHex(headerHMAC) << std::endl;
#endif
	if(libcdoc::Crypto::sign_hmac(hhk, header_data) != headerHMAC) {
		setLastError(t_("CDoc 2.0 hash mismatch"));
		return false;
	}
	return !fmk.empty();
}

bool
CDoc2Reader::decryptPayload(const std::vector<uint8_t>& fmk, libcdoc::MultiDataConsumer *consumer)
{
	if (!_at_nonce) {
		if (!_src->seek(_nonce_pos)) {
			setLastError("Input stream cannot be rewound");
			return false;
		}
	}
	_at_nonce = false;

	setLastError({});

	std::vector<uint8_t> cek = libcdoc::Crypto::expand(fmk, std::vector<uint8_t>(CEK.cbegin(), CEK.cend()));
	std::vector<uint8_t> nonce(NONCE_LEN);
	if (_src->read(nonce.data(), NONCE_LEN) != NONCE_LEN) {
		setLastError("Error reading nonce");
		return false;
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
		setLastError("Internal error");
		return false;
	}

	TaggedSource tgs(_src, false, 16);
	libcdoc::CipherSource csrc(&tgs, false, &dec);
	libcdoc::ZSource zsrc(&csrc);

	bool warning = false;
	if (!libcdoc::TAR::files(&zsrc, warning, consumer)) return false;
	if(warning) {
		setLastError(t_("CDoc contains additional payload data that is not part of content"));
	}

#ifndef NDEBUG
	std::cerr << "tag: " << libcdoc::Crypto::toHex(tgs.tag) << std::endl;
#endif
	dec.setTag(tgs.tag);
	return dec.result();
}


CDoc2Reader::CDoc2Reader(libcdoc::DataSource *src, bool take_ownership)
	: _src(src), _owned(take_ownership)
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
		auto fillRecipientPK = [&] (libcdoc::CKey::PKType pk_type, auto key) {
			std::shared_ptr<libcdoc::CKeyPublicKey> k(new libcdoc::CKeyPublicKey(pk_type, key->recipient_public_key()->data(), key->recipient_public_key()->size()));
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
				std::shared_ptr<libcdoc::CKeyPublicKey> k = fillRecipientPK(libcdoc::CKey::PKType::ECC, key);
				k->key_material.assign(key->sender_public_key()->cbegin(), key->sender_public_key()->cend());
				std::cerr << "Load PK: " << libcdoc::Crypto::toHex(k->rcpt_key) << std::endl;
				keys.push_back(k);
			}
			break;
		case Capsule::RSAPublicKeyCapsule:
			if(const auto *key = recipient->capsule_as_RSAPublicKeyCapsule())
			{
				std::shared_ptr<libcdoc::CKeyPublicKey> k = fillRecipientPK(libcdoc::CKey::PKType::RSA, key);
				k->key_material.assign(key->encrypted_kek()->cbegin(), key->encrypted_kek()->cend());
				keys.push_back(k);
			}
			break;
		case Capsule::KeyServerCapsule:
			if (const KeyServerCapsule *server = recipient->capsule_as_KeyServerCapsule()) {
				KeyDetailsUnion details = server->recipient_key_details_type();
				std::shared_ptr<libcdoc::CKeyServer> ckey = nullptr;
				switch (details) {
				case KeyDetailsUnion::EccKeyDetails:
					if(const EccKeyDetails *eccDetails = server->recipient_key_details_as_EccKeyDetails()) {
						if(eccDetails->curve() == EllipticCurve::secp384r1) {
							ckey = libcdoc::CKeyServer::fromKey(std::vector<uint8_t>(eccDetails->recipient_public_key()->cbegin(), eccDetails->recipient_public_key()->cend()), libcdoc::CKey::PKType::ECC);
						} else {
							std::cerr << "Unsupported elliptic curve key type" << std::endl;
						}
					} else {
						std::cerr << "Invalid file format" << std::endl;
					}
					break;
				case KeyDetailsUnion::RsaKeyDetails:
					if(const RsaKeyDetails *rsaDetails = server->recipient_key_details_as_RsaKeyDetails()) {
						ckey = libcdoc::CKeyServer::fromKey(std::vector<uint8_t>(rsaDetails->recipient_public_key()->cbegin(), rsaDetails->recipient_public_key()->cend()), libcdoc::CKey::PKType::RSA);
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
					keys.push_back(ckey);
				}
			} else {
				std::cerr << "Invalid file format" << std::endl;
			}
			break;
		case Capsule::SymmetricKeyCapsule:
			if(const auto *capsule = recipient->capsule_as_SymmetricKeyCapsule())
			{
				std::shared_ptr<libcdoc::CKeySymmetric> key(new libcdoc::CKeySymmetric(std::vector<uint8_t>(capsule->salt()->cbegin(), capsule->salt()->cend())));
				key->label = recipient->key_label()->str();
				key->encrypted_fmk.assign(recipient->encrypted_fmk()->cbegin(), recipient->encrypted_fmk()->cend());
				keys.push_back(key);
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
				std::shared_ptr<libcdoc::CKeySymmetric> key(new libcdoc::CKeySymmetric(std::vector<uint8_t>(salt->cbegin(), salt->cend())));
				key->label = recipient->key_label()->str();
				key->encrypted_fmk.assign(recipient->encrypted_fmk()->cbegin(), recipient->encrypted_fmk()->cend());
				key->pw_salt.assign(pw_salt->cbegin(), pw_salt->cend());
				key->kdf_iter = kdf_iter;
				keys.push_back(key);
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

bool
CDoc2Writer::encrypt(std::ostream& ofs, libcdoc::MultiDataSource& src, const std::vector<std::shared_ptr<libcdoc::EncKey>>& keys)
{
	last_error.clear();
	std::vector<uint8_t> fmk = libcdoc::Crypto::extract(libcdoc::Crypto::random(CDoc2Reader::KEY_LEN), std::vector<uint8_t>(CDoc2Reader::SALT.cbegin(), CDoc2Reader::SALT.cend()));
	std::vector<uint8_t> cek = libcdoc::Crypto::expand(fmk, std::vector<uint8_t>(CDoc2Reader::CEK.cbegin(), CDoc2Reader::CEK.cend()));
	std::vector<uint8_t> hhk = libcdoc::Crypto::expand(fmk, std::vector<uint8_t>(CDoc2Reader::HMAC.cbegin(), CDoc2Reader::HMAC.cend()));
#ifndef NDEBUG
	std::cerr << "fmk: " << libcdoc::Crypto::toHex(fmk) << std::endl;
	std::cerr << "cek: " << libcdoc::Crypto::toHex(cek) << std::endl;
	std::cerr << "hhk: " << libcdoc::Crypto::toHex(hhk) << std::endl;
#endif

	flatbuffers::FlatBufferBuilder builder;
	std::vector<flatbuffers::Offset<cdoc20::header::RecipientRecord>> recipients;

	auto toVector = [&builder](const std::vector<uint8_t> &data) {
		return builder.CreateVector((const uint8_t*)data.data(), size_t(data.size()));
	};

	for(std::shared_ptr<libcdoc::EncKey> key: keys) {
		if (key->isPKI()) {
			const libcdoc::EncKeyPKI& pki = static_cast<const libcdoc::EncKeyPKI&>(*key);
			if(pki.pk_type == libcdoc::CKey::PKType::RSA) {
				std::vector<uint8_t> kek = libcdoc::Crypto::random(fmk.size());
				std::vector<uint8_t> xor_key = libcdoc::Crypto::xor_data(fmk, kek);
				auto publicKey = libcdoc::Crypto::fromRSAPublicKeyDer(pki.rcpt_key);
				if(!publicKey)
					return false;
				std::vector<uint8_t> encrytpedKek = libcdoc::Crypto::encrypt(publicKey.get(), RSA_PKCS1_OAEP_PADDING, kek);
	#ifndef NDEBUG
				std::cerr << "publicKeyDer" << libcdoc::Crypto::toHex(pki.rcpt_key) << std::endl;
				std::cerr << "kek" << libcdoc::Crypto::toHex(kek) << std::endl;
				std::cerr << "xor" << libcdoc::Crypto::toHex(xor_key) << std::endl;
				std::cerr << "encrytpedKek" << libcdoc::Crypto::toHex(encrytpedKek) << std::endl;
	#endif
				if(!conf->getBoolean(libcdoc::Configuration::USE_KEYSERVER)) {
					auto rsaPublicKey = cdoc20::recipients::CreateRSAPublicKeyCapsule(builder,
																					  toVector(pki.rcpt_key), toVector(encrytpedKek));
					auto offs = cdoc20::header::CreateRecipientRecord(builder,
																	  cdoc20::recipients::Capsule::RSAPublicKeyCapsule, rsaPublicKey.Union(),
																	  builder.CreateString(pki.label), toVector(xor_key), cdoc20::header::FMKEncryptionMethod::XOR);
					recipients.push_back(offs);
				} else {
					std::pair<std::string,std::string> result = network->sendKey(this, pki.rcpt_key, std::vector<uint8_t>(encrytpedKek.cbegin(), encrytpedKek.cend()), "rsa");
					if (result.second.empty()) return false;
					auto rsaKeyServer = cdoc20::recipients::CreateRsaKeyDetails(builder, toVector(pki.rcpt_key));
					auto keyServer = cdoc20::recipients::CreateKeyServerCapsule(builder,
																				cdoc20::recipients::KeyDetailsUnion::RsaKeyDetails,
																				rsaKeyServer.Union(), builder.CreateString(result.first), builder.CreateString(result.second));
					auto offs = cdoc20::header::CreateRecipientRecord(builder,
																	  cdoc20::recipients::Capsule::KeyServerCapsule, keyServer.Union(),
																	  builder.CreateString(pki.label), builder.CreateVector(xor_key), cdoc20::header::FMKEncryptionMethod::XOR);
					recipients.push_back(offs);
				}
			} else {
				auto publicKey = libcdoc::Crypto::fromECPublicKeyDer(pki.rcpt_key, NID_secp384r1);
				if(!publicKey) return false;
				auto ephKey = libcdoc::Crypto::genECKey(publicKey.get());
				std::vector<uint8_t> sharedSecret = libcdoc::Crypto::deriveSharedSecret(ephKey.get(), publicKey.get());
				std::vector<uint8_t> ephPublicKeyDer = libcdoc::Crypto::toPublicKeyDer(ephKey.get());
				std::vector<uint8_t> kekPm = libcdoc::Crypto::extract(sharedSecret, std::vector<uint8_t>(CDoc2Reader::KEKPREMASTER.cbegin(), CDoc2Reader::KEKPREMASTER.cend()));
				std::string info_str = CDoc2Reader::KEK +
						cdoc20::header::EnumNameFMKEncryptionMethod(cdoc20::header::FMKEncryptionMethod::XOR) +
						std::string(pki.rcpt_key.cbegin(), pki.rcpt_key.cend()) +
						std::string(ephPublicKeyDer.cbegin(), ephPublicKeyDer.cend());

				std::vector<uint8_t> kek = libcdoc::Crypto::expand(kekPm, std::vector<uint8_t>(info_str.cbegin(), info_str.cend()), fmk.size());
				std::vector<uint8_t> xor_key = libcdoc::Crypto::xor_data(fmk, kek);
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
																					  cdoc20::recipients::EllipticCurve::secp384r1, toVector(pki.rcpt_key), toVector(ephPublicKeyDer));
					auto offs = cdoc20::header::CreateRecipientRecord(builder,
																	  cdoc20::recipients::Capsule::ECCPublicKeyCapsule, eccPublicKey.Union(),
																	  builder.CreateString(pki.label), toVector(xor_key), cdoc20::header::FMKEncryptionMethod::XOR);
					recipients.push_back(offs);
				} else {
					std::pair<std::string,std::string> result = network->sendKey(this, pki.rcpt_key, ephPublicKeyDer, "ecc_secp384r1");
					if (result.second.empty()) return false;
					auto eccKeyServer = cdoc20::recipients::CreateEccKeyDetails(builder,
																				cdoc20::recipients::EllipticCurve::secp384r1, toVector(pki.rcpt_key));
					auto keyServer = cdoc20::recipients::CreateKeyServerCapsule(builder,
																				cdoc20::recipients::KeyDetailsUnion::EccKeyDetails,
																				eccKeyServer.Union(), builder.CreateString(result.first), builder.CreateString(result.second));
					auto offs = cdoc20::header::CreateRecipientRecord(builder,
																	  cdoc20::recipients::Capsule::KeyServerCapsule, keyServer.Union(),
																	  builder.CreateString(pki.label), toVector(xor_key), cdoc20::header::FMKEncryptionMethod::XOR);
					recipients.push_back(offs);
				}
			}
		} else if (key->isSymmetric()) {
			const libcdoc::EncKeySymmetric& sk = static_cast<const libcdoc::EncKeySymmetric&>(*key);
			std::string info_str = sk.getSaltForExpand();
			std::vector<uint8_t> kek(32);
			crypto->getKEK(kek, sk.salt, sk.pw_salt, sk.kdf_iter, sk.label, info_str);
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

				std::vector<uint8_t> xor_key = libcdoc::Crypto::xor_data(fmk, kek);

				auto capsule = cdoc20::recipients::CreatePBKDF2Capsule(builder, builder.CreateVector(sk.salt), builder.CreateVector(sk.pw_salt), cdoc20::recipients::KDFAlgorithmIdentifier::PBKDF2WithHmacSHA256, sk.kdf_iter);
				auto offs = cdoc20::header::CreateRecipientRecord(builder,
																  cdoc20::recipients::Capsule::PBKDF2Capsule, capsule.Union(),
																  builder.CreateString(sk.label), builder.CreateVector(xor_key), cdoc20::header::FMKEncryptionMethod::XOR);
				recipients.push_back(offs);
			} else {
				// KeyMaterialSalt_i = CSRNG()
//				std::vector<uint8_t> salt = libcdoc::Crypto::random();
				// KeyMaterialSalt_i = CSRNG()
				// KEK_i = HKDF(KeyMaterialSalt_i, S_i)
				//QByteArray info = KEK + cdoc20::header::EnumNameFMKEncryptionMethod(cdoc20::header::FMKEncryptionMethod::XOR) + QByteArray(label.data(), label.size());
//				std::vector<uint8_t> tmp = libcdoc::Crypto::extract(std::vector<uint8_t>(secret.cbegin(), secret.cend()), salt, 32);
//				std::vector<uint8_t> kek = libcdoc::Crypto::expand(tmp, std::vector<uint8_t>(info_str.cbegin(), info_str.cend()), 32);

				std::vector<uint8_t> xor_key = libcdoc::Crypto::xor_data(fmk, kek);

				auto capsule = cdoc20::recipients::CreateSymmetricKeyCapsule(builder, builder.CreateVector(sk.salt));
				auto offs = cdoc20::header::CreateRecipientRecord(builder,
																  cdoc20::recipients::Capsule::SymmetricKeyCapsule, capsule.Union(),
																  builder.CreateString(sk.label), builder.CreateVector(xor_key), cdoc20::header::FMKEncryptionMethod::XOR);
				recipients.push_back(offs);
			}
		} else {
			return false;
		}
	}

	auto offset = cdoc20::header::CreateHeader(builder, builder.CreateVector(recipients),
											   cdoc20::header::PayloadEncryptionMethod::CHACHA20POLY1305);
	builder.Finish(offset);

	std::vector<uint8_t> header(builder.GetBufferPointer(), builder.GetBufferPointer() + builder.GetSize());
	std::vector<uint8_t> headerHMAC = libcdoc::Crypto::sign_hmac(hhk, header);
	std::vector<uint8_t> nonce = libcdoc::Crypto::random(CDoc2Reader::NONCE_LEN);
#ifndef NDEBUG
	std::cerr << "hmac" << libcdoc::Crypto::toHex(headerHMAC) << std::endl;
	std::cerr << "nonce" << libcdoc::Crypto::toHex(nonce) << std::endl;
#endif
	libcdoc::Crypto::Cipher enc(EVP_chacha20_poly1305(), std::vector<uint8_t>(cek.cbegin(), cek.cend()), std::vector<uint8_t>(nonce.cbegin(), nonce.cend()), true);
	std::vector<uint8_t> aad(CDoc2Reader::PAYLOAD.cbegin(), CDoc2Reader::PAYLOAD.cend());
	aad.insert(aad.end(), header.cbegin(), header.cend());
	aad.insert(aad.end(), headerHMAC.cbegin(), headerHMAC.cend());
	enc.updateAAD(aad);
	uint32_t hs = uint32_t(header.size());
	uint8_t header_len[] {uint8_t(hs >> 24), uint8_t((hs >> 16) & 0xff), uint8_t((hs >> 8) & 0xff), uint8_t(hs & 0xff)};

	libcdoc::OStreamConsumer scons(&ofs);
	scons.write((const uint8_t *) CDoc2Reader::LABEL.data(), CDoc2Reader::LABEL.size());
	scons.write((const uint8_t *) &header_len, 4);
	scons.write(header.data(), header.size());
	scons.write(headerHMAC.data(), headerHMAC.size());
	scons.write(nonce.data(), nonce.size());
	libcdoc::CipherConsumer ccons(&scons, false, &enc);
	libcdoc::ZConsumer zcons(&ccons);
	if(!libcdoc::TAR::save(zcons, src)) {
		return false;
	}
	zcons.close();
	if(!enc.result()) {
		return false;
	}
	std::vector<uint8_t> tag = enc.tag();
#ifndef NDEBUG
	std::cerr << "tag" << libcdoc::Crypto::toHex(tag) << std::endl;
#endif
	scons.write(tag.data(), tag.size());
	scons.close();
#if 0
	ofs.write(CDoc2Reader::LABEL.data(), CDoc2Reader::LABEL.size());
	ofs.write((const char *) &header_len, 4);
	ofs.write((const char *) header.data(), header.size());
	ofs.write((const char *) headerHMAC.data(), headerHMAC.size());
	ofs.write((const char *) nonce.data(), nonce.size());
	libcdoc::zostream zofs(&ofs, &enc);
	if(!libcdoc::TAR::save(zofs, src)) {
		return false;
	}
	zofs.close();
	if(!enc.result()) {
		return false;
	}
	std::vector<uint8_t> tag = enc.tag();
#ifndef NDEBUG
	std::cerr << "tag" << libcdoc::Crypto::toHex(tag) << std::endl;
#endif
	ofs.write((const char *) tag.data(), tag.size());
	ofs.flush();
#endif
	return true;
}
