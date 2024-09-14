#define __CDOC1_READER_CPP__

#include <iostream>
#include <map>
#include <set>

#include <openssl/x509.h>

#include "certificate.h"
#define __CDOC1WRITER_CPP__

#include "Crypto.h"
#include "DDOCReader.h"
#include "Token.h"
#include "XMLReader.h"
#include "zstream.h"

#include "CDOC1Reader.h"

static const std::string MIME_ZLIB = "http://www.isi.edu/in-noes/iana/assignments/media-types/application/zip";
static const std::string MIME_DDOC = "http://www.sk.ee/DigiDoc/v1.3.0/digidoc.xsd";
static const std::string MIME_DDOC_OLD = "http://www.sk.ee/DigiDoc/1.3.0/digidoc.xsd";

#define SCOPE(TYPE, VAR, DATA) std::unique_ptr<TYPE,decltype(&TYPE##_free)> VAR(DATA, TYPE##_free)

static const std::set<std::string> SUPPORTED_METHODS = {
	libcdoc::Crypto::AES128CBC_MTH, libcdoc::Crypto::AES192CBC_MTH, libcdoc::Crypto::AES256CBC_MTH, libcdoc::Crypto::AES128GCM_MTH, libcdoc::Crypto::AES192GCM_MTH, libcdoc::Crypto::AES256GCM_MTH
};

const std::set<std::string> SUPPORTED_KWAES = {
	libcdoc::Crypto::KWAES128_MTH, libcdoc::Crypto::KWAES192_MTH, libcdoc::Crypto::KWAES256_MTH
};

/**
 * @class CDOC1Reader
 * @brief CDOC1Reader is used for decrypt data.
 */

class CDOC1Reader::Private
{
public:
	struct Key
	{
		std::string id, recipient, name;
		std::string method, agreement, derive, concatDigest;
		std::vector<uchar> cert, publicKey, cipher;
		std::vector<uchar> AlgorithmID, PartyUInfo, PartyVInfo;
	};
	struct File
	{
		std::string name, size, mime, id;
	};

	std::string file, mime, method;
	std::vector<Key> _keys;
	std::vector<std::shared_ptr<libcdoc::CKey>> keys;
	std::vector<File> files;
	std::map<std::string,std::string> properties;
};

libcdoc::CKey::DecryptionStatus
CDOC1Reader::canDecrypt(const libcdoc::Certificate &cert) {
	if(getDecryptionKey(cert)) {
		return libcdoc::CKey::DecryptionStatus::CAN_DECRYPT;
	}
	return libcdoc::CKey::DecryptionStatus::CANNOT_DECRYPT;
}

std::shared_ptr<libcdoc::CKey>
CDOC1Reader::getDecryptionKey(const libcdoc::Certificate &cert)
{
	if (!SUPPORTED_METHODS.contains(d->method)) return {};
	for(std::shared_ptr<libcdoc::CKey> key: d->keys) {
		if (key->type != libcdoc::CKey::Type::CDOC1) continue;
		const libcdoc::CKeyCDoc1 *k = (libcdoc::CKeyCDoc1 *) key.get();
		if(k->cert != cert.cert || k->encrypted_fmk.empty()) continue;
		if(cert.getAlgorithm() == libcdoc::Certificate::RSA &&
			k->method == libcdoc::Crypto::RSA_MTH)
			return key;
		if(cert.getAlgorithm() == libcdoc::Certificate::ECC &&
			!k->publicKey.empty() &&
			SUPPORTED_KWAES.contains(k->method))
			return key;
	}
	return {};
}

std::vector<uint8_t>
CDOC1Reader::getFMK(const libcdoc::CKey &key)
{
	if (key.type != libcdoc::CKey::Type::CDOC1) {
		setLastError(t_("Not a CDoc1 key"));
		return {};
	}
	const libcdoc::CKeyCDoc1& ckey = static_cast<const libcdoc::CKeyCDoc1&>(key);
	setLastError({});
	std::vector<uint8_t> decrypted_key;
	if (ckey.pk_type == libcdoc::CKey::PKType::RSA) {
		decrypted_key = crypto->decryptRSA(ckey.encrypted_fmk, false);
	} else {
		decrypted_key = crypto->deriveConcatKDF(ckey.publicKey, ckey.concatDigest,
				libcdoc::Crypto::keySize(ckey.method), ckey.AlgorithmID, ckey.PartyUInfo, ckey.PartyVInfo);
	}
	if(decrypted_key.empty()) {
		setLastError(t_("Failed to decrypt/derive key"));
		return {};
	}
	if(ckey.pk_type == libcdoc::CKey::PKType::RSA) {
		return decrypted_key;
	} else {
		return libcdoc::Crypto::AESWrap(decrypted_key, ckey.encrypted_fmk, false);
	}
}

bool
CDOC1Reader::decryptPayload(const std::vector<uint8_t>& fmk, libcdoc::MultiDataConsumer *dst)
{
	std::vector<uint8_t> data = this->decryptData(fmk);
	std::string mime = d->mime;
	if (d->mime == MIME_ZLIB) {
		libcdoc::VectorSource vsrc(data);
		libcdoc::ZSource zsrc(&vsrc);
		std::vector<uint8_t> tmp;
		libcdoc::VectorConsumer vcons(tmp);
		vcons.writeAll(&zsrc);
		data = std::move(tmp);
		mime = d->properties["OriginalMimeType"];
	}
	libcdoc::VectorSource vsrc(data);
	if(mime == MIME_DDOC || mime == MIME_DDOC_OLD) {
		std::cerr << "Contains DDoc content" << mime;
		DDOCReader::parse(&vsrc, dst);
		return true;
	}
	dst->open(d->properties["Filename"], data.size());
	dst->writeAll(&vsrc);
	dst->close();
	return true;
}

const std::vector<std::shared_ptr<libcdoc::CKey>>&
CDOC1Reader::getKeys()
{
	return d->keys;
}

#if 0
const std::vector<libcdoc::CDoc::File>&
CDOC1Reader::getFiles()
{
	return d->cdfiles;
}
#endif

/**
 * CDOC1Reader constructor.
 * @param file File to open reading
 */
CDOC1Reader::CDOC1Reader(const std::string &file)
	: CDocReader(), d(new Private)
{
	d->file = file;
	auto hex2bin = [](const std::string &in) {
		std::vector<uchar> out;
		char data[] = "00";
		for(std::string::const_iterator i = in.cbegin(); distance(i, in.cend()) >= 2;)
		{
			data[0] = *(i++);
			data[1] = *(i++);
			out.push_back(static_cast<uchar>(strtoul(data, 0, 16)));
		}
		if(out[0] == 0x00)
			out.erase(out.cbegin());
		return out;
	};

	XMLReader reader(file);
	while (reader.read()) {
		if(reader.isEndElement())
			continue;
		// EncryptedData
		else if(reader.isElement("EncryptedData"))
			d->mime = reader.attribute("MimeType");
		// EncryptedData/EncryptionMethod
		else if(reader.isElement("EncryptionMethod"))
			d->method = reader.attribute("Algorithm");
		// EncryptedData/EncryptionProperties/EncryptionProperty
		else if(reader.isElement("EncryptionProperty"))
		{
			std::string attr = reader.attribute("Name");
			std::string value = reader.readText();
			if(attr == "orig_file")
			{
				Private::File file;
				size_t pos = 0, oldpos = 0;
				file.name = value.substr(oldpos, (pos = value.find("|", oldpos)) - oldpos);
				oldpos = pos + 1;
				file.size = value.substr(oldpos, (pos = value.find("|", oldpos)) - oldpos);
				oldpos = pos + 1;
				file.mime = value.substr(oldpos, (pos = value.find("|", oldpos)) - oldpos);
				oldpos = pos + 1;
				file.id = value.substr(oldpos, (pos = value.find("|", oldpos)) - oldpos);
				d->files.push_back(file);
			}
			else
				d->properties[attr] = value;
		}
		// EncryptedData/KeyInfo/EncryptedKey
		else if(reader.isElement("EncryptedKey"))
		{
			std::shared_ptr<libcdoc::CKeyCDoc1> key = std::make_shared<libcdoc::CKeyCDoc1>();
			//key.id = reader.attribute("Id");
			key->label = reader.attribute("Recipient");
			while(reader.read())
			{
				if(reader.isElement("EncryptedKey") && reader.isEndElement())
					break;
				else if(reader.isEndElement())
					continue;
				// EncryptedData/KeyInfo/KeyName
				//if(reader.isElement("KeyName"))
				//	key.name = reader.readText();
				// EncryptedData/KeyInfo/EncryptedKey/EncryptionMethod
				else if(reader.isElement("EncryptionMethod"))
					key->method = reader.attribute("Algorithm");
				// EncryptedData/KeyInfo/EncryptedKey/KeyInfo/AgreementMethod
				//else if(reader.isElement("AgreementMethod"))
				//	key.agreement = reader.attribute("Algorithm");
				// EncryptedData/KeyInfo/EncryptedKey/KeyInfo/AgreementMethod/KeyDerivationMethod
				//else if(reader.isElement("KeyDerivationMethod"))
				//	key.derive = reader.attribute("Algorithm");
				// EncryptedData/KeyInfo/EncryptedKey/KeyInfo/AgreementMethod/KeyDerivationMethod/ConcatKDFParams
				else if(reader.isElement("ConcatKDFParams"))
				{
					key->AlgorithmID = hex2bin(reader.attribute("AlgorithmID"));
					key->PartyUInfo = hex2bin(reader.attribute("PartyUInfo"));
					key->PartyVInfo = hex2bin(reader.attribute("PartyVInfo"));
				}
				// EncryptedData/KeyInfo/EncryptedKey/KeyInfo/AgreementMethod/KeyDerivationMethod/ConcatKDFParams/DigestMethod
				else if(reader.isElement("DigestMethod"))
					key->concatDigest = reader.attribute("Algorithm");
				// EncryptedData/KeyInfo/EncryptedKey/KeyInfo/AgreementMethod/OriginatorKeyInfo/KeyValue/ECKeyValue/PublicKey
				else if(reader.isElement("PublicKey"))
					key->publicKey = reader.readBase64();
				// EncryptedData/KeyInfo/EncryptedKey/KeyInfo/X509Data/X509Certificate
				else if(reader.isElement("X509Certificate"))
					key->cert = reader.readBase64();
				// EncryptedData/KeyInfo/EncryptedKey/KeyInfo/CipherData/CipherValue
				else if(reader.isElement("CipherValue"))
					key->encrypted_fmk = reader.readBase64();
			}
			d->keys.push_back(key);
		}
	}
}

CDOC1Reader::~CDOC1Reader()
{
	delete d;
}

/**
 * Returns decrypted mime type
 */
std::string CDOC1Reader::mimeType() const
{
	return d->mime;
}

/**
 * Returns decrypted filename
 */
std::string CDOC1Reader::fileName() const
{
	return d->properties["Filename"];
}

/**
 * Returns decrypted data
 * @param key Transport key to used for decrypt data
 */
std::vector<uchar> CDOC1Reader::decryptData(const std::vector<uchar> &key)
{
	XMLReader reader(d->file);
	std::vector<uchar> data;
	int skipKeyInfo = 0;
	while (reader.read()) {
		// EncryptedData/KeyInfo
		if(reader.isElement("KeyInfo") && reader.isEndElement())
			--skipKeyInfo;
		else if(reader.isElement("KeyInfo"))
			++skipKeyInfo;
		else if(skipKeyInfo > 0)
			continue;
		// EncryptedData/CipherData/CipherValue
		else if(reader.isElement("CipherValue"))
			return libcdoc::Crypto::decrypt(d->method, key, reader.readBase64());
	}

	return data;
}

/**
 * Returns decrypted data
 * @param token Token to be used for decrypting data
 */
std::vector<uchar> CDOC1Reader::decryptData(Token *token)
{
	const std::vector<uchar> &cert = token->cert();
	for(std::shared_ptr<libcdoc::CKey> &ck: d->keys)
	{
		libcdoc::CKeyCDoc1 *k = (libcdoc::CKeyCDoc1 *) ck.get();
		if (k->cert != cert)
			continue;

		SCOPE(X509, x509, libcdoc::Crypto::toX509(k->cert));
		SCOPE(EVP_PKEY, key, X509_get_pubkey(x509.get()));
		switch (EVP_PKEY_base_id(key.get()))
		{
		case EVP_PKEY_EC:
		{
			std::vector<uchar> derived = token->deriveConcatKDF(k->publicKey, k->concatDigest,
				libcdoc::Crypto::keySize(k->method), k->AlgorithmID, k->PartyUInfo, k->PartyVInfo);
#ifndef NDEBUG
			printf("Ss %s\n", libcdoc::Crypto::toHex(k->publicKey).c_str());
			printf("ConcatKDF %s\n", libcdoc::Crypto::toHex(derived).c_str());
#endif
			return decryptData(libcdoc::Crypto::AESWrap(derived, k->encrypted_fmk, false));
		}
		case EVP_PKEY_RSA:
			return decryptData(token->decrypt(k->encrypted_fmk));
		default:
			return std::vector<uchar>();
		}
	}
	return std::vector<uchar>();
}
