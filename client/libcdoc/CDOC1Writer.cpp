#define __CDOC1WRITER_CPP__

#include <fstream>

#include "Crypto.h"
#include "DDOCWriter.h"
#include <utils.h>
#include "XMLWriter.h"

#include <openssl/x509.h>

#include "CDOC1Writer.h"

#define SCOPE(TYPE, VAR, DATA) std::unique_ptr<TYPE,decltype(&TYPE##_free)> VAR(DATA, TYPE##_free)

/**
 * @class CDOC1Writer
 * @brief CDOC1Writer is used for encrypt data.
 */

class CDOC1Writer::Private
{
public:
	static const XMLWriter::NS DENC, DS, XENC11, DSIG11;
	std::string method, documentFormat = "ENCDOC-XML|1.1", lastError;
	bool writeRecipient(XMLWriter *xmlw, const std::vector<uchar> &recipient, libcdoc::Crypto::Key transportKey);
};

const XMLWriter::NS CDOC1Writer::Private::DENC{ "denc", "http://www.w3.org/2001/04/xmlenc#" };
const XMLWriter::NS CDOC1Writer::Private::DS{ "ds", "http://www.w3.org/2000/09/xmldsig#" };
const XMLWriter::NS CDOC1Writer::Private::XENC11{ "xenc11", "http://www.w3.org/2009/xmlenc11#" };
const XMLWriter::NS CDOC1Writer::Private::DSIG11{ "dsig11", "http://www.w3.org/2009/xmldsig11#" };

/**
 * CDOC1Writer constructor.
 * @param method Encrypton method to be used
 */
CDOC1Writer::CDOC1Writer(const std::string &method)
	: CDocWriter(), d(new Private())
{
	d->method = method;
}

CDOC1Writer::~CDOC1Writer()
{
	delete d;
}

bool CDOC1Writer::Private::writeRecipient(XMLWriter *xmlw, const std::vector<uchar> &recipient, libcdoc::Crypto::Key transportKey)
{
	SCOPE(X509, peerCert, libcdoc::Crypto::toX509(recipient));
	if(!peerCert)
		return false;
	std::string cn = [&]{
		std::string cn;
		X509_NAME *name = X509_get_subject_name(peerCert.get());
		if(!name)
			return cn;
		int pos = X509_NAME_get_index_by_NID(name, NID_commonName, 0);
		if(pos == -1)
			return cn;
		X509_NAME_ENTRY *e = X509_NAME_get_entry(name, pos);
		if(!e)
			return cn;
		char *data = nullptr;
		int size = ASN1_STRING_to_UTF8((uchar**)&data, X509_NAME_ENTRY_get_data(e));

		cn.assign(data, size_t(size));
		OPENSSL_free(data);
		return cn;
	}();
	xmlw->writeElement(Private::DENC, "EncryptedKey", {{"Recipient", cn}}, [&]{
		std::vector<uchar> encryptedData;
		SCOPE(EVP_PKEY, peerPKey, X509_get_pubkey(peerCert.get()));
		switch(EVP_PKEY_base_id(peerPKey.get()))
		{
		case EVP_PKEY_RSA:
		{
			SCOPE(RSA, rsa, EVP_PKEY_get1_RSA(peerPKey.get()));
			encryptedData.resize(size_t(RSA_size(rsa.get())));
			RSA_public_encrypt(int(transportKey.key.size()), transportKey.key.data(),
				encryptedData.data(), rsa.get(), RSA_PKCS1_PADDING);
			xmlw->writeElement(Private::DENC, "EncryptionMethod", {{"Algorithm", libcdoc::Crypto::RSA_MTH}});
			xmlw->writeElement(Private::DS, "KeyInfo", [&]{
				xmlw->writeElement(Private::DS, "X509Data", [&]{
					xmlw->writeBase64Element(Private::DS, "X509Certificate", recipient);
				});
			});
			break;
		}
		case EVP_PKEY_EC:
		{
			SCOPE(EC_KEY, peerECKey, EVP_PKEY_get1_EC_KEY(peerPKey.get()));
			int curveName = EC_GROUP_get_curve_name(EC_KEY_get0_group(peerECKey.get()));
			SCOPE(EC_KEY, priv, EC_KEY_new_by_curve_name(curveName));
			EC_KEY_generate_key(priv.get());
			SCOPE(EVP_PKEY, pkey, EVP_PKEY_new());
			EVP_PKEY_set1_EC_KEY(pkey.get(), priv.get());
			std::vector<uchar> sharedSecret = libcdoc::Crypto::deriveSharedSecret(pkey.get(), peerPKey.get());

			std::string oid(50, 0);
			oid.resize(size_t(OBJ_obj2txt(&oid[0], int(oid.size()), OBJ_nid2obj(curveName), 1)));
			std::vector<uchar> SsDer(size_t(i2d_PublicKey(pkey.get(), nullptr)), 0);
			uchar *p = SsDer.data();
			i2d_PublicKey(pkey.get(), &p);

			std::string encryptionMethod = libcdoc::Crypto::KWAES256_MTH;
			std::string concatDigest = libcdoc::Crypto::SHA384_MTH;
			switch ((SsDer.size() - 1) / 2) {
			case 32: concatDigest = libcdoc::Crypto::SHA256_MTH; break;
			case 48: concatDigest = libcdoc::Crypto::SHA384_MTH; break;
			default: concatDigest = libcdoc::Crypto::SHA512_MTH; break;
			}

			std::vector<uchar> AlgorithmID(documentFormat.cbegin(), documentFormat.cend());
			std::vector<uchar> encryptionKey = libcdoc::Crypto::concatKDF(concatDigest, libcdoc::Crypto::keySize(encryptionMethod), sharedSecret,
				AlgorithmID, SsDer, recipient);
			encryptedData = libcdoc::Crypto::AESWrap(encryptionKey, transportKey.key, true);

#ifndef NDEBUG
			printf("Ss %s\n", libcdoc::Crypto::toHex(SsDer).c_str());
			printf("Ksr %s\n", libcdoc::Crypto::toHex(sharedSecret).c_str());
			printf("ConcatKDF %s\n", libcdoc::Crypto::toHex(encryptionKey).c_str());
			printf("iv %s\n", libcdoc::Crypto::toHex(transportKey.iv).c_str());
			printf("transport %s\n", libcdoc::Crypto::toHex(transportKey.key).c_str());
#endif

			xmlw->writeElement(Private::DENC, "EncryptionMethod", {{"Algorithm", encryptionMethod}});
			xmlw->writeElement(Private::DS, "KeyInfo", [&]{
				xmlw->writeElement(Private::DENC, "AgreementMethod", {{"Algorithm", libcdoc::Crypto::AGREEMENT_MTH}}, [&]{
					xmlw->writeElement(Private::XENC11, "KeyDerivationMethod", {{"Algorithm", libcdoc::Crypto::CONCATKDF_MTH}}, [&]{
						xmlw->writeElement(Private::XENC11, "ConcatKDFParams", {
							{"AlgorithmID", "00" + libcdoc::Crypto::toHex(AlgorithmID)},
							{"PartyUInfo", "00" + libcdoc::Crypto::toHex(SsDer)},
							{"PartyVInfo", "00" + libcdoc::Crypto::toHex(recipient)}}, [&]{
							xmlw->writeElement(Private::DS, "DigestMethod", {{"Algorithm", concatDigest}});
						});
					});
					xmlw->writeElement(Private::DENC, "OriginatorKeyInfo", [&]{
						xmlw->writeElement(Private::DS, "KeyValue", [&]{
							xmlw->writeElement(Private::DSIG11, "ECKeyValue", [&]{
								xmlw->writeElement(Private::DSIG11, "NamedCurve", {{"URI", "urn:oid:" + oid}});
								xmlw->writeBase64Element(Private::DSIG11, "PublicKey", SsDer);
							});
						});
					});
					xmlw->writeElement(Private::DENC, "RecipientKeyInfo", [&]{
						xmlw->writeElement(Private::DS, "X509Data", [&]{
							xmlw->writeBase64Element(Private::DS, "X509Certificate", recipient);
						});
					});
				});
			 });
			break;
		}
		default: break;
		}
		xmlw->writeElement(Private::DENC, "CipherData", [&]{
			xmlw->writeBase64Element(Private::DENC, "CipherValue", encryptedData);
		});
	});
	return true;
}

/**
 * Encrypt data
 */
bool CDOC1Writer::encrypt(std::ostream& ofs, libcdoc::MultiDataSource& src, const std::vector<std::shared_ptr<libcdoc::EncKey>>& keys)
{
	libcdoc::Crypto::Key transportKey = libcdoc::Crypto::generateKey(d->method);
	XMLWriter *xmlw = new XMLWriter(&ofs);
	xmlw->writeStartElement(Private::DENC, "EncryptedData", {{"MimeType", src.getNumComponents() > 1 ? "http://www.sk.ee/DigiDoc/v1.3.0/digidoc.xsd" : "application/octet-stream"}});
	xmlw->writeElement(Private::DENC, "EncryptionMethod", {{"Algorithm", d->method}});
	xmlw->writeStartElement(Private::DS, "KeyInfo", {});
	for (const std::shared_ptr<libcdoc::EncKey>& key : keys) {
		if (!key->isCertificate()) {
			d->lastError = "Invalid key type";
			return false;
		}
		const std::shared_ptr<libcdoc::EncKeyCert> ckey = std::static_pointer_cast<libcdoc::EncKeyCert>(key);
		if(!d->writeRecipient(xmlw, ckey->cert, transportKey)) {
			d->lastError = "Failed to write Recipient info";
			return false;
		}
	}
	xmlw->writeEndElement(Private::DS); // KeyInfo

	std::vector<libcdoc::MultiDataSource::File> files;
	xmlw->writeElement(Private::DENC, "CipherData", [&]{
		if(src.getNumComponents() > 1) {
			std::vector<uint8_t> data(4096);
			DDOCWriter ddoc(data);
			libcdoc::MultiDataSource::File file;
			while (src.next(file)) {
				files.push_back(file);
				std::vector<uint8_t> data;
				libcdoc::VectorConsumer vcons(data);
				src.readAll(vcons);
				ddoc.addFile(file.name, "application/octet-stream", data);
			}
			ddoc.close();
			libcdoc::vectorwrapbuf databuf(data);
			std::istream in(&databuf);
			xmlw->writeBase64Element(Private::DENC, "CipherValue", libcdoc::Crypto::encrypt(d->method, transportKey, in));
		} else if (src.getNumComponents() == 1) {
			libcdoc::MultiDataSource::File file;
			src.next(file);
			std::vector<uint8_t> data;
			libcdoc::VectorConsumer vcons(data);
			src.readAll(vcons);
			libcdoc::vectorwrapbuf databuf(data);
			std::istream in(&databuf);
			xmlw->writeBase64Element(Private::DENC, "CipherValue", libcdoc::Crypto::encrypt(d->method, transportKey, in));
		}
	});
	xmlw->writeElement(Private::DENC, "EncryptionProperties", [&]{
		xmlw->writeTextElement(Private::DENC, "EncryptionProperty", {{"Name", "LibraryVersion"}}, "cdoc|0.0.1");
		xmlw->writeTextElement(Private::DENC, "EncryptionProperty", {{"Name", "DocumentFormat"}}, d->documentFormat);
		xmlw->writeTextElement(Private::DENC, "EncryptionProperty", {{"Name", "Filename"}}, files.size() == 1 ? files.at(0).name : "tmp.ddoc");
		for(const libcdoc::MultiDataSource::File &file: files)
		{
			xmlw->writeTextElement(Private::DENC, "EncryptionProperty", {{"Name", "orig_file"}},
				file.name + "|" + std::to_string(file.size) + "|" + "application/octet-stream" + "|D0");
		}
	});
	xmlw->writeEndElement(Private::DENC); // EncryptedData
	xmlw->close();
	return true;
}
