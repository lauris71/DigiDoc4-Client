#include <fstream>

#include "CDOC1Writer.h"
#include "cdoc2.h"
#include <Crypto.h>
#include <iostream>
#include "CDOC1Reader.h"


#include "cdoc.h"

namespace libcdoc {

bool
Configuration::getBoolean(const std::string& param)
{
	std::string val = getValue(param);
	return val == "true";
}

std::string
CryptoBackend::getLastErrorStr(int code) const
{
	switch (code) {
	case OK:
		return "";
	case NOT_IMPLEMENTED:
		return "CryptoBackend: Method not implemented";
	case INVALID_PARAMS:
		return "CryptoBackend: Invalid parameters";
	case OPENSSL_ERROR:
		return "CryptoBackend: OpenSSL error";
	default:
		break;
	}
	return "Internal error";
}

int
CryptoBackend::deriveConcatKDF(std::vector<uint8_t>& dst, const std::vector<uint8_t> &publicKey, const std::string &digest, int keySize,
	const std::vector<uint8_t> &algorithmID, const std::vector<uint8_t> &partyUInfo, const std::vector<uint8_t> &partyVInfo)
{
	std::vector<uint8_t> shared_secret;
	int result = derive(shared_secret, publicKey);
	if (result != OK) return result;
	dst = libcdoc::Crypto::concatKDF(digest, keySize, shared_secret, algorithmID, partyUInfo, partyVInfo);
	return (dst.empty()) ? OPENSSL_ERROR : OK;
}

int
CryptoBackend::getKeyMaterial(std::vector<uint8_t>& key_material, const std::vector<uint8_t> pw_salt, int32_t kdf_iter, const std::string& label)
{
	if (kdf_iter > 0) {
		if (pw_salt.empty()) return INVALID_PARAMS;
		std::vector<uint8_t> secret;
		int result = getSecret(secret, label);
		if (result < 0) return result;
#ifdef LOCAL_DEBUG
		std::cerr << "Secret: " << Crypto::toHex(secret) << std::endl;
#endif
		key_material = libcdoc::Crypto::pbkdf2_sha256(secret, pw_salt, kdf_iter);
		std::fill(secret.begin(), secret.end(), 0);
		if (key_material.empty()) return OPENSSL_ERROR;
	} else {
		int result = getSecret(key_material, label);
		if (result < 0) return result;
	}
#ifdef LOCAL_DEBUG
	std::cerr << "Key material: " << Crypto::toHex(key_material) << std::endl;
#endif
	return OK;
}

int
CryptoBackend::getKEK(std::vector<uint8_t>& kek, const std::vector<uint8_t>& salt, const std::vector<uint8_t> pw_salt, int32_t kdf_iter,
			const std::string& label, const std::string& expand_salt)
{
	if (salt.empty() || expand_salt.empty()) return INVALID_PARAMS;
	if ((kdf_iter > 0) && pw_salt.empty()) return INVALID_PARAMS;
	std::vector<uint8_t> key_material;
	int result = getKeyMaterial(key_material, pw_salt, kdf_iter, label);
	if (result) return result;
	std::vector<uint8_t> tmp = libcdoc::Crypto::extract(key_material, salt, 32);
	std::fill(key_material.begin(), key_material.end(), 0);
	if (tmp.empty()) return OPENSSL_ERROR;
#ifdef LOCAL_DEBUG
	std::cerr << "Extract: " << Crypto::toHex(tmp) << std::endl;
#endif
	kek = libcdoc::Crypto::expand(tmp, std::vector<uint8_t>(expand_salt.cbegin(), expand_salt.cend()), 32);
	if (kek.empty()) return OPENSSL_ERROR;
#ifdef LOCAL_DEBUG
	std::cerr << "KEK: " << Crypto::toHex(kek) << std::endl;
#endif
	return OK;
}

std::string
NetworkBackend::getLastErrorStr(int code) const
{
	switch (code) {
	case OK:
		return "";
	case NOT_IMPLEMENTED:
		return "NetworkBackend: Method not implemented";
	case INVALID_PARAMS:
		return "NetworkBackend: Invalid parameters";
	case NETWORK_ERROR:
		return "NetworkBackend: Network error";
	default:
		break;
	}
	return "Internal error";
}

int
CDocReader::getCDocFileVersion(const std::string& path)
{
	if (CDoc2Reader::isCDoc2File(path)) return 2;
	// fixme: better check
	static const std::string XML_TAG("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
	std::vector<char>buf(XML_TAG.size());
	std::ifstream ifs(path);
	if (!ifs.is_open()) return -1;
	ifs.read(buf.data(), XML_TAG.size());
	if (ifs.gcount() != XML_TAG.size()) return -1;
	if (XML_TAG.compare(0, XML_TAG.size(), buf.data())) return -1;
	return 1;
}

CDocReader *
CDocReader::createReader(const std::string& path, Configuration *conf, CryptoBackend *crypto, NetworkBackend *network)
{
	int version = getCDocFileVersion(path);
	CDocReader *reader;
	if (version == 1) {
		reader = new CDOC1Reader(path);
	} else if (version == 2) {
		reader = new CDoc2Reader(path);
	} else {
		return nullptr;
	}
	reader->conf = conf;
	reader->crypto = crypto;
	reader->network = network;
	return reader;
}

CDocWriter *
CDocWriter::createWriter(int version, const std::string& filename, Configuration *conf, CryptoBackend *crypto, NetworkBackend *network)
{
	CDocWriter *writer;
	if (version == 1) {
		writer = new CDOC1Writer();
	} else if (version == 2) {
		writer = new CDoc2Writer();
	} else {
		return nullptr;
	}
	writer->conf = conf;
	writer->crypto = crypto;
	writer->network = network;
	return writer;
}


}; // namespace libcdoc
