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

bool
CryptoBackend::getKeyMaterial(std::vector<uint8_t>& key_material, const std::vector<uint8_t> pw_salt, int32_t kdf_iter, const std::string& label)
{
	if (kdf_iter > 0) {
		std::vector<uint8_t> secret;
		if (!getSecret(secret, label)) return false;
		std::cerr << "Secret: " << Crypto::toHex(secret) << std::endl;
		key_material = libcdoc::Crypto::pbkdf2_sha256(secret, pw_salt, kdf_iter);
		std::fill(secret.begin(), secret.end(), 0);
	} else {
		if (!getSecret(key_material, label)) return false;
	}
	std::cerr << "Key material: " << Crypto::toHex(key_material) << std::endl;
	return !key_material.empty();
}

bool
CryptoBackend::getKEK(std::vector<uint8_t>& kek, const std::vector<uint8_t>& salt, const std::vector<uint8_t> pw_salt, int32_t kdf_iter,
			const std::string& label, const std::string& info)
{
	std::vector<uint8_t> key_material;
	if (!getKeyMaterial(key_material, pw_salt, kdf_iter, label)) return false;
	std::vector<uint8_t> tmp = libcdoc::Crypto::extract(key_material, salt, 32);
	std::fill(key_material.begin(), key_material.end(), 0);
	std::cerr << "Extract: " << Crypto::toHex(tmp) << std::endl;
	kek = libcdoc::Crypto::expand(tmp, std::vector<uint8_t>(info.cbegin(), info.cend()), 32);
	std::cerr << "KEK: " << Crypto::toHex(kek) << std::endl;
	return !kek.empty();
}

struct TempListConsumer : public libcdoc::MultiDataConsumer {
	static constexpr int64_t MAX_VEC_SIZE = 500L * 1024L * 1024L;

	size_t _max_memory_size;
	std::vector<libcdoc::IOEntry> files;
	explicit TempListConsumer(size_t max_memory_size = 500L * 1024L * 1024L) : _max_memory_size(max_memory_size) {}
	~TempListConsumer();
	size_t write(const uint8_t *src, size_t size) override final;
	bool close() override final;
	bool isError() override final;
	bool open(const std::string& name, int64_t size) override final;
private:
	std::ostream *ofs = nullptr;

	std::stringstream *sstream = nullptr;
	std::ofstream *fstream = nullptr;
	std::string tmp_name;
};

TempListConsumer::~TempListConsumer()
{
	if (ofs) delete ofs;
}

size_t
TempListConsumer::write(const uint8_t *src, size_t size)
{
	if (!ofs) return 0;
	libcdoc::IOEntry& file = files.back();
	ofs->write((const char *) src, size);
	file.size += size;
	return size;
}

bool
TempListConsumer::close()
{
	libcdoc::IOEntry& file = files.back();
	if (fstream) {
		fstream->close();
		file.stream = std::make_shared<std::ifstream>(tmp_name);
		fstream = nullptr;
		ofs = nullptr;
		return true;
	} else if (sstream) {
		file.stream = std::shared_ptr<std::istream>(sstream);
		file.stream->seekg(0);
		sstream = nullptr;
		ofs = nullptr;
		return true;
	} else {
		return false;
	}
}

bool
TempListConsumer::isError()
{
	return sstream && sstream->bad();
}

bool
TempListConsumer::open(const std::string& name, int64_t size)
{
	if (ofs) return false;
	files.push_back({name, {}, "application/octet-stream", 0, nullptr});
	if ((size < 0) || (size > MAX_VEC_SIZE)) {
		char name[L_tmpnam];
		// fixme:
		std::tmpnam(name);
		fstream = new std::ofstream(name);
		ofs = fstream;
	} else {
		sstream = new std::stringstream(std::ios_base::out | std::ios_base::in);
		ofs = sstream;
	}
	return true;
}

std::vector<IOEntry> CDocReader::decryptPayload(const std::vector<uint8_t> &fmk)
{
	TempListConsumer cons;
	if (!decryptPayload(fmk, &cons)) return {};
	return std::move(cons.files);
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

bool
CDocWriter::encrypt(const std::string& filename, const std::vector<IOEntry>& files, const std::vector<std::shared_ptr<libcdoc::EncKey>>& keys)
{
	std::ofstream ofs(filename, std::ios_base::binary);
	if (ofs.bad()) return false;
	StreamListSource slsrc(files);
	bool result = encrypt(ofs, slsrc, keys);
	ofs.close();
	if (!result) {
		std::filesystem::remove(std::filesystem::path(filename));
	}
	return result;
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
