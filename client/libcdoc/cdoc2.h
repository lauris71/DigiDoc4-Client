#ifndef CDOC2_H
#define CDOC2_H

#include <libcdoc/cdoc.h>

class CDoc2Reader final: public libcdoc::CDocReader {
public:
	static const std::string LABEL;
	static const std::string CEK, HMAC, KEK, KEKPREMASTER, PAYLOAD, SALT;
	static constexpr int KEY_LEN = 32, NONCE_LEN = 12;

	CDoc2Reader(libcdoc::DataSource *src, bool take_ownership = false);
	CDoc2Reader(const std::string &path);

	static bool isCDoc2File(const std::string& path);

	uint32_t getVersion() override final { return 2; }
	libcdoc::CKey::DecryptionStatus canDecrypt(const libcdoc::Certificate &cert) final;
	std::shared_ptr<libcdoc::CKey> getDecryptionKey(const libcdoc::Certificate &cert) final;

	bool decryptPayload(const std::vector<uint8_t>& fmk, libcdoc::MultiDataConsumer *consumer) override final;

	const std::vector<std::shared_ptr<libcdoc::CKey>>& getKeys() override final { return keys; }

	std::vector<uint8_t> getFMK(const libcdoc::CKey &key, const std::vector<uint8_t>& secret) final;
private:
	std::vector<std::shared_ptr<libcdoc::CKey>> keys;

	//std::string path;
	libcdoc::DataSource *_src;
	bool _owned;
	size_t _nonce_pos;
	bool _at_nonce;

	std::vector<uint8_t> header_data, headerHMAC;
	//uint64_t noncePos = -1;
};

class CDoc2Writer final: public libcdoc::CDocWriter {
public:
	explicit CDoc2Writer() {};
	~CDoc2Writer() {};

	uint32_t getVersion() final { return 2; }
	bool encrypt(std::ostream& ofs, libcdoc::MultiDataSource& src, const std::vector<std::shared_ptr<libcdoc::EncKey>>& keys) override final;
private:
	std::string last_error;
};

#endif // CDOC2_H
