#ifndef CDOC2_H
#define CDOC2_H

#include <libcdoc/CDocReader.h>
#include <libcdoc/CDocWriter.h>

class CDoc2Reader final: public libcdoc::CDocReader {
public:
	static const std::string LABEL;
	static const std::string CEK, HMAC, KEK, KEKPREMASTER, PAYLOAD, SALT;
	static constexpr int KEY_LEN = 32, NONCE_LEN = 12;

	~CDoc2Reader() final;

	const std::vector<libcdoc::Lock *>& getLocks() override final { return locks; }
	const libcdoc::Lock *getDecryptionLock(const std::vector<uint8_t>& cert) final;
	int getFMK(std::vector<uint8_t>& fmk, const libcdoc::Lock *lock) override final;
	int decryptPayload(const std::vector<uint8_t>& fmk, libcdoc::MultiDataConsumer *consumer) override final;

	CDoc2Reader(libcdoc::DataSource *src, bool take_ownership = false);
	CDoc2Reader(const std::string &path);

	static bool isCDoc2File(const std::string& path);
private:
	std::vector<libcdoc::Lock *> locks;

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
	explicit CDoc2Writer();
	~CDoc2Writer();

	int beginEncryption(libcdoc::DataConsumer& dst) override final;
	int addRecipient(const libcdoc::Recipient& rcpt) override final;
	int addFile(const std::string& name, size_t size) override final;
	int writeData(const uint8_t *src, size_t size) override final;
	int finishEncryption(bool close_dst = true) override final;

	int encrypt(libcdoc::DataConsumer& dst, libcdoc::MultiDataSource& src, const std::vector<libcdoc::Recipient>& keys) override final;
private:
	struct Private;

	std::string last_error;
	std::unique_ptr<Private> priv;

	int encryptInternal(libcdoc::MultiDataSource& src, const std::vector<libcdoc::Recipient>& keys);
	int writeHeader(const std::vector<uint8_t>& header, const std::vector<uint8_t>& hhk);
	int buildHeader(std::vector<uint8_t>& header, const std::vector<libcdoc::Recipient>& keys, const std::vector<uint8_t>& fmk);
};

#endif // CDOC2_H
