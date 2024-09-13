#pragma once

#include "CDOCExport.h"

#include <string>
#include <vector>

#include <libcdoc/cdoc.h>

class Token;

class CDOC_EXPORT CDOC1Reader : public libcdoc::CDocReader
{
public:
	CDOC1Reader(const std::string &file);
	~CDOC1Reader();

	uint32_t getVersion() override final { return 1; }
	libcdoc::CKey::DecryptionStatus canDecrypt(const libcdoc::Certificate &cert) override final;
	std::shared_ptr<libcdoc::CKey> getDecryptionKey(const libcdoc::Certificate &cert) override final;
	std::vector<uint8_t> getFMK(const libcdoc::CKey &key, const std::vector<uint8_t>& secret) override final;

	bool decryptPayload(const std::vector<uint8_t>& fmk, libcdoc::MultiDataConsumer *dst) override final;

	const std::vector<std::shared_ptr<libcdoc::CKey>>& getKeys() override;
	//const std::vector<libcdoc::CDoc::File>& getFiles() override;

	std::string mimeType() const;
	std::string fileName() const;
	std::vector<unsigned char> decryptData(const std::vector<unsigned char> &key);
	std::vector<unsigned char> decryptData(Token *token);

private:
	CDOC1Reader(const CDOC1Reader &) = delete;
	CDOC1Reader &operator=(const CDOC1Reader &) = delete;
	class Private;
	Private *d;
};
