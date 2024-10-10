#pragma once

#include <string>
#include <vector>

#include "CDocWriter.h"

class CDoc1Writer : public libcdoc::CDocWriter
{
public:
	CDoc1Writer(const std::string &method = "http://www.w3.org/2009/xmlenc11#aes256-gcm");
	~CDoc1Writer();

	std::string last_error;

	int beginEncryption(libcdoc::DataConsumer& dst) override final;
	int addRecipient(const libcdoc::Recipient& rcpt) override final;
	int addFile(const std::string& name, size_t size) override final;
	int writeData(const uint8_t *src, size_t size) override final;
	int finishEncryption(bool close_dst) override final;

	int encrypt(libcdoc::DataConsumer& dst, libcdoc::MultiDataSource& src, const std::vector<libcdoc::Recipient>& keys) final;
private:
	CDoc1Writer(const CDoc1Writer &) = delete;
	CDoc1Writer &operator=(const CDoc1Writer &) = delete;
	class Private;
	Private *d;
};
