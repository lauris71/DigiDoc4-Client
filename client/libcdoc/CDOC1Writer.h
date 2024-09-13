#pragma once

#include <string>
#include <vector>

#include "cdoc.h"
#include "CDOCExport.h"

class CDOC_EXPORT CDOC1Writer : public libcdoc::CDocWriter
{
public:
	CDOC1Writer(const std::string &method = "http://www.w3.org/2009/xmlenc11#aes256-gcm");
	~CDOC1Writer();

	std::string last_error;

	uint32_t getVersion() final { return 1; }
	bool encrypt(std::ostream& ofs, libcdoc::MultiDataSource& src, const std::vector<std::shared_ptr<libcdoc::EncKey>>& keys) final;
private:
	CDOC1Writer(const CDOC1Writer &) = delete;
	CDOC1Writer &operator=(const CDOC1Writer &) = delete;
	class Private;
	Private *d;
};
