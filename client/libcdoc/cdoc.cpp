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
		reader = new CDoc1Reader(path);
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
CDocWriter::createWriter(int version, Configuration *conf, CryptoBackend *crypto, NetworkBackend *network)
{
	CDocWriter *writer;
	if (version == 1) {
		writer = new CDoc1Writer();
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
