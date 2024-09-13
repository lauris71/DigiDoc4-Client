#pragma once

#include <istream>
#include <string>
#include <vector>

#include <libcdoc/cdoc.h>

class XMLReader
{
public:
	XMLReader(libcdoc::DataSource *src, bool delete_on_close = false);
	XMLReader(std::istream *ifs, bool delete_on_close = false);
	XMLReader(const std::string &file);
	XMLReader(const std::vector<uint8_t> &data);
	~XMLReader();

	std::string attribute(const char *attr) const;
	bool isElement(const char *element) const;
	bool isEndElement() const;
	bool read();
	std::vector<uint8_t> readBase64();
	std::string readText();

private:
	struct Private;
	Private *d;
};
