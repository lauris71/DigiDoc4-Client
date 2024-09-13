#pragma once
#include <ostream>
#include <functional>
#include <map>
#include <string>
#include <vector>

class XMLWriter
{
public:
	struct NS { std::string prefix, ns; };

	XMLWriter(std::ostream *ofs);
	XMLWriter(const std::string& path);
	XMLWriter(std::vector<uint8_t>& vec);
	virtual ~XMLWriter();

	virtual void close();
	void writeStartElement(const NS &ns, const std::string &name, const std::map<std::string, std::string> &attr);
	void writeEndElement(const NS &ns);
	void writeElement(const NS &ns, const std::string &name, const std::function<void()> &f = nullptr);
	void writeElement(const NS &ns, const std::string &name, const std::map<std::string, std::string> &attr, const std::function<void()> &f = nullptr);
	void writeBase64Element(const NS &ns, const std::string &name, const std::vector<unsigned char> &data, const std::map<std::string, std::string> &attr = {});
	void writeTextElement(const NS &ns, const std::string &name, const std::map<std::string, std::string> &attr, const std::string &data);

private:
	struct Private;
	Private *d;
};
