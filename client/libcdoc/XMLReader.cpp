#define __XML_READER_CPP__

#include <libxml/xmlreader.h>

#include "Crypto.h"

#include "XMLReader.h"

typedef xmlChar *pxmlChar;
typedef const xmlChar *pcxmlChar;

struct XMLReader::Private
{
	xmlTextReaderPtr reader = nullptr;

	libcdoc::DataSource *_src = nullptr;
	bool _delete_src = false;

	xmlParserInputBufferPtr ibuf = nullptr;

	std::string tostring(const xmlChar *tmp)
	{
		std::string result;
		if(!tmp)
			return result;
		result = (const char*)tmp;
		return result;
	}

	static int xmlInputReadCallback (void *context, char *buffer, int len);
	static int xmlInputCloseCallback (void *context);
};

int
XMLReader::Private::xmlInputReadCallback (void *context, char *buffer, int len)
{
	XMLReader *reader = reinterpret_cast<XMLReader *>(context);
	return reader->d->_src->read((uint8_t *) buffer, len);
}

int
XMLReader::Private::xmlInputCloseCallback (void *context)
{
	XMLReader *reader = reinterpret_cast<XMLReader *>(context);
	int result = ((reader->d->_src && !reader->d->_src->isError())) ? 0 : -1;
	if (reader->d->_src && reader->d->_delete_src) {
		delete reader->d->_src;
		reader->d->_src = nullptr;
	}
	return result;
}

XMLReader::XMLReader(libcdoc::DataSource *src, bool delete_on_close)
	: d(new Private)
{
	d->_src = src;
	d->_delete_src = delete_on_close;
	d->ibuf = xmlAllocParserInputBuffer(XML_CHAR_ENCODING_UTF8);
	d->ibuf->context = this;
	d->ibuf->readcallback = Private::xmlInputReadCallback;
	d->ibuf->closecallback = Private::xmlInputCloseCallback;
	d->reader = xmlNewTextReader(d->ibuf, "");
}

XMLReader::XMLReader(std::istream *ifs, bool delete_on_close)
	: XMLReader(new libcdoc::IStreamSource(ifs, delete_on_close), true)
{
}

XMLReader::XMLReader(const std::string &file)
	: d(new Private)
{
	d->reader = xmlReaderForFile(file.c_str(), nullptr, XML_PARSE_HUGE);
}

XMLReader::XMLReader(const std::vector<uchar> &data)
	: d(new Private)
{
	d->reader = xmlReaderForMemory((const char*)data.data(), int(data.size()), nullptr, nullptr, XML_PARSE_HUGE);
}

XMLReader::~XMLReader()
{
	if(d->reader) xmlFreeTextReader(d->reader);
	if(d->_src && d->_delete_src) delete d->_src;
	delete d;
}

std::string XMLReader::attribute(const char *attr) const
{
	xmlChar *tmp = xmlTextReaderGetAttribute(d->reader, pcxmlChar(attr));
	std::string result = d->tostring(tmp);
	xmlFree(tmp);
	return result;
}

bool XMLReader::isEndElement() const
{
	return xmlTextReaderNodeType(d->reader) == XML_READER_TYPE_END_ELEMENT;
}

bool XMLReader::isElement(const char *elem) const
{
	return xmlStrEqual(xmlTextReaderConstLocalName(d->reader), pcxmlChar(elem)) == 1;
}

bool XMLReader::read()
{
	return xmlTextReaderRead(d->reader) == 1;
}

std::vector<uchar> XMLReader::readBase64()
{
	xmlTextReaderRead(d->reader);
	return libcdoc::Crypto::decodeBase64(xmlTextReaderConstValue(d->reader));
}

std::string XMLReader::readText()
{
	xmlTextReaderRead(d->reader);
	return d->tostring(xmlTextReaderConstValue(d->reader));
}
