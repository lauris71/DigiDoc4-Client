#define __XMLWRITER_CPP__

#include <fstream>

#include "XMLWriter.h"

#include "Crypto.h"
#include <utils.h>
#include <libxml/xmlwriter.h>

#include <algorithm>

typedef xmlChar *pxmlChar;
typedef const xmlChar *pcxmlChar;

struct XMLWriter::Private
{
	xmlTextWriterPtr w = nullptr;
	std::map<std::string, int> nsmap;

	std::ostream *ofs = nullptr;
	bool close_ofs = false;
	libcdoc::vectorwrapbuf *vbuf = nullptr;

	xmlOutputBufferPtr obuf = nullptr;

	static int xmlOutputWriteCallback (void *context, const char *buffer, int len);
	static int xmlOutputCloseCallback (void *context);
};

int
XMLWriter::Private::xmlOutputWriteCallback (void *context, const char *buffer, int len)
{
	XMLWriter *writer = reinterpret_cast<XMLWriter *>(context);
	writer->d->ofs->write(buffer, len);
	return (writer->d->ofs->fail()) ? -1 : len;
}

int
XMLWriter::Private::xmlOutputCloseCallback (void *context)
{
	XMLWriter *writer = reinterpret_cast<XMLWriter *>(context);
	writer->d->ofs->flush();
	return (writer->d->ofs->fail()) ? -1 : 0;
}

XMLWriter::XMLWriter(std::ostream *ofs)
	: d(new Private)
{
	d->ofs = ofs;
	d->obuf = xmlAllocOutputBuffer(nullptr);
	d->obuf->context = this;
	d->obuf->writecallback = Private::xmlOutputWriteCallback;
	d->obuf->closecallback = Private::xmlOutputCloseCallback;
	d->w = xmlNewTextWriter(d->obuf);
	xmlTextWriterStartDocument(d->w, nullptr, "UTF-8", nullptr);
}

XMLWriter::XMLWriter(const std::string& path)
	: d(new Private)
{
	d->ofs = new std::ofstream(path);;
	d->close_ofs = true;
	d->obuf = xmlAllocOutputBuffer(nullptr);
	d->obuf->context = this;
	d->obuf->writecallback = Private::xmlOutputWriteCallback;
	d->obuf->closecallback = Private::xmlOutputCloseCallback;
	d->w = xmlNewTextWriter(d->obuf);
	xmlTextWriterStartDocument(d->w, nullptr, "UTF-8", nullptr);
}

XMLWriter::XMLWriter(std::vector<uint8_t>& vec)
	: d(new Private)
{
	d->vbuf = new libcdoc::vectorwrapbuf(vec);
	d->ofs = new std::ostream(d->vbuf);
	d->close_ofs = true;
	d->obuf = xmlAllocOutputBuffer(nullptr);
	d->obuf->context = this;
	d->obuf->writecallback = Private::xmlOutputWriteCallback;
	d->obuf->closecallback = Private::xmlOutputCloseCallback;
	d->w = xmlNewTextWriter(d->obuf);
	xmlTextWriterStartDocument(d->w, nullptr, "UTF-8", nullptr);
}

XMLWriter::~XMLWriter()
{
	close();
	if(d->ofs && d->close_ofs) delete d->ofs;
	if(d->vbuf) delete d->vbuf;
	delete d;
}

void XMLWriter::close()
{
	if(!d->w)
		return;
	xmlTextWriterEndDocument(d->w);
	xmlFreeTextWriter(d->w);
	d->w = nullptr;
}

void XMLWriter::writeStartElement(const NS &ns, const std::string &name, const std::map<std::string, std::string> &attr)
{
	std::map<std::string, int>::iterator pos = d->nsmap.find(ns.prefix);
	if (pos != d->nsmap.cend())
		pos->second++;
	else
		pos = d->nsmap.insert({ns.prefix, 1}).first;
	if(!d->w)
		return;
	xmlTextWriterStartElementNS(d->w, ns.prefix.empty() ? nullptr : pcxmlChar(ns.prefix.c_str()),
		pcxmlChar(name.c_str()), pos->second > 1 ? nullptr : pcxmlChar(ns.ns.c_str()));
	for(auto i = attr.cbegin(), end = attr.cend(); i != end; ++i)
		xmlTextWriterWriteAttribute(d->w, pcxmlChar(i->first.c_str()), pcxmlChar(i->second.c_str()));
}

void XMLWriter::writeEndElement(const NS &ns)
{
	if(d->w)
		xmlTextWriterEndElement(d->w);
	std::map<std::string, int>::iterator pos = d->nsmap.find(ns.prefix);
	if (pos != d->nsmap.cend())
		pos->second--;
}

void XMLWriter::writeElement(const NS &ns, const std::string &name, const std::function<void()> &f)
{
	writeStartElement(ns, name, {});
	if(f)
		f();
	writeEndElement(ns);
}

void XMLWriter::writeElement(const NS &ns, const std::string &name, const std::map<std::string, std::string> &attr, const std::function<void()> &f)
{
	writeStartElement(ns, name, attr);
	if(f)
		f();
	writeEndElement(ns);
}

void XMLWriter::writeBase64Element(const NS &ns, const std::string &name, const std::vector<xmlChar> &data, const std::map<std::string, std::string> &attr)
{
	if (!d->w)
		return;
	writeStartElement(ns, name, attr);
	static const size_t bufLen = 48 * 10240;
	for (size_t i = 0; i < data.size(); i += bufLen)
	{
		std::string b64 = libcdoc::Crypto::toBase64(&data[i], std::min<size_t>(data.size() - i, bufLen));
		xmlTextWriterWriteRaw(d->w, (const xmlChar*)b64.c_str());
	}
	writeEndElement(ns);
}

void XMLWriter::writeTextElement(const NS &ns, const std::string &name, const std::map<std::string, std::string> &attr, const std::string &data)
{
	writeStartElement(ns, name, attr);
	if(d->w)
		xmlTextWriterWriteString(d->w, pcxmlChar(data.c_str()));
	writeEndElement(ns);
}
