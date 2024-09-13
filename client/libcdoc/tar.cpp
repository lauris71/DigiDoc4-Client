#define __TAR_CPP__

#include "tar.h"

bool
libcdoc::TAR::files(libcdoc::DataSource *src, bool &warning, libcdoc::MultiDataConsumer *dst)
{
	Header h {};
	auto readHeader = [&h, src] { return src->read((uint8_t *) &h, sizeof(Header)) == sizeof(Header); };
	while(!src->isEof()) {
		if(!readHeader())
			return false;
		if(h.isNull())
		{
			if(!readHeader() && !h.isNull())
				return false;
			warning = !src->isEof();
			return true;
		}
		if(!h.verify())
			return false;

		std::string name = std::string(h.name.data(), std::min<int>(h.name.size(), int(strlen(h.name.data()))));
		size_t size = fromOctal(h.size);
		if(h.typeflag == 'x')
		{
			std::vector<char> pax_in(size);
			if (src->read((uint8_t *) pax_in.data(), pax_in.size()) != size)
				return {};
			std::string paxData(pax_in.data(), pax_in.size());
			src->skip(padding(size));
			if(!readHeader() || h.isNull() || !h.verify())
				return {};
			size = fromOctal(h.size);
			std::stringstream ss(paxData);
			std::string data;
			for(const std::string &data: split(paxData, '\n')) {
				if(data.empty())
					break;
				const auto &headerValue = split(data, '=');
				const auto &lenKeyword = split(headerValue[0], ' ');
				if(data.size() + 1 != stoi(lenKeyword[0]))
					return {};
				if(lenKeyword[1] == "path")
					name = headerValue[1];
				if(lenKeyword[1] == "size")
					size = stoi(headerValue[1]);
			}
		}

		if(h.typeflag == '0' || h.typeflag == 0) {
			dst->open(name, size);
			size_t to_write = size;
			while (to_write > 0) {
				uint8_t b[256];
				size_t len = std::min<size_t>(to_write, 256);
				src->read(b, len);
				dst->write(b, len);
				to_write -= len;
			}
			dst->close();
			src->skip(padding(size));
		} else {
			src->skip(size + padding(size));
		}
	}
	return true;
}

bool
libcdoc::TAR::save(libcdoc::zostream& io, libcdoc::MultiDataSource& src)
{
	auto writeHeader = [&io](Header &h, uint64_t size) {
		h.chksum.fill(' ');
		toOctal(h.size, size);
		toOctal(h.chksum, h.checksum().first);
		return io.writeData((const char*)&h, sizeof(Header)) == sizeof(Header);
	};
	auto writePadding = [&io](uint64_t size) {
		std::vector<char> pad(padding(size), 0);
		return io.writeData(pad.data(), pad.size()) == pad.size();
	};
	auto toPaxRecord = [](const std::string &keyword, const std::string &value) {
		std::string record = ' ' + keyword + '=' + value + '\n';
		std::string result;
		for(auto len = record.size() + 1; result.size() != len; ++len)
			result = std::to_string(len + 1) + record;
		return result;
	};
	libcdoc::MultiDataSource::File file;
	while (src.next(file)) {
		Header h {};
		std::string filename(file.name);
		std::string filenameTruncated(filename.begin(), filename.begin() + h.name.size());
		std::copy(filenameTruncated.cbegin(), filenameTruncated.cend(), h.name.begin());

		if(filename.size() > 100 || file.size > 07777777) {
			h.typeflag = 'x';
			std::string paxData;
			if(filename.size() > 100)
				paxData += toPaxRecord("path", filename);
			if(file.size > 07777777)
				paxData += toPaxRecord("size", std::to_string(file.size));
			if(!writeHeader(h, paxData.size()) ||
				io.writeData(paxData.data(), paxData.size()) != paxData.size() ||
				!writePadding(paxData.size()))
				return false;
		}

		h.typeflag = '0';
		if(!writeHeader(h, file.size))
			return false;
		size_t total_written = 0;
		while (!src.isEof()) {
			uint8_t buf[256];
			size_t n_read = src.read(buf, 256);
			io.writeData((const char *) buf, n_read);
			total_written += n_read;
		}
		writePadding(total_written);

	}
	Header empty = {};
	return io.writeData((const char*)&empty, sizeof(Header)) == sizeof(Header) &&
		io.writeData((const char*)&empty, sizeof(Header)) == sizeof(Header);
}
