#define __TAR_CPP__

#include "tar.h"

template<std::size_t SIZE>
static int64_t fromOctal(const std::array<char,SIZE> &data)
{
	int64_t i = 0;
	for(const char c: data)
	{
		if(c < '0' || c > '7')
			continue;
		i <<= 3;
		i += c - '0';
	}
	return i;
}

template<std::size_t SIZE>
static void toOctal(std::array<char,SIZE> &data, int64_t value)
{
	data.fill(' ');
	for(auto it = data.rbegin() + 1; it != data.rend(); ++it)
	{
		*it = char(value & 7) + '0';
		value >>= 3;
	}
}

struct Header {
	std::array<char,100> name;
	std::array<char,  8> mode;
	std::array<char,  8> uid;
	std::array<char,  8> gid;
	std::array<char, 12> size;
	std::array<char, 12> mtime;
	std::array<char,  8> chksum;
	char typeflag;
	std::array<char,100> linkname;
	std::array<char,  6> magic;
	std::array<char,  2> version;
	std::array<char, 32> uname;
	std::array<char, 32> gname;
	std::array<char,  8> devmajor;
	std::array<char,  8> devminor;
	std::array<char,155> prefix;
	std::array<char, 12> padding;

	std::pair<int64_t,int64_t> checksum() const
	{
		int64_t unsignedSum = 0;
		int64_t signedSum = 0;
		for (size_t i = 0, size = sizeof(Header); i < size; i++) {
			unsignedSum += ((unsigned char*) this)[i];
			signedSum += ((signed char*) this)[i];
		}
		return {unsignedSum, signedSum};
	}

	bool isNull() {
		Header empty = {};
		return std::memcmp(this, &empty, sizeof(Header)) == 0;
	}

	bool verify() {
		auto copy = chksum;
		chksum.fill(' ');
		auto checkSum = checksum();
		chksum.swap(copy);
		int64_t referenceChecksum = fromOctal(chksum);
		return referenceChecksum == checkSum.first ||
			   referenceChecksum == checkSum.second;
	}

	static const Header Empty;
	static const int Size;
};

static int padding(int64_t size)
{
	return sizeof(Header) - size % sizeof(Header);
}

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

int64_t writePadding(libcdoc::DataConsumer *dst, uint64_t size) {
	std::vector<char> pad(padding(size), 0);
	return dst->write((const uint8_t *) pad.data(), pad.size()) == pad.size();
};

int64_t writeHeader (libcdoc::DataConsumer *dst, Header &h, uint64_t size) {
	h.chksum.fill(' ');
	toOctal(h.size, size);
	toOctal(h.chksum, h.checksum().first);
	return dst->write((const uint8_t *)&h, sizeof(Header)) == sizeof(Header);
};

std::string toPaxRecord (const std::string &keyword, const std::string &value) {
	std::string record = ' ' + keyword + '=' + value + '\n';
	std::string result;
	for(auto len = record.size() + 1; result.size() != len; ++len)
		result = std::to_string(len + 1) + record;
	return result;
};

bool
libcdoc::TAR::save(libcdoc::DataConsumer& dst, libcdoc::MultiDataSource& src)
{
	std::string name;
	int64_t size;
	while (src.next(name, size)) {
		Header h {};
		std::string filename(name);
		std::string filenameTruncated(filename.begin(), filename.begin() + h.name.size());
		std::copy(filenameTruncated.cbegin(), filenameTruncated.cend(), h.name.begin());

		if(filename.size() > 100 || size > 07777777) {
			h.typeflag = 'x';
			std::string paxData;
			if(filename.size() > 100)
				paxData += toPaxRecord("path", filename);
			if(size > 07777777)
				paxData += toPaxRecord("size", std::to_string(size));
			if(!writeHeader(&dst, h, paxData.size()) ||
				dst.write((const uint8_t *) paxData.data(), paxData.size()) != paxData.size() ||
				!writePadding(&dst, paxData.size()))
				return false;
		}

		h.typeflag = '0';
		if(!writeHeader(&dst, h, size))
			return false;
		size_t total_written = 0;
		while (!src.isEof()) {
			uint8_t buf[256];
			size_t n_read = src.read(buf, 256);
			if (n_read < 0) return false;
			dst.write(buf, n_read);
			total_written += n_read;
		}
		writePadding(&dst, total_written);

	}
	Header empty = {};
	return dst.write((const uint8_t *)&empty, sizeof(Header)) == sizeof(Header) &&
		dst.write((const uint8_t *)&empty, sizeof(Header)) == sizeof(Header);
}

libcdoc::TarConsumer::TarConsumer(DataConsumer *dst, bool take_ownership)
	: _dst(dst), _owned(take_ownership), _current_size(0)
{

}

libcdoc::TarConsumer::~TarConsumer()
{
	if (_owned) {
		delete _dst;
	}
}

int64_t
libcdoc::TarConsumer::write(const uint8_t *src, size_t size)
{
	return _dst->write(src, size);
}

int
libcdoc::TarConsumer::close()
{
	if (_current_size) {
		writePadding(_dst, _current_size);
	}
	Header empty = {};
	_dst->write((const uint8_t *)&empty, sizeof(Header));
	_dst->write((const uint8_t *)&empty, sizeof(Header));
	if (_owned) {
		_dst->close();
	}
	return OK;
}

bool
libcdoc::TarConsumer::isError()
{
	return _dst->isError();
}

int
libcdoc::TarConsumer::open(const std::string& name, int64_t size)
{
	if (_current_size) {
		writePadding(_dst, _current_size);
	}
	_current_size = size;
	Header h {};
	std::string filename(name);
	std::string filenameTruncated(filename.begin(), filename.begin() + h.name.size());
	std::copy(filenameTruncated.cbegin(), filenameTruncated.cend(), h.name.begin());

	if(filename.size() > 100 || size > 07777777) {
		h.typeflag = 'x';
		std::string paxData;
		if(filename.size() > 100)
			paxData += toPaxRecord("path", filename);
		if(size > 07777777)
			paxData += toPaxRecord("size", std::to_string(size));
		if(!writeHeader(_dst, h, paxData.size()) ||
			_dst->write((const uint8_t *) paxData.data(), paxData.size()) != paxData.size() ||
			!writePadding(_dst, paxData.size()))
			return false;
	}

	h.typeflag = '0';
	if(writeHeader(_dst, h, size) < 0) return OUTPUT_ERROR;
	return OK;
}
