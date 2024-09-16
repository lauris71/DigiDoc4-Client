#ifndef TAR_H
#define TAR_H

#include <array>
#include <vector>
#include <string>

#include <sstream>
#include <cstdio>
#include <fstream>

#include <libcdoc/zstream.h>
#include <libcdoc/cdoc.h>

namespace libcdoc {

struct TAR {
	explicit TAR() = default;

	static bool files(libcdoc::DataSource *src, bool &warning, libcdoc::MultiDataConsumer *dst);
	static bool save(libcdoc::DataConsumer& dst, libcdoc::MultiDataSource& src);

	static std::vector<std::string> split (const std::string &s, char delim) {
		std::vector<std::string> result;
		std::stringstream ss (s);
		std::string item;

		while (getline (ss, item, delim)) {
			result.push_back (item);
		}

		return result;
	}

private:
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
			return memcmp(this, &empty, sizeof(Header)) == 0;
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

	static constexpr int padding(int64_t size)
	{
		return sizeof(Header) - size % sizeof(Header);
	}
};

} // namespace libcdoc

#endif // TAR_H
