#ifndef TAR_H
#define TAR_H

#include <array>
#include <cstring>
#include <vector>
#include <string>

#include <sstream>
#include <cstdio>

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
};

struct TarConsumer : public MultiDataConsumer
{
public:
	TarConsumer(DataConsumer *dst, bool take_ownership);
	~TarConsumer();

	int64_t write(const uint8_t *src, size_t size) override final;
	int close() override final;
	bool isError() override final;
	int open(const std::string& name, int64_t size) override final;
private:
	DataConsumer *_dst;
	bool _owned;
	int64_t _current_size;
	int64_t _current_written;
};

} // namespace libcdoc

#endif // TAR_H
