#ifndef TAR_H
#define TAR_H

#include <cstring>
#include <string>

#include <cstdio>

#include <libcdoc/zstream.h>
#include <libcdoc/cdoc.h>

namespace libcdoc {

struct TAR {
	explicit TAR() = default;

	static bool files(libcdoc::DataSource *src, bool &warning, libcdoc::MultiDataConsumer *dst);
	static bool save(libcdoc::DataConsumer& dst, libcdoc::MultiDataSource& src);
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

struct TarSource : public MultiDataSource
{
public:
	TarSource(DataSource *src, bool take_ownership);
	~TarSource();
	int64_t read(uint8_t *dst, size_t size) override final;
	bool isError() override final;
	bool isEof() override final;
	bool next(std::string& name, int64_t& size) override final;
private:
	DataSource *_src;
	bool _owned;
	bool _eof;
	int _error;
	size_t _block_size;
	size_t _data_size;
	size_t _pos;
};

} // namespace libcdoc

#endif // TAR_H
