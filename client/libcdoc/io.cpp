#define __IO_CPP__

#include <fstream>

#include "io.h"

namespace libcdoc {

int64_t
DataConsumer::writeAll(DataSource *src)
{
	static const size_t BUF_SIZE = 64 * 1024;
	uint8_t buf[BUF_SIZE];
	size_t total_read = 0;
	while (!isError() && !src->isError() && !src->isEof()) {
		size_t n_read = src->read(buf, BUF_SIZE);
		write(buf, n_read);
		total_read += n_read;
	}
	return total_read;
}

size_t
DataSource::skip(size_t size) {
	static constexpr size_t BLOCK_SIZE = 65536;
	uint8_t b[BLOCK_SIZE];
	size_t total_read = 0;
	while (total_read < size) {
		size_t to_read = std::min<size_t>(size - total_read, BLOCK_SIZE);
		size_t n_read = read(b, to_read);
		total_read += n_read;
		if (n_read != to_read) break;
	}
	return total_read;
}

IStreamSource::IStreamSource(const std::string& path)
	: IStreamSource(new std::ifstream(path), true)
{
}

StreamListSource::StreamListSource(const std::vector<IOEntry>& files) : _files(files), _current(-1)
{
}

size_t
StreamListSource::read(uint8_t *dst, size_t size)
{
	if ((_current < 0) || (_current >= _files.size())) return 0;
	_files[_current].stream->read((char *) dst, size);
	return _files[_current].stream->gcount();
}

bool
StreamListSource::isError()
{
	if ((_current < 0) || (_current >= _files.size())) return 0;
	return _files[_current].stream->bad();
}

bool
StreamListSource::isEof()
{
	if (_current < 0) return false;
	if (_current >= _files.size()) return true;
	return _files[_current].stream->eof();
}

size_t
StreamListSource::getNumComponents()
{
	return _files.size();
}

bool
StreamListSource::next(StreamListSource::File& file)
{
	++_current;
	if (_current >= _files.size()) return false;
	file.name = _files[_current].name;
	file.size = _files[_current].size;
	return true;
}

} // namespace libcdoc
