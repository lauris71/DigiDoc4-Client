#define __IO_CPP__

#include <fstream>

#include "io.h"

namespace libcdoc {

std::string
DataConsumer::getLastErrorStr(int code) const
{
	switch (code) {
	case OK:
		return "";
	case OUTPUT_ERROR:
		return "DataConsumer: Output error";
	case OUTPUT_STREAM_ERROR:
		return "DataConsumer: Output stream error";
	default:
		break;
	}
	return "DataConsumer: Internal error";
}

std::string
DataSource::getLastErrorStr(int code) const
{
	switch (code) {
	case OK:
		return "";
	case INPUT_ERROR:
		return "DataConsumer: Input error";
	case INPUT_STREAM_ERROR:
		return "DataConsumer: Intput stream error";
	default:
		break;
	}
	return "DataConsumer: Internal error";
}

int64_t
DataConsumer::writeAll(DataSource& src)
{
	static const size_t BUF_SIZE = 64 * 1024;
	uint8_t buf[BUF_SIZE];
	size_t total_read = 0;
	while (!src.isEof()) {
		int64_t n_read = src.read(buf, BUF_SIZE);
		if (n_read < 0) return n_read;
		n_read = write(buf, n_read);
		if (n_read < 0) return n_read;
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
		if (n_read < 0) return n_read;
		total_read += n_read;
	}
	return total_read;
}

IStreamSource::IStreamSource(const std::string& path)
	: IStreamSource(new std::ifstream(path), true)
{
}

OStreamConsumer::OStreamConsumer(const std::string& path)
	: OStreamConsumer(new std::ofstream(path), true)
{
}

FileListSource::FileListSource(const std::string& base, const std::vector<std::string>& files) : _base(base), _files(files), _current(-1)
{
}

int64_t
FileListSource::read(uint8_t *dst, size_t size)
{
	if ((_current < 0) || (_current >= _files.size())) return 0;
	_ifs.read((char *) dst, size);
	return _ifs.gcount();
}

bool
FileListSource::isError()
{
	if ((_current < 0) || (_current >= _files.size())) return 0;
	return _ifs.bad();
}

bool
FileListSource::isEof()
{
	if (_current < 0) return false;
	if (_current >= _files.size()) return true;
	return _ifs.eof();
}

size_t
FileListSource::getNumComponents()
{
	return _files.size();
}

bool
FileListSource::next(std::string& name, int64_t& size)
{
	_ifs.close();
	++_current;
	if (_current >= _files.size()) return false;
	std::filesystem::path path(_base);
	path.append(_files[_current]);
	if (!std::filesystem::exists(path)) return false;
	_ifs.open(path, std::ios_base::in);
	if (!_ifs) return false;
	name = _files[_current];
	size = std::filesystem::file_size(path);
	return true;
}

} // namespace libcdoc
