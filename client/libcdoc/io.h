#ifndef IO_H
#define IO_H

#include <filesystem>
#include <fstream>
#include <vector>

namespace libcdoc {

struct DataConsumer;
struct DataSource;

struct DataConsumer {
	static constexpr int OK = 0;
	static constexpr int OUTPUT_ERROR = -500;
	static constexpr int OUTPUT_STREAM_ERROR = -501;

	virtual ~DataConsumer() = default;
	virtual int64_t write(const uint8_t *src, size_t size) = 0;
	virtual int close() = 0;
	virtual bool isError() = 0;
	virtual std::string getLastErrorStr(int code) const;

	int64_t write(const std::vector<uint8_t>& src) {
		return write(src.data(), src.size());
	}
	int64_t write(const std::string& src) {
		return write((const uint8_t *) src.data(), src.size());
	}
	int64_t writeAll(DataSource& src);
};

struct DataSource {
	static constexpr int OK = 0;
	static constexpr int INPUT_ERROR = -600;
	static constexpr int INPUT_STREAM_ERROR = -601;

	virtual ~DataSource() = default;
	virtual bool seek(size_t pos) { return false; }
	virtual int64_t read(uint8_t *dst, size_t size) = 0;
	virtual bool isError() = 0;
	virtual bool isEof() = 0;
	virtual std::string getLastErrorStr(int code) const;

	size_t skip(size_t size);
	size_t readAll(DataConsumer& dst) {
		return dst.writeAll(*this);
	}
};

struct MultiDataConsumer : public DataConsumer {
	virtual ~MultiDataConsumer() = default;
	// Negative value means unknown size
	virtual bool open(const std::string& name, int64_t size) = 0;
};

struct MultiDataSource : public DataSource {
	virtual size_t getNumComponents() = 0;
	virtual bool next(std::string& name, int64_t& size) = 0;
};

struct ChainedConsumer : public DataConsumer {
	DataConsumer *_dst;
	bool _owned;
	ChainedConsumer(DataConsumer *dst, bool take_ownership) : _dst(dst), _owned(take_ownership) {}
	~ChainedConsumer() {
		if (_owned) delete _dst;
	}
	int64_t write(const uint8_t *src, size_t size) {
		return _dst->write(src, size);
	}
	int close() {
		if (_owned) return _dst->close();
		return OK;
	}
	bool isError() {
		return _dst->isError();
	}
};

struct ChainedSource : public DataSource {
	DataSource *_src;
	bool _owned;
	ChainedSource(DataSource *src, bool take_ownership) : _src(src), _owned(take_ownership) {}
	~ChainedSource() {
		if (_owned) delete _src;
	}
	int64_t read(uint8_t *dst, size_t size) {
		return _src->read(dst, size);
	}
	bool isError() {
		return _src->isError();
	}
	bool isEof() {
		return _src->isEof();
	}
};

struct IStreamSource : public DataSource {
	std::istream *_ifs;
	bool _owned;

	IStreamSource(std::istream *ifs, bool take_ownership = false) : _ifs(ifs), _owned(take_ownership) {}
	IStreamSource(const std::string& path);
	~IStreamSource() {
		if (_owned) delete _ifs;
	}

	bool seek(size_t pos) {
		_ifs->seekg(pos);
		return _ifs;
	}

	int64_t read(uint8_t *dst, size_t size) {
		_ifs->read((char *) dst, size);
		return (_ifs) ? _ifs->gcount() : INPUT_STREAM_ERROR;
	}

	bool isError() { return !_ifs; }
	bool isEof() { return _ifs->eof(); }
};

struct OStreamConsumer : public DataConsumer {
	static constexpr int STREAM_ERROR = -500;
	std::ostream *_ofs;
	bool _owned;

	OStreamConsumer(std::ostream *ofs, bool take_ownership = false) : _ofs(ofs), _owned(take_ownership) {}
	OStreamConsumer(const std::string& path);
	~OStreamConsumer() {
		if (_owned) delete _ofs;
	}

	int64_t write(const uint8_t *src, size_t size) {
		_ofs->write((const char *) src, size);
		return (_ofs) ? size : OUTPUT_STREAM_ERROR;
	}

	int close() {
		_ofs->flush();
		return (_ofs) ? OK : OUTPUT_STREAM_ERROR;
	}

	bool isError() { return !_ofs; }
};

struct VectorSource : public DataSource {
	const std::vector<uint8_t>& _data;
	size_t _ptr;

	VectorSource(const std::vector<uint8_t>& data) : _data(data), _ptr(0) {}

	bool seek(size_t pos) {
		if (pos > _data.size()) return false;
		_ptr = pos;
		return true;
	}

	int64_t read(uint8_t *dst, size_t size) {
		size = std::min<size_t>(size, _data.size() - _ptr);
		std::copy(_data.cbegin() + _ptr, _data.cbegin() + _ptr + size, dst);
		_ptr += size;
		return size;
	}

	bool isError() { return false; }
	bool isEof() { return _ptr >= _data.size(); }
};

struct VectorConsumer : public DataConsumer {
	std::vector<uint8_t> _data;
	VectorConsumer(std::vector<uint8_t>& data) : _data(data) {}
	int64_t write(const uint8_t *src, size_t size) override final {
		_data.insert(_data.end(), src, src + size);
		return size;
	}
	int close() override final { return OK; }
	virtual bool isError() override final { return false; }
};

struct FileListConsumer : public MultiDataConsumer {
	std::filesystem::path base;
	std::ofstream ofs;
	FileListConsumer(const std::string base_path) {
		base = base_path;
	}
	int64_t write(const uint8_t *src, size_t size) override final {
		ofs.write((const char *) src, size);
		return (ofs) ? size : OUTPUT_STREAM_ERROR;
	}
	int close() override final {
		ofs.close();
		return (ofs) ? OK : OUTPUT_STREAM_ERROR;
	}
	bool isError() override final {
		return !ofs;
	}
	bool open(const std::string& name, int64_t size) override final {
		std::filesystem::path path = base.append(name);
		ofs.open(path.string(), std::ios_base::out);
		return bool(ofs);
	}
};

struct FileListSource : public MultiDataSource {
	FileListSource(const std::string& base, const std::vector<std::string>& files);
	int64_t read(uint8_t *dst, size_t size) override final;
	bool isError() override final;
	bool isEof() override final;
	size_t getNumComponents() override final;
	bool next(std::string& name, int64_t& size) override final;

	std::filesystem::path _base;
	const std::vector<std::string>& _files;
	int64_t _current;
	std::ifstream _ifs;
};

} // namespace libcdoc

#endif // IO_H
