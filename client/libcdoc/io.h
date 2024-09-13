#ifndef IO_H
#define IO_H

#include <istream>
#include <vector>

namespace libcdoc {

struct DataConsumer;
struct DataSource;

struct DataConsumer {
	virtual ~DataConsumer() = default;
	virtual size_t write(const uint8_t *src, size_t size) = 0;
	virtual bool close() = 0;
	virtual bool isError() = 0;

	int64_t writeAll(DataSource *src);
};

struct MultiDataConsumer : public DataConsumer {
	virtual ~MultiDataConsumer() = default;
	// Negative size means unknown
	virtual bool open(const std::string& name, int64_t size) = 0;
};

struct DataSource {
	virtual ~DataSource() = default;
	virtual bool seek(size_t pos) { return false; }
	virtual size_t read(uint8_t *dst, size_t size) = 0;
	virtual bool isError() = 0;
	virtual bool isEof() = 0;

	size_t skip(size_t size);
	size_t readAll(DataConsumer *dst) {
		return dst->writeAll(this);
	}
};

struct MultiDataSource : public DataSource {
	struct File {
		std::string name;
		int64_t size;
	};
	virtual size_t getNumComponents() = 0;
	virtual bool next(File& file) = 0;
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

	size_t read(uint8_t *dst, size_t size) {
		_ifs->read((char *) dst, size);
		return _ifs->gcount();
	}

	bool isError() { return _ifs; }
	bool isEof() { return _ifs->eof(); }
};

struct OStreamConsumer : public DataConsumer {
	std::ostream *_ofs;
	bool _owned;

	OStreamConsumer(std::ostream *ofs, bool take_ownership = false) : _ofs(ofs), _owned(take_ownership) {}
	~OStreamConsumer() {
		if (_owned) delete _ofs;
	}

	size_t write(const uint8_t *src, size_t size) {
		_ofs->write((const char *) src, size);
		return size;
	}

	bool close() {
		_ofs->flush();
		return _ofs;
	}

	bool isError() { return _ofs; }
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

	size_t read(uint8_t *dst, size_t size) {
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
	size_t write(const uint8_t *src, size_t size) override final {
		_data.insert(_data.end(), src, src + size);
		return size;
	}
	bool close() override final { return true; }
	virtual bool isError() override final { return false; }
};

struct IOEntry
{
	std::string name, id, mime;
	int64_t size;
	std::shared_ptr<std::istream> stream;
};

struct StreamListSource : public MultiDataSource {
	StreamListSource(const std::vector<IOEntry>& files);
	size_t read(uint8_t *dst, size_t size) override final;
	bool isError() override final;
	bool isEof() override final;
	size_t getNumComponents() override final;
	bool next(File& file) override final;

	const std::vector<IOEntry>& _files;
	int64_t _current;
};

} // namespace libcdoc

#endif // IO_H
