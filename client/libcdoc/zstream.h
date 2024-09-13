#ifndef __ZSTREAM_H__
#define __ZSTREAM_H__

#include <cstdint>
#include <array>
#include <ios>
#include <vector>

#include <zlib.h>

#include <libcdoc/Crypto.h>
#include <libcdoc/io.h>

namespace libcdoc {

struct CipherSource : public DataSource {
	DataSource *_src;
	bool _owned;
	bool _fail = false;
	libcdoc::Crypto::Cipher *_cipher;
	uint32_t _block_size;
	CipherSource(DataSource *src, bool take_ownership, libcdoc::Crypto::Cipher *cipher)
		: _src(src), _owned(take_ownership), _cipher(cipher), _block_size(cipher->blockSize()) {}
	~CipherSource() {
		if (_owned) delete _src;
	}

	size_t read(uint8_t *dst, size_t size) override final {
		if (_fail) return 0;
		size_t n_read = _src->read(dst, _block_size * (size / _block_size));
		if (n_read) {
			if((n_read % _block_size) || !_cipher->update(dst, n_read)) {
				_fail = true;
				return 0;
			}
		}
		return n_read;
	}

	virtual bool isError() override final {
		return _fail || _src->isError();
	};

	virtual bool isEof() override final {
		return _src->isEof();
	};
};

struct ZSource : public DataSource {
	static constexpr uint64_t CHUNK = 16LL * 1024LL;
	DataSource *_src;
	bool _owned;
	z_stream _s {};
	bool _fail = false;
	std::vector<uint8_t> buf;
	int flush = Z_NO_FLUSH;
	ZSource(DataSource *src, bool take_ownership = false) : _src(src), _owned(take_ownership) {
		if (inflateInit2(&_s, MAX_WBITS) != Z_OK) _fail = true;
	}
	~ZSource() {
		if (!_fail) inflateEnd(&_s);
		if (_owned) delete _src;
	}

	size_t read(uint8_t *dst, size_t size) override final {
		if (_fail) return 0;
		_s.next_out = (Bytef *) dst;
		_s.avail_out = uInt (size);
		uint8_t in[CHUNK];
		int res = Z_OK;
		while((_s.avail_out > 0) && (res == Z_OK)) {
			size_t readlen = CHUNK;
			size_t rsize = _src->read(in, readlen);
			if (rsize > 0) {
				buf.insert(buf.end(), in, in + rsize);
			}
			_s.next_in = (z_const Bytef *) buf.data();
			_s.avail_in = uInt(buf.size());
			res = inflate(&_s, flush);
			switch(res) {
			case Z_OK:
				buf.erase(buf.begin(), buf.end() - _s.avail_in);
				break;
			case Z_STREAM_END:
				buf.clear();
				break;
			default:
				_fail = true;
				return 0;
			}
		}
		return size - _s.avail_out;
	}

	virtual bool isError() override final {
		return _fail || _src->isError();
	};

	virtual bool isEof() override final {
		return (_s.avail_in == 0) && _src->isEof();
	};
};

struct zostream
{
	static constexpr uint64_t CHUNK = 16LL * 1024LL;
	std::ostream *io {};
	libcdoc::Crypto::Cipher *cipher {};
	z_stream s {};
	std::vector<uint8_t> buf;
	int flush = Z_NO_FLUSH;

	zostream(std::ostream *_io, libcdoc::Crypto::Cipher *_cipher)
		: io(_io),
		cipher(_cipher)
	{
		if(deflateInit(&s, Z_DEFAULT_COMPRESSION) != Z_OK) io = nullptr;
	}

	~zostream()
	{
		if (io != nullptr) {
			close();
		}
	}

	void
	close()
	{
		if (io != nullptr) {
			flush = Z_FINISH;
			writeData(nullptr, 0);
			deflateEnd(&s);
		}
	}

	bool
	isEOF() const {
		if (io == nullptr) return true;
		return (s.avail_in == 0) && io->eof();
	}

	int64_t writeData(const char *data, int64_t len)
	{
		if (io == nullptr) return -1;
		s.next_in = (z_const Bytef *)data;
		s.avail_in = uInt(len);
		std::array<uint8_t,CHUNK> out{};
		while(true) {
			s.next_out = (Bytef *)out.data();
			s.avail_out = out.size();
			int res = deflate(&s, flush);
			if(res == Z_STREAM_ERROR)
				return -1;
			auto size = out.size() - s.avail_out;
			if(size > 0) {
				if(!cipher->update(out.data(), int(size))) return -1;
				io->write((const char *) out.data(), size);
				if (io->bad()) return -1;
			}
			if(res == Z_STREAM_END)
				break;
			if(flush == Z_FINISH)
				continue;
			if(s.avail_in == 0)
				break;
		}
		return len;
	}

	int64_t copyFrom(std::istream *ifs) {
		int64_t copied = 0;
		while(!ifs->eof()) {
			char buf[256];
			ifs->read(buf, 256);
			int len = ifs->gcount();
			int written = 0;
			while(written < len) {
				written += writeData(buf + written, len - written);
			}
			copied += len;
		}
		return copied;
	}
};

} // namespace libcdoc

#endif // ZSTREAM_H
