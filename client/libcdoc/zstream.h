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

struct CipherConsumer : public ChainedConsumer {
	bool _fail = false;
	libcdoc::Crypto::Cipher *_cipher;
	uint32_t _block_size;
	CipherConsumer(DataConsumer *dst, bool take_ownership, libcdoc::Crypto::Cipher *cipher)
		: ChainedConsumer(dst, take_ownership), _cipher(cipher), _block_size(cipher->blockSize()) {}
	~CipherConsumer() {
	}

	int64_t write(const uint8_t *src, size_t size) override final {
		static constexpr uint64_t CHUNK_SIZE = 16LL * 1024LL;
		if (_fail) return OUTPUT_ERROR;
		if (size % _block_size) {
			_fail = true;
			return OUTPUT_ERROR;
		}
		uint8_t b[CHUNK_SIZE];
		size_t processed = 0;
		while (processed < size) {
			size_t to_process = std::min<size_t>(size, CHUNK_SIZE);
			std::copy(src + processed, src + processed + to_process, b);
			if(!_cipher->update(b, int(to_process))) {
				_fail = true;
				return OUTPUT_ERROR;
			}
			int64_t n_written = _dst->write(b, to_process);
			if (n_written != to_process) {
				_fail = true;
				return OUTPUT_ERROR;
			}
			processed += to_process;
		}
		return processed;
	}

	virtual bool isError() override final {
		return _fail || ChainedConsumer::isError();
	};
};

struct CipherSource : public ChainedSource {
	bool _fail = false;
	libcdoc::Crypto::Cipher *_cipher;
	uint32_t _block_size;
	CipherSource(DataSource *src, bool take_ownership, libcdoc::Crypto::Cipher *cipher)
		: ChainedSource(src, take_ownership), _cipher(cipher), _block_size(cipher->blockSize()) {}

	int64_t read(uint8_t *dst, size_t size) override final {
		if (_fail) return INPUT_ERROR;
		size_t n_read = _src->read(dst, _block_size * (size / _block_size));
		if (n_read) {
			if((n_read % _block_size) || !_cipher->update(dst, n_read)) {
				_fail = true;
				return INPUT_ERROR;
			}
		}
		return n_read;
	}

	virtual bool isError() override final {
		return _fail || ChainedSource::isError();
	};
};

struct ZConsumer : public ChainedConsumer {
	static constexpr uint64_t CHUNK = 16LL * 1024LL;
	z_stream _s {};
	bool _fail = false;
	std::vector<uint8_t> buf;
	int flush = Z_NO_FLUSH;
	ZConsumer(DataConsumer *dst, bool take_ownership = false) : ChainedConsumer(dst, take_ownership) {
		if (deflateInit(&_s, Z_DEFAULT_COMPRESSION) != Z_OK) _fail = true;
	}
	~ZConsumer() {
		if (!_fail) deflateEnd(&_s);
	}

	int64_t write(const uint8_t *src, size_t size) override final {
		if (_fail) return OUTPUT_ERROR;
		_s.next_in = (z_const Bytef *) src;
		_s.avail_in = uInt(size);
		std::array<uint8_t,CHUNK> out{};
		while(true) {
			_s.next_out = (Bytef *)out.data();
			_s.avail_out = out.size();
			int res = deflate(&_s, flush);
			if(res == Z_STREAM_ERROR)
				return OUTPUT_ERROR;
			auto o_size = out.size() - _s.avail_out;
			if(o_size > 0) {
				int64_t result = _dst->write(out.data(), o_size);
				if (result != o_size) return result;
			}
			if(res == Z_STREAM_END) break;
			if(flush == Z_FINISH) continue;
			if(_s.avail_in == 0) break;
		}
		return size;
	}

	virtual bool isError() override final {
		return _fail || ChainedConsumer::isError();
	};

	int close() override final {
		flush = Z_FINISH;
		write (nullptr, 0);
		deflateEnd(&_s);
		return ChainedConsumer::close();
	}
};

struct ZSource : public ChainedSource {
	static constexpr uint64_t CHUNK = 16LL * 1024LL;
	z_stream _s {};
	bool _fail = false;
	std::vector<uint8_t> buf;
	int flush = Z_NO_FLUSH;
	ZSource(DataSource *src, bool take_ownership = false) : ChainedSource(src, take_ownership) {
		if (inflateInit2(&_s, MAX_WBITS) != Z_OK) _fail = true;
	}
	~ZSource() {
		if (!_fail) inflateEnd(&_s);
	}

	int64_t read(uint8_t *dst, size_t size) override final {
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
				return INPUT_ERROR;
			}
		}
		return size - _s.avail_out;
	}

	virtual bool isError() override final {
		return _fail || ChainedSource::isError();
	};

	virtual bool isEof() override final {
		return (_s.avail_in == 0) && ChainedSource::isEof();
	};
};

} // namespace libcdoc

#endif // ZSTREAM_H
