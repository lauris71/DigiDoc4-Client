#ifndef UTILS_H
#define UTILS_H

#include <algorithm>
#include <iostream>
#include <vector>

#include <libcdoc/io.h>

namespace libcdoc {

class vectorwrapbuf : public std::streambuf {
public:
	using traits_type = typename std::streambuf::traits_type;
	vectorwrapbuf(std::vector<char> &_vec) : vec(_vec){
		setg(_vec.data(), _vec.data(), _vec.data() + _vec.size());
		setp(_vec.data(), _vec.data() + _vec.size());
	}
	vectorwrapbuf(std::vector<uint8_t> &_vec) : vec(reinterpret_cast<std::vector<char>&>(_vec)){
		setg((char*)_vec.data(), (char*)_vec.data(), (char*)_vec.data() + _vec.size());
		setp((char*)_vec.data(), (char*)_vec.data() + _vec.size());
	}
	pos_type seekpos(pos_type sp, std::ios_base::openmode which) override {
		return seekoff(sp - pos_type(off_type(0)), std::ios_base::beg, which);
	}
	pos_type seekoff(off_type off, std::ios_base::seekdir dir, std::ios_base::openmode which) override {
		if (which & std::ios_base::in) {
			switch (dir) {
				case std::ios_base::cur: gbump(int(off)); break;
				case std::ios_base::end: setg(eback(), egptr() + off, egptr()); break;
				case std::ios_base::beg: setg(eback(), eback() + off, egptr()); break;
			}
		} else if (which & std::ios_base::out) {
			switch (dir) {
				case std::ios_base::cur: pbump(int(off)); break;
				case std::ios_base::end: setp(eback(), epptr() + off); break;
				case std::ios_base::beg: setp(eback(), eback() + off); break;
			}
		}
		return gptr() - eback();
	}
	std::streamsize xsputn (const char* s, std::streamsize n) override {
		ensure_space(n);
		char *pp = pptr();
		traits_type::copy(pp, s, n);
		std::streambuf::pbump(n);
		return n;
	}
	int overflow (int c) override {
		ensure_space(1);
		return c;
	}
private:
	std::vector<char>& vec;
	void ensure_space(int n) {
		char *dp = vec.data();
		char *pp = pptr();
		char *ep = epptr();
		if((pp + n) > (dp + vec.size())) {
			size_t req_size = pp + n - dp;
			size_t new_size = vec.size() * 2;
			if (new_size < req_size) new_size = req_size;
			vec.resize(new_size);
		}
	}
};

} // vectorwrapbuf

// A source implementation that always keeps last 16 bytes in tag

struct TaggedSource : public libcdoc::DataSource {
	std::vector<uint8_t> tag;
	libcdoc::DataSource *_src;
	bool _owned;

	TaggedSource(libcdoc::DataSource *src, bool take_ownership, size_t tag_size) : tag(tag_size), _src(src), _owned(take_ownership) {
		tag.resize(tag.size());
		_src->read(tag.data(), tag.size());
	}
	~TaggedSource() {
		if (_owned) delete(_src);
	}

	int seek(size_t pos) override final {
		if (!_src->seek(pos)) return INPUT_STREAM_ERROR;
		if (_src->read(tag.data(), tag.size()) != tag.size()) return INPUT_STREAM_ERROR;
		return libcdoc::OK;
	}

	int64_t read(uint8_t *dst, size_t size) override final {
		uint8_t tmp[tag.size()];
		size_t nread = _src->read(dst, size);
		if (nread >= tag.size()) {
			std::copy(dst + nread - tag.size(), dst + nread, tmp);
			std::copy_backward(dst, dst + nread - tag.size(), dst + nread);
			std::copy(tag.cbegin(), tag.cend(), dst);
			std::copy(tmp, tmp + tag.size(), tag.begin());
		} else {
			std::copy(dst, dst + nread, tmp);
			std::copy(tag.cbegin(), tag.cbegin() + nread, dst);
			std::copy(tag.cbegin() + nread, tag.cend(), tag.begin());
			std::copy(tmp, tmp + nread, tag.end() - nread);
		}
		return nread;
	}

	virtual bool isError() override final {
		return _src->isError();
	}
	virtual bool isEof() override final {
		return _src->isEof();
	}
};

#endif // UTILS_H
