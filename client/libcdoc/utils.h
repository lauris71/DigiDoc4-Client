#ifndef UTILS_H
#define UTILS_H

#include <iostream>
#include <vector>

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

#endif // UTILS_H
