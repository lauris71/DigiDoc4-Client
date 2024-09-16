#include <cstring>
#include <iostream>
#include <fstream>
#include <map>
#include <memory>

#include "CDOC1Writer.h"
#include "CDOC1Reader.h"
#include "Token.h"
#include "DDOCReader.h"
#include "Crypto.h"
#include "cdoc.h"


#ifdef _WIN32
#include <Windows.h>

static std::wstring toWide(UINT codePage, const std::string &in)
{
	std::wstring result;
	if(in.empty())
		return result;
	int len = MultiByteToWideChar(codePage, 0, in.data(), int(in.size()), nullptr, 0);
	result.resize(size_t(len), 0);
	len = MultiByteToWideChar(codePage, 0, in.data(), int(in.size()), &result[0], len);
	return result;
}

static std::string toMultiByte(UINT codePage, const std::wstring &in)
{
	std::string result;
	if(in.empty())
		return result;
	int len = WideCharToMultiByte(codePage, 0, in.data(), int(in.size()), nullptr, 0, nullptr, nullptr);
	result.resize(size_t(len), 0);
	len = WideCharToMultiByte(codePage, 0, in.data(), int(in.size()), &result[0], len, nullptr, nullptr);
	return result;
}
#endif

static std::string toUTF8(const std::string &in)
{
#ifdef _WIN32
	return toMultiByte(CP_UTF8, toWide(CP_ACP, in));
#else
	return in;
#endif
}

static std::vector<unsigned char> readFile(const std::string &path)
{
	std::vector<unsigned char> data;
#ifdef _WIN32
	std::ifstream f(toWide(CP_UTF8, path).c_str(), std::ifstream::binary);
#else
	std::ifstream f(path, std::ifstream::binary);
#endif
	if (!f)
		return data;
	f.seekg(0, std::ifstream::end);
	data.resize(size_t(f.tellg()));
	f.clear();
	f.seekg(0);
	f.read((char*)data.data(), std::streamsize(data.size()));
	return data;
}

static void writeFile(const std::string &path, const std::vector<unsigned char> &data)
{
#ifdef _WIN32
	std::ofstream f(toWide(CP_UTF8, path).c_str(), std::ofstream::binary);
#else
	std::ofstream f(path.c_str(), std::ofstream::binary);
#endif
	f.write((const char*)data.data(), std::streamsize(data.size()));
}

struct Recipient {
	enum Type { CERT, PASSWORD, KEY };
	Type type;
	std::string label;
	std::vector<uint8_t> data;
};

static void
print_usage(std::ostream& ofs, int exit_value)
{
	ofs
		//<< "cdoc-tool encrypt -r X509DerRecipientCert [-r X509DerRecipientCert [...]] InFile [InFile [...]] OutFile" << std::endl
		<< "cdoc-tool encrypt [--rcpt-cert LABEL X509DERFILE] [--rcpt-key LABEL SECRED [--rcpt-pwd LABEL PASSWORD] [...] [--file INFILE] [...] --out OUTFILE" << std::endl
#ifdef _WIN32
		<< "cdoc-tool decrypt win [ui|noui] pin InFile OutFolder" << std::endl
#endif
		<< "cdoc-tool decrypt pkcs11 path/to/so pin InFile OutFolder" << std::endl
		<< "cdoc-tool decrypt pkcs12 path/to/pkcs12 pin InFile OutFolder" << std::endl;
	exit(exit_value);
}

static std::vector<uint8_t>
fromHex(const std::string& hex) {
	std::vector<uint8_t> val(hex.size() / 2);
	char c[3] = {0};
	for (size_t i = 0; i < (hex.size() & 0xfffffffe); i += 2) {
		std::copy(hex.cbegin() + i, hex.cbegin() + i + 2, c);
		std::cerr << c << std::endl;
		val[i / 2] = (uint8_t) strtol(c, NULL, 16);
	}
	std::cerr << libcdoc::Crypto::toHex(val) << std::endl;
	return std::move(val);
}

static std::vector<uint8_t>
fromStr(const std::string& str) {
	return std::vector<uint8_t>(str.cbegin(), str.cend());
}

struct ToolConf : public libcdoc::Configuration {
	std::string getValue(const std::string& param) override final {
		return "false";
	}
};

struct ToolCrypto : public libcdoc::CryptoBackend {
	const std::map<std::string,std::vector<uint8_t>>& _secrets;
	ToolCrypto(const std::map<std::string,std::vector<uint8_t>>& secrets) : _secrets(secrets) {}
	int decryptRSA(std::vector<uint8_t>& result, const std::vector<uint8_t> &data, bool oaep) const override final { return {}; }
	std::vector<uint8_t> deriveConcatKDF(const std::vector<uint8_t> &publicKey, const std::string &digest, int keySize,
		const std::vector<uint8_t> &algorithmID, const std::vector<uint8_t> &partyUInfo, const std::vector<uint8_t> &partyVInfo) const override final { return {}; }
	std::vector<uint8_t> deriveHMACExtract(const std::vector<uint8_t> &publicKey, const std::vector<uint8_t> &salt, int keySize) const override final { return {}; }
	int getSecret(std::vector<uint8_t>& secret, const std::string& label) override final {
		secret =_secrets.at(label);
		return (secret.empty()) ? INVALID_PARAMS : OK;
	}
};

int
encrypt(int argc, char *argv[])
{
	std::cerr << "Encrypting" << std::endl;
	std::vector<Recipient> rcpts;
	std::vector<std::string> files;
	std::string out;
	for (int i = 0; i < argc; i++) {
		if (!strcmp(argv[i], "--rcpt-cert") && ((i + 2) <= argc)) {
			rcpts.push_back({Recipient::CERT, argv[i + 1], readFile(toUTF8(argv[i + 2]))});
			i += 2;
		} else if (!strcmp(argv[i], "--rcpt-pwd") && ((i + 2) <= argc)) {
			rcpts.push_back({Recipient::PASSWORD, argv[i + 1], fromStr(argv[i + 2])});
			i += 2;
		} else if (!strcmp(argv[i], "--rcpt-key") && ((i + 2) <= argc)) {
			rcpts.push_back({Recipient::KEY, argv[i + 1], fromHex(argv[i + 2])});
			i += 2;
		} else if (!strcmp(argv[i], "--file") && ((i + 1) <= argc)) {
			files.push_back(argv[i + 1]);
			i += 1;
		} else if (!strcmp(argv[i], "--out") && ((i + 1) <= argc)) {
			out = argv[i + 1];
			i += 1;
		} else {
			print_usage(std::cerr, 1);
		}
	}
	if (rcpts.empty() || files.empty() || out.empty()) print_usage(std::cerr, 1);
	std::vector<std::shared_ptr<libcdoc::CKey>> keys;
	std::map<std::string,std::vector<uint8_t>> secrets;
	for (const Recipient& r : rcpts) {
		libcdoc::CKey *key = nullptr;
		if (r.type == Recipient::Type::CERT) {
			key = new libcdoc::CKeyCert(r.label, r.data);
			secrets[r.label] = {};
		} else if (r.type == Recipient::Type::KEY) {
			key = new libcdoc::CKeySymmetric(libcdoc::Crypto::random(), {}, 0);
			key->label = r.label;
			secrets[r.label] = r.data;
		} else if (r.type == Recipient::Type::PASSWORD) {
			key = new libcdoc::CKeySymmetric(libcdoc::Crypto::random(), libcdoc::Crypto::random(), 65535);
			key->label = r.label;
			secrets[r.label] = r.data;
		}
		keys.push_back(std::shared_ptr<libcdoc::CKey>(key));
	}
	std::vector<libcdoc::IOEntry> entries;
	for (const std::string& file : files) {
		std::ifstream *ifs = new std::ifstream(file);
		ifs->seekg(0, std::ios_base::seekdir::end);
		size_t size = ifs->tellg();
		ifs->seekg(0);
		entries.push_back({file, "id", "application/octet-stream", (int64_t) size, nullptr});
		entries.back().stream = std::shared_ptr<std::istream>(ifs);
	}
	ToolConf conf;
	ToolCrypto crypto(secrets);
	libcdoc::CDocWriter *writer = libcdoc::CDocWriter::createWriter(2, out, &conf, &crypto, nullptr);

	writer->encrypt(out, entries, keys);

	return 0;
}

int
main(int argc, char *argv[])
{
	if (argc < 2) print_usage(std::cerr, 1);
	std::cerr << "Command: " << argv[1] << std::endl;
	if (!strcmp(argv[1], "encrypt")) {
		return encrypt(argc - 2, argv + 2);
	}
	if(argc >= 5 && strcmp(argv[1], "encrypt") == 0)
	{
#if 0
		CDOC1Writer w(toUTF8(argv[argc-1]));
		for(int i = 2; i < argc - 1; ++i)
		{
			if (strcmp(argv[i], "-r") == 0)
			{
				w.addRecipient(readFile(toUTF8(argv[i + 1])));
				++i;
			}
			else
			{
				std::string inFile = toUTF8(argv[i]);
				size_t pos = inFile.find_last_of("/\\");
				w.addFile(pos == std::string::npos ? inFile : inFile.substr(pos + 1), "application/octet-stream", inFile);
			}
		}
		if(w.encrypt())
			std::cout << "Success" << std::endl;
		else
			std::cout << w.lastError() << std::endl;
#endif
	}
	else if(argc == 7 && strcmp(argv[1], "decrypt") == 0)
	{
		std::unique_ptr<Token> token;
		if (strcmp(argv[2], "pkcs11") == 0)
			token.reset(new PKCS11Token(toUTF8(argv[3]), argv[4]));
		else if (strcmp(argv[2], "pkcs12") == 0)
			token.reset(new PKCS12Token(toUTF8(argv[3]), argv[4]));
#ifdef _WIN32
		else if (strcmp(argv[2], "win") == 0)
			token.reset(new WinToken(strcmp(argv[3], "ui") == 0, argv[4]));
#endif
		CDOC1Reader r(toUTF8(argv[5]));
		if(r.mimeType() == "http://www.sk.ee/DigiDoc/v1.3.0/digidoc.xsd")
		{
			for(const DDOCReader::File &file: DDOCReader::files(r.decryptData(token.get())))
				writeFile(toUTF8(argv[6]) + "/" + file.name, file.data);
		}
		else
			writeFile(toUTF8(argv[6]) + "/" + r.fileName(), r.decryptData(token.get()));
	}
	else
	{
		print_usage(std::cout, 0);
	}
	return 0;
}
