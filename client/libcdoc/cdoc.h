#ifndef CDOC_H
#define CDOC_H

#include <istream>
#include <ostream>
#include <memory>
#include <string>
#include <vector>
#include <utility>

#include <libcdoc/keys.h>
#include <libcdoc/io.h>

// fixme:
// Bogus declaration until translation system is set up
#define t_(s) (s)

namespace libcdoc {

class CDocReader;
class CDocWriter;
class Certificate;
struct CKeyServer;

struct Configuration {
	static inline const char *USE_KEYSERVER = "USE_KEYSERVER";

	virtual std::string getValue(const std::string& param) = 0;

	bool getBoolean(const std::string& param);
};

struct CryptoBackend {
	virtual std::vector<uint8_t> decryptRSA(const std::vector<uint8_t> &data, bool oaep) const = 0;
	virtual std::vector<uint8_t> deriveConcatKDF(const std::vector<uint8_t> &publicKey, const std::string &digest, int keySize,
		const std::vector<uint8_t> &algorithmID, const std::vector<uint8_t> &partyUInfo, const std::vector<uint8_t> &partyVInfo) const = 0;
	virtual std::vector<uint8_t> deriveHMACExtract(const std::vector<uint8_t> &publicKey, const std::vector<uint8_t> &salt, int keySize) const = 0;
	// Derive KEK
	// PBKDF2_SHA256 password pw_salt iter
	// HKDF extract salt
	// HKDF expand info
	// If kdf_iter is 0, secret is symmetric key, otherwise plaintext password
	virtual bool getSecret(std::vector<uint8_t>& secret, const std::string& label) { return false; }
	// Default implementation calls getSecret and calculates hash
	virtual bool getKeyMaterial(std::vector<uint8_t>& key_material, const std::vector<uint8_t> pw_salt, int32_t kdf_iter, const std::string& label);
	// Default implementation calls ::getKeyMaterial
	virtual bool getKEK(std::vector<uint8_t>& kek, const std::vector<uint8_t>& salt, const std::vector<uint8_t> pw_salt, int32_t kdf_iter,
				const std::string& label, const std::string& info);
};

struct NetworkBackend {
	virtual std::pair<std::string,std::string> sendKey (CDocWriter *writer, const std::vector<uint8_t> &recipient_id, const std::vector<uint8_t> &key_material, const std::string &type) = 0;
	virtual std::vector<uint8_t> fetchKey (CDocReader *reader, const libcdoc::CKeyServer& key) = 0;
};

class CDocReader {
public:
	virtual ~CDocReader() = default;

	virtual uint32_t getVersion() = 0;
	virtual const std::vector<std::shared_ptr<CKey>>& getKeys() = 0;
	virtual CKey::DecryptionStatus canDecrypt(const Certificate &cert) = 0;
	virtual std::shared_ptr<libcdoc::CKey> getDecryptionKey(const Certificate &cert) = 0;
	virtual std::vector<uint8_t> getFMK(const libcdoc::CKey &key, const std::vector<uint8_t>& secret) = 0;
	virtual bool decryptPayload(const std::vector<uint8_t>& fmk, MultiDataConsumer *consumer) = 0;

	void setLastError(const std::string& message) { last_error = message; }
	std::string getLastError() { return last_error; }

	// Returns < 0 if not CDoc file
	static int getCDocFileVersion(const std::string& path);
	std::vector<IOEntry> decryptPayload(const std::vector<uint8_t> &fmk);

	static CDocReader *createReader(const std::string& path, Configuration *conf, CryptoBackend *crypto, NetworkBackend *network);
protected:
	explicit CDocReader() = default;

	std::string last_error;

	Configuration *conf = nullptr;
	CryptoBackend *crypto = nullptr;
	NetworkBackend *network = nullptr;
};

class CDocWriter {
public:
	virtual ~CDocWriter() = default;

	virtual uint32_t getVersion() = 0;
	std::string getLastError() { return last_error; }
	virtual bool encrypt(std::ostream& ofs, MultiDataSource& src, const std::vector<std::shared_ptr<libcdoc::EncKey>>& keys) = 0;

	bool encrypt(const std::string& filename, const std::vector<IOEntry>& files, const std::vector<std::shared_ptr<libcdoc::EncKey>>& keys);
	void setLastError(const std::string& message) { last_error = message; }

	static CDocWriter *createWriter(int version, const std::string& filename, Configuration *conf, CryptoBackend *crypto, NetworkBackend *network);
protected:
	explicit CDocWriter() = default;

	std::string last_error;

	Configuration *conf = nullptr;
	CryptoBackend *crypto = nullptr;
	NetworkBackend *network = nullptr;
};

}; // namespace libcdoc

#endif // CDOC_H
