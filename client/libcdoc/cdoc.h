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

/**
 * @brief A configuration provider.
 * Subclasses can implement different configuration systems (registry, .ini files etc.) by overriding getValue.
 */
struct Configuration {
	static inline const char *USE_KEYSERVER = "USE_KEYSERVER";

	virtual std::string getValue(const std::string& param) = 0;

	bool getBoolean(const std::string& param);
};

/**
 * @brief An authentication provider
 * Implements cryptographic methods that potentially need either user action (supplying password) or external communication (PKCS11).
 *
 */
struct CryptoBackend {
	static constexpr int OK = 0;
	static constexpr int NOT_IMPLEMENTED = -200;
	static constexpr int INVALID_PARAMS = -201;
	static constexpr int OPENSSL_ERROR = -202;

	virtual std::string getLastErrorStr(int code) const;

	/**
	 * @brief Fill vector with random bytes
	 * Trim vector to requested size and fill it with random bytes. The default implementation uses OpenSSL randomness generator.
	 * @param dst the destination container for randomness
	 * @param size the requested amount of random data
	 * @return  error code or OK
	 */
	virtual int random(std::vector<uint8_t> dst, uint32_t size);
	/**
	 * @brief Derive shared secret
	 * @param result the destination container for shared key
	 * @param public_key ECDH public Key used to derive shared secret
	 * @return error code or OK
	 */
	virtual int derive(std::vector<uint8_t>& dst, const std::vector<uint8_t> &public_key) { return NOT_IMPLEMENTED; }
	/**
	 * @brief decryptRSA
	 * @param dst the destination container for decrypted data
	 * @param data encrypted data
	 * @param oaep
	 * @return error code or OK
	 */
	virtual int decryptRSA(std::vector<uint8_t>& dst, const std::vector<uint8_t> &data, bool oaep) const = 0;
	/**
	 * @brief Derive key by ConcatKDF algorithm
	 * The ConcatKDF key derivation algorithm is defined in Section 5.8.1 of NIST SP 800-56A.
	 * The default implementation calls derive and performs concatKDF
	 * @param dst the container for derived key
	 * @param publicKey ECDH public Key used to derive shared secret
	 * @param digest Digest method to use for ConcatKDF algorithm
	 * @param keySize Key size to output
	 * @param algorithmID OtherInfo info parameters to input
	 * @param partyUInfo OtherInfo info parameters to input
	 * @param partyVInfo OtherInfo info parameters to input
	 * @return error code or OK
	 */
	virtual int  deriveConcatKDF(std::vector<uint8_t>& dst, const std::vector<uint8_t> &publicKey, const std::string &digest, int keySize,
		const std::vector<uint8_t> &algorithmID, const std::vector<uint8_t> &partyUInfo, const std::vector<uint8_t> &partyVInfo);

	virtual std::vector<uint8_t> deriveHMACExtract(const std::vector<uint8_t> &publicKey, const std::vector<uint8_t> &salt, int keySize) const = 0;
	// Derive KEK
	// PBKDF2_SHA256 password pw_salt iter
	// HKDF extract salt
	// HKDF expand info
	// If kdf_iter is 0, secret is symmetric key, otherwise plaintext password
	/**
	 * @brief Get secret value (either password or symmetric key)
	 * @param secret the destination container for secret
	 * @param label label the label of the capsule (key)
	 * @return error code or OK
	 */
	virtual int getSecret(std::vector<uint8_t>& secret, const std::string& label) { return NOT_IMPLEMENTED; }
	/**
	 * @brief Get CDoc2 key material for HKDF expansion
	 * Fetches key material for a given symmetric key (either password or key-based).
	 * The default implementation calls getSecret and performs PBKDF2_SHA256 if key is password-based.
	 * @param key_material the destination container for key material
	 * @param pw_salt the salt value for PBKDF
	 * @param kdf_iter kdf_iter the number of KDF iterations. If kdf_iter is 0, the key is plain symmetric key instead of password.
	 * @param label the label of the capsule (key)
	 * @return error code or OK
	 */
	virtual int getKeyMaterial(std::vector<uint8_t>& key_material, const std::vector<uint8_t> pw_salt, int32_t kdf_iter, const std::string& label);
	/**
	 * @brief Get CDoc2 KEK for symmetric key
	 * Fetches KEK (Key Encryption Key) for a given symmetric key (either password or key-based).
	 * The default implementation calls getKeyMaterial and performs HKDF extract + expand.
	 * @param kek the destination container for KEK
	 * @param salt the salt value for HKDF extract
	 * @param pw_salt the salt value for PBKDF
	 * @param kdf_iter the number of KDF iterations. If kdf_iter is 0, the key is plain symmetric key instead of password.
	 * @param label the label of the capsule (key)
	 * @param expand_salt the salt for HKDF expand
	 * @return error code or OK
	 */
	virtual int getKEK(std::vector<uint8_t>& kek, const std::vector<uint8_t>& salt, const std::vector<uint8_t> pw_salt, int32_t kdf_iter,
				const std::string& label, const std::string& expand_salt);
};

struct NetworkBackend {
	static constexpr int OK = 0;
	static constexpr int NOT_IMPLEMENTED = -300;
	static constexpr int INVALID_PARAMS = -301;
	static constexpr int NETWORK_ERROR = -302;

	virtual std::string getLastErrorStr(int code) const;

	virtual std::pair<std::string,std::string> sendKey (CDocWriter *writer, const std::vector<uint8_t> &recipient_id, const std::vector<uint8_t> &key_material, const std::string &type) = 0;
	virtual std::vector<uint8_t> fetchKey (CDocReader *reader, const libcdoc::CKeyServer& key) = 0;
};
/**
 * @brief The CDocReader class
 * An abstract class fro CDoc1 and CDoc2 readers. Provides unified interface for loading and decryption.
 */
class CDocReader {
public:
	virtual ~CDocReader() = default;

	virtual uint32_t getVersion() = 0;
	/**
	 * @brief Get encryption keys in given document
	 * @return a vector of keys
	 */
	virtual const std::vector<std::shared_ptr<DecKey>>& getKeys() = 0;
	/**
	 * @brief Tests if the public key of given X509 certificate is among document keys
	 * @param cert a X509 certificate (der)
	 * @return true if key is found
	 */
	virtual CKey::DecryptionStatus canDecrypt(const Certificate &cert) = 0;
	/**
	 * @brief Fetches the encryption key for given certificate
	 * @param cert a x509 certificate (der)
	 * @return the key or nullptr if not found
	 */
	virtual std::shared_ptr<libcdoc::DecKey> getDecryptionKey(const Certificate &cert) = 0;
	/**
	 * @brief Fetches FMK from provided key
	 * Fetches FMK (File Master Key) from the provided encryption key. Depending on the key type it uses relevant CryptoBackend and/or
	 * NetworkBackend methods to either fetch secret and derive key or perform external decryption of encrypted KEK.
	 * @param fmk The FMK of the document
	 * @param key a key (from document key list)
	 * @return true if successful
	 */
	virtual bool getFMK(std::vector<uint8_t>& fmk, const libcdoc::CKey &key) = 0;
	/**
	 * @brief Decrypt document
	 * Decrypts the encrypted content and writes files to provided output object
	 * @param fmk The FMK of the document
	 * @param consumer a consumer of decrypted files
	 * @return true if successful
	 */
	virtual bool decryptPayload(const std::vector<uint8_t>& fmk, MultiDataConsumer *consumer) = 0;

	void setLastError(const std::string& message) { last_error = message; }
	std::string getLastError() { return last_error; }

	// Returns < 0 if not CDoc file
	static int getCDocFileVersion(const std::string& path);

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
	virtual bool encrypt(std::ostream& ofs, MultiDataSource& src, const std::vector<std::shared_ptr<libcdoc::EncKey>>& keys) = 0;

	std::string getLastError() { return last_error; }
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
