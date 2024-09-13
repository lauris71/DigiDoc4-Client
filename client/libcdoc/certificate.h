#ifndef SSLCERTIFICATE_H
#define SSLCERTIFICATE_H

#include <cstdint>
#include <string>
#include <vector>

namespace libcdoc {

class Certificate {
public:
	enum Algorithm {
		RSA,
		ECC
	};

	std::vector<uint8_t> cert;

	Certificate(const std::vector<uint8_t> _cert) : cert(_cert) {}

	std::string getCommonName() const;
	std::string getGivenName() const;
	std::string getSurname() const;
	std::string getSerialNumber() const;

	std::vector<std::string> policies() const;

	std::vector<uint8_t> getPublicKey() const;
	Algorithm getAlgorithm() const;
};

} // Namespace

#endif // SSLCERTIFICATE_H
