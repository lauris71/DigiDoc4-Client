#ifndef __CDOCSUPPORT_H__
#define __CDOCSUPPORT_H__

/*
 * QDigiDocCrypto
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#include <fstream>
#include <sstream>

#include <QtCore/QObject>

#include <libcdoc/cdoc.h>

struct DDConfiguration : public libcdoc::Configuration {
	std::string getValue(const std::string& param) final;

	explicit DDConfiguration() = default;
};

struct DDCryptoBackend : public libcdoc::CryptoBackend {
	int decryptRSA(std::vector<uint8_t>& result, const std::vector<uint8_t> &data, bool oaep) const final;
	std::vector<uint8_t> deriveConcatKDF(const std::vector<uint8_t> &publicKey, const std::string &digest, int keySize,
		const std::vector<uint8_t> &algorithmID, const std::vector<uint8_t> &partyUInfo, const std::vector<uint8_t> &partyVInfo) const final;
	std::vector<uint8_t> deriveHMACExtract(const std::vector<uint8_t> &publicKey, const std::vector<uint8_t> &salt, int keySize) const final;
	int getSecret(std::vector<uint8_t>& secret, const std::string& label) final;

	std::vector<uint8_t> secret;

	explicit DDCryptoBackend() = default;
};

struct DDNetworkBackend : public libcdoc::NetworkBackend, private QObject {
	std::pair<std::string,std::string> sendKey(libcdoc::CDocWriter *writer, const std::vector<uint8_t> &recipient_id, const std::vector<uint8_t> &key_material, const std::string &type) final;
	std::vector<uint8_t> fetchKey(libcdoc::CDocReader *reader, const libcdoc::CKeyServer& key);

	explicit DDNetworkBackend() = default;
};

struct TempListConsumer : public libcdoc::MultiDataConsumer {
	static constexpr int64_t MAX_VEC_SIZE = 500L * 1024L * 1024L;

	size_t _max_memory_size;
	std::vector<libcdoc::IOEntry> files;
	explicit TempListConsumer(size_t max_memory_size = 500L * 1024L * 1024L) : _max_memory_size(max_memory_size) {}
	~TempListConsumer();
	int64_t write(const uint8_t *src, size_t size) override final;
	bool close() override final;
	bool isError() override final;
	bool open(const std::string& name, int64_t size) override final;
private:
	std::ostream *ofs = nullptr;

	std::stringstream *sstream = nullptr;
	std::ofstream *fstream = nullptr;
	std::string tmp_name;
};

#endif // __CDOCSUPPORT_H__
