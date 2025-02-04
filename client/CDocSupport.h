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

#include <QtCore/QObject>

#include <cdoc/Configuration.h>
#include <cdoc/CryptoBackend.h>
#include <cdoc/NetworkBackend.h>
#include <cdoc/Io.h>

struct DDConfiguration : public libcdoc::Configuration {
    std::string getValue(const std::string_view& param) final;
    std::string getValue(const std::string_view& domain, const std::string_view& param) final;

	explicit DDConfiguration() = default;
};

struct DDCryptoBackend : public libcdoc::CryptoBackend {
    int decryptRSA(std::vector<uint8_t>& result, const std::vector<uint8_t> &data, bool oaep, unsigned int idx) override final;
	int deriveConcatKDF(std::vector<uint8_t>& dst, const std::vector<uint8_t> &publicKey, const std::string &digest,
						const std::vector<uint8_t> &algorithmID, const std::vector<uint8_t> &partyUInfo, const std::vector<uint8_t> &partyVInfo,
                        unsigned int idx) override final;
    int deriveHMACExtract(std::vector<uint8_t>& dst, const std::vector<uint8_t> &publicKey, const std::vector<uint8_t> &salt, unsigned int idx) override final;
    int getSecret(std::vector<uint8_t>& secret, unsigned int idx) override final;

	std::vector<uint8_t> secret;

	explicit DDCryptoBackend() = default;
};

struct DDNetworkBackend : public libcdoc::NetworkBackend, private QObject {
	static constexpr int BACKEND_ERROR = -303;

	std::string getLastErrorStr(int code) const final;
    int sendKey(libcdoc::NetworkBackend::CapsuleInfo& dst, const std::string& url, const std::vector<uint8_t>& rcpt_key, const std::vector<uint8_t> &key_material, const std::string &type) override final;
    int fetchKey(std::vector<uint8_t>& result, const std::string& keyserver_id, const std::string& transaction_id) override final;

    int getClientTLSCertificate(std::vector<uint8_t>& dst) override final { return libcdoc::NOT_IMPLEMENTED; }
    int getPeerTLSCertificates(std::vector<std::vector<uint8_t>> &dst) override final { return libcdoc::NOT_IMPLEMENTED; }

    explicit DDNetworkBackend() = default;

	std::string last_error;
};

struct IOEntry
{
	std::string name, mime;
	int64_t size;
	//std::shared_ptr<std::istream> stream;
	std::unique_ptr<QIODevice> data;
};

struct TempListConsumer : public libcdoc::MultiDataConsumer {
	static constexpr int64_t MAX_VEC_SIZE = 500L * 1024L * 1024L;

	size_t _max_memory_size;
	std::vector<IOEntry> files;
	explicit TempListConsumer(size_t max_memory_size = 500L * 1024L * 1024L) : _max_memory_size(max_memory_size) {}
	~TempListConsumer();
	int64_t write(const uint8_t *src, size_t size) override final;
	int close() override final;
	bool isError() override final;
	int open(const std::string& name, int64_t size) override final;
private:
	//std::ostream *ofs = nullptr;

	//std::stringstream *sstream = nullptr;
	//std::ofstream *fstream = nullptr;
	//std::string tmp_name;
};

struct StreamListSource : public libcdoc::MultiDataSource {
	StreamListSource(const std::vector<IOEntry>& files);
	int64_t read(uint8_t *dst, size_t size) override final;
	bool isError() override final;
	bool isEof() override final;
	size_t getNumComponents() override final;
	int next(std::string& name, int64_t& size) override final;

	const std::vector<IOEntry>& _files;
	int64_t _current;
};

#endif // __CDOCSUPPORT_H__
