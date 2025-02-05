/*
 * QDigiDocClient
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

#include "CDoc2.h"

#include "Application.h"
#include "CheckConnection.h"
#include "Crypto.h"
#include "QCryptoBackend.h"
#include "QSigner.h"
#include "Settings.h"
#include "TokenData.h"
#include "Utils.h"
#include "header_generated.h"
#include "effects/FadeInNotification.h"
#include "openssl/kdf.h"

#include <QtCore/QBuffer>
#include <QtCore/QDebug>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonObject>
#include <QtCore/QtEndian>
#include <QtCore/QTemporaryFile>
#include <QtNetwork/QNetworkAccessManager>
#include <QtNetwork/QNetworkReply>
#include <QtNetwork/QSslKey>
#include <QPasswordDigestor>

#include <openssl/x509.h>

#include <zlib.h>

using cdoc20::recipients::KeyServerCapsule;
using cdoc20::recipients::KeyDetailsUnion;
using cdoc20::recipients::EccKeyDetails;
using cdoc20::recipients::RsaKeyDetails;

const QByteArray CDoc2::LABEL = "CDOC\x02";
const QByteArray CDoc2::CEK = "CDOC2cek";
const QByteArray CDoc2::HMAC = "CDOC2hmac";
const QByteArray CDoc2::KEK = "CDOC2kek";
const QByteArray CDoc2::KEKPREMASTER = "CDOC2kekpremaster";
const QByteArray CDoc2::PAYLOAD = "CDOC2payload";
const QByteArray CDoc2::SALT = "CDOC2salt";

namespace cdoc20 {
	bool checkConnection() {
		if(CheckConnection().check())
			return true;
		return dispatchToMain([] {
			FadeInNotification::error(Application::mainWindow()->findChild<QWidget*>(QStringLiteral("topBar")),
				QCoreApplication::translate("MainWindow", "Check internet connection"));
			return false;
		});
	}

	QNetworkRequest req(const QString &keyserver_id, const QString &transaction_id = {}) {
#ifdef CONFIG_URL
		QJsonObject list = Application::confValue(QLatin1String("CDOC2-CONF")).toObject();
		QJsonObject data = list.value(keyserver_id).toObject();
		QString url = transaction_id.isEmpty() ?
			data.value(QLatin1String("POST")).toString(Settings::CDOC2_POST) :
			data.value(QLatin1String("FETCH")).toString(Settings::CDOC2_GET);
#else
		QString url = transaction_id.isEmpty() ? Settings::CDOC2_POST : Settings::CDOC2_GET;
#endif
		if(url.isEmpty())
			return QNetworkRequest{};
		QNetworkRequest req(QStringLiteral("%1/key-capsules%2").arg(url,
			transaction_id.isEmpty() ? QString(): QStringLiteral("/%1").arg(transaction_id)));
		req.setHeader(QNetworkRequest::ContentTypeHeader, QStringLiteral("application/json"));
		return req;
	}

	struct stream final: public QIODevice
	{
		static constexpr qint64 CHUNK = 16LL * 1024LL;
		QIODevice *io {};
		Crypto::Cipher *cipher {};
		z_stream s {};
		QByteArray buf;
		int flush = Z_NO_FLUSH;

		stream(QIODevice *_io, Crypto::Cipher *_cipher)
			: io(_io)
			, cipher(_cipher)
		{
			if(io->isReadable())
			{
				if(inflateInit2(&s, MAX_WBITS) == Z_OK)
					open(QIODevice::ReadOnly);
			}
			if(io->isWritable())
			{
				if(deflateInit(&s, Z_DEFAULT_COMPRESSION) == Z_OK)
					open(QIODevice::WriteOnly);
			}
		}

		~stream() final
		{
			if(io->isReadable())
				inflateEnd(&s);
			if(io->isWritable())
			{
				flush = Z_FINISH;
				writeData(nullptr, 0);
				deflateEnd(&s);
			}
		}

		bool isSequential() const final
		{
			return true;
		}

		qint64 bytesAvailable() const final
		{
			return (io->bytesAvailable() -  Crypto::Cipher::tagLen()) + buf.size() + QIODevice::bytesAvailable();
		}

		qint64 readData(char *data, qint64 maxlen) final
		{
			s.next_out = (Bytef*)data;
			s.avail_out = uInt(maxlen);
			std::array<char,CHUNK> in{};
			for(int res = Z_OK; s.avail_out > 0 && res == Z_OK;)
			{
				if(auto insize = io->bytesAvailable() -  Crypto::Cipher::tagLen(),
					size = io->read(in.data(), qMin<qint64>(insize, in.size())); size > 0)
				{
					if(!cipher->update(in.data(), int(size)))
						return -1;
					buf.append(in.data(), size);
				}
				s.next_in = (z_const Bytef*)buf.data();
				s.avail_in = uInt(buf.size());
				switch(res = inflate(&s, flush))
				{
				case Z_OK:
					buf = buf.right(s.avail_in);
					break;
				case Z_STREAM_END:
					buf.clear();
					break;
				default: return -1;
				}
			}
			return qint64(maxlen - s.avail_out);
		}

		qint64 writeData(const char *data, qint64 len) final
		{
			s.next_in = (z_const Bytef *)data;
			s.avail_in = uInt(len);
			std::array<char,CHUNK> out{};
			while(true) {
				s.next_out = (Bytef *)out.data();
				s.avail_out = out.size();
				int res = deflate(&s, flush);
				if(res == Z_STREAM_ERROR)
					return -1;
				if(auto size = out.size() - s.avail_out; size > 0)
				{
					if(!cipher->update(out.data(), int(size)) ||
						io->write(out.data(), size) != size)
						return -1;
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
	};

	struct TAR {
		std::unique_ptr<QIODevice> io;
		explicit TAR(std::unique_ptr<QIODevice> &&in)
			: io(std::move(in))
		{}

		bool save(const std::vector<CDoc::File> &files)
		{
			auto writeHeader = [this](Header &h, qint64 size) {
				h.chksum.fill(' ');
				toOctal(h.size, size);
				toOctal(h.chksum, h.checksum().first);
				return io->write((const char*)&h, Header::Size) == Header::Size;
			};
			auto writePadding = [this](qint64 size) {
				QByteArray pad(padding(size), 0);
				return io->write(pad) == pad.size();
			};
			auto toPaxRecord = [](const QByteArray &keyword, const QByteArray &value) {
				QByteArray record = ' ' + keyword + '=' + value + '\n';
				QByteArray result;
				for(auto len = record.size(); result.size() != len; ++len)
					result = QByteArray::number(len + 1) + record;
				return result;
			};
			for(const CDoc::File &file: files)
			{
				Header h {};
				QByteArray filename = file.name.toUtf8();
				QByteArray filenameTruncated = filename.left(h.name.size());
				std::copy(filenameTruncated.cbegin(), filenameTruncated.cend(), h.name.begin());

				if(filename.size() > 100 ||
					file.size > 07777777)
				{
					h.typeflag = 'x';
					QByteArray paxData;
					if(filename.size() > 100)
						paxData += toPaxRecord("path", filename);
					if(file.size > 07777777)
						paxData += toPaxRecord("size", QByteArray::number(file.size));
					if(!writeHeader(h, paxData.size()) ||
						io->write(paxData) != paxData.size() ||
						!writePadding(paxData.size()))
						return false;
				}

				h.typeflag = '0';
				if(!writeHeader(h, file.size))
					return false;
				file.data->seek(0);
				if(auto size = copyIODevice(file.data.get(), io.get()); size < 0 || !writePadding(size))
					return false;
			}
			return io->write((const char*)&Header::Empty, Header::Size) == Header::Size &&
				io->write((const char*)&Header::Empty, Header::Size) == Header::Size;
		}

		std::vector<CDoc::File> files(bool &warning) const
		{
			std::vector<CDoc::File> result;
			Header h {};
			auto readHeader = [&h, this] { return io->read((char*)&h, Header::Size) == Header::Size; };
			while(io->bytesAvailable() > 0)
			{
				if(!readHeader())
					return {};
				if(h.isNull())
				{
					if(!readHeader() && !h.isNull())
						return {};
					warning = io->bytesAvailable() > 0;
					return result;
				}
				if(!h.verify())
					return {};

				CDoc::File f;
				f.name = QString::fromUtf8(h.name.data(), std::min<int>(h.name.size(), int(strlen(h.name.data()))));
				f.size = fromOctal(h.size);
				if(h.typeflag == 'x')
				{
					QByteArray paxData = io->read(f.size);
					if(paxData.size() != f.size)
						return {};
					io->skip(padding(f.size));
					if(!readHeader() || h.isNull() || !h.verify())
						return {};
					if(f.name.startsWith(QLatin1String("./PaxHeaders.X")))
						f.name = QString::fromUtf8(h.name.data(), std::min<int>(h.name.size(), int(strlen(h.name.data()))));
					f.size = fromOctal(h.size);
					for(const QByteArray &data: paxData.split('\n'))
					{
						if(data.isEmpty())
							break;
						const auto &headerValue = data.split('=');
						const auto &lenKeyword = headerValue[0].split(' ');
						if(data.size() + 1 != lenKeyword[0].toUInt())
							return {};
						if(lenKeyword[1] == "path")
							f.name = QString::fromUtf8(headerValue[1]);
						if(lenKeyword[1] == "size")
							f.size = headerValue[1].toUInt();
					}
				}

				if(h.typeflag == '0' || h.typeflag == 0)
				{
					if(f.size > 500L * 1024L * 1024L)
						f.data = std::make_unique<QTemporaryFile>();
					else
						f.data = std::make_unique<QBuffer>();
					f.data->open(QIODevice::ReadWrite);
					if(f.size != copyIODevice(io.get(), f.data.get(), f.size))
						return {};
					io->skip(padding(f.size));
					result.push_back(std::move(f));
				}
				else
					io->skip(f.size + padding(f.size));
			}
			return result;
		}

	private:
		struct Header {
			std::array<char,100> name;
			std::array<char,  8> mode;
			std::array<char,  8> uid;
			std::array<char,  8> gid;
			std::array<char, 12> size;
			std::array<char, 12> mtime;
			std::array<char,  8> chksum;
			char typeflag;
			std::array<char,100> linkname;
			std::array<char,  6> magic;
			std::array<char,  2> version;
			std::array<char, 32> uname;
			std::array<char, 32> gname;
			std::array<char,  8> devmajor;
			std::array<char,  8> devminor;
			std::array<char,155> prefix;
			std::array<char, 12> padding;

			std::pair<int64_t,int64_t> checksum() const
			{
				int64_t unsignedSum = 0;
				int64_t signedSum = 0;
				for (size_t i = 0, size = sizeof(Header); i < size; i++) {
					unsignedSum += ((unsigned char*) this)[i];
					signedSum += ((signed char*) this)[i];
				}
				return {unsignedSum, signedSum};
			}

			bool isNull() {
				return memcmp(this, &Empty, sizeof(Header)) == 0;
			}

			bool verify() {
				auto copy = chksum;
				chksum.fill(' ');
				auto checkSum = checksum();
				chksum.swap(copy);
				int64_t referenceChecksum = fromOctal(chksum);
				return referenceChecksum == checkSum.first ||
					   referenceChecksum == checkSum.second;
			}

			static const Header Empty;
			static const int Size;
		};

		template<std::size_t SIZE>
		static int64_t fromOctal(const std::array<char,SIZE> &data)
		{
			int64_t i = 0;
			for(const char c: data)
			{
				if(c < '0' || c > '7')
					continue;
				i <<= 3;
				i += c - '0';
			}
			return i;
		}

		template<std::size_t SIZE>
		static void toOctal(std::array<char,SIZE> &data, int64_t value)
		{
			data.fill(' ');
			for(auto it = data.rbegin() + 1; it != data.rend(); ++it)
			{
				*it = char(value & 7) + '0';
				value >>= 3;
			}
		}

		static constexpr int padding(int64_t size)
		{
			return Header::Size - size % Header::Size;
		}
	};

	const TAR::Header TAR::Header::Empty {};
	const int TAR::Header::Size = int(sizeof(TAR::Header));
}

bool
CDoc2::isCDoc2File(const QString& path)
{
	QFile f(path);
	if(!f.open(QFile::ReadOnly)) return false;
	if (f.read(LABEL.length()) != LABEL) return false;
	return true;
}

CDoc2::CDoc2(const QString &_path)
: path(_path)
/*	: QFile(path) */
{
	using namespace cdoc20::recipients;
	using namespace cdoc20::header;
	setLastError(QStringLiteral("Invalid CDoc 2.0 header"));
	uint32_t header_len = 0;
	QFile ifs(path);
	if(!ifs.open(QFile::ReadOnly) ||
		ifs.read(LABEL.length()) != LABEL ||
		ifs.read((char*)&header_len, int(sizeof(header_len))) != int(sizeof(header_len)))
		return;
	header_data = ifs.read(qFromBigEndian<uint32_t>(header_len));
	if(header_data.size() != qFromBigEndian<uint32_t>(header_len))
		return;
	headerHMAC = ifs.read(KEY_LEN);
	if(headerHMAC.size() != KEY_LEN)
		return;
	noncePos = ifs.pos();
	ifs.close();
	flatbuffers::Verifier verifier(reinterpret_cast<const uint8_t*>(header_data.data()), header_data.size());
	if(!VerifyHeaderBuffer(verifier))
		return;
	const auto *header = GetHeader(header_data.constData());
	if(!header)
		return;
	if(header->payload_encryption_method() != PayloadEncryptionMethod::CHACHA20POLY1305)
		return;
	const auto *recipients = header->recipients();
	if(!recipients)
		return;
	setLastError({});

	auto toByteArray = [](const flatbuffers::Vector<uint8_t> *data) -> QByteArray {
		return data ? QByteArray((const char*)data->Data(), int(data->size())) : QByteArray();
	};
	auto toString = [](const flatbuffers::String *data) -> QString {
		return data ? QString::fromUtf8(data->c_str(), data->size()) : QString();
	};
	for(const auto *recipient: *recipients){
		if(recipient->fmk_encryption_method() != FMKEncryptionMethod::XOR)
		{
            keys.append(std::make_shared<CKey>(CKey::Unsupported));
			qWarning() << "Unsupported FMK encryption method: skipping";
			continue;
		}
		auto fillRecipientPK = [&] (CKey::PKType pk_type, auto key, bool unsupported = false) {
			std::shared_ptr<CKeyPK> k(new CKeyPK(pk_type, toByteArray(key->recipient_public_key())));
			k->label = toString(recipient->key_label());
			k->cipher = toByteArray(recipient->encrypted_fmk());
			k->unsupported = unsupported;
			return k;
		};
		switch(recipient->capsule_type())
		{
		case Capsule::ECCPublicKeyCapsule:
			if(const auto *key = recipient->capsule_as_ECCPublicKeyCapsule())
			{
                std::shared_ptr<CKey> k = fillRecipientPK(CKey::PKType::ECC, key, key->curve() != EllipticCurve::secp384r1);
				k->publicKey = toByteArray(key->sender_public_key());
				keys.append(k);
			}
			break;
		case Capsule::RSAPublicKeyCapsule:
			if(const auto *key = recipient->capsule_as_RSAPublicKeyCapsule())
			{
				std::shared_ptr<CKeyPK> k = fillRecipientPK(CKey::PKType::RSA, key);
				k->encrypted_kek = toByteArray(key->encrypted_kek());
				keys.append(k);
			}
			break;
		case Capsule::KeyServerCapsule:
			if (const KeyServerCapsule *server = recipient->capsule_as_KeyServerCapsule()) {
				KeyDetailsUnion details = server->recipient_key_details_type();
				std::shared_ptr<CKeyServer> ckey = nullptr;
				switch (details) {
				case KeyDetailsUnion::EccKeyDetails:
					if(const EccKeyDetails *eccDetails = server->recipient_key_details_as_EccKeyDetails()) {
						ckey = CKeyServer::fromKey(toByteArray(eccDetails->recipient_public_key()), CKey::PKType::ECC);
						ckey->unsupported = eccDetails->curve() != EllipticCurve::secp384r1;
					} else {
						qWarning() << "Invalid file format";
					}
					break;
				case KeyDetailsUnion::RsaKeyDetails:
					if(const RsaKeyDetails *rsaDetails = server->recipient_key_details_as_RsaKeyDetails()) {
						ckey = CKeyServer::fromKey(toByteArray(rsaDetails->recipient_public_key()), CKey::PKType::RSA);
					} else {
						qWarning() << "Invalid file format";
					}
					break;
				default:
                    keys.append(std::make_shared<CKey>(CKey::Unsupported));
					qWarning() << "Unsupported Key Server Details: skipping";
				}
				if (ckey) {
					ckey->label = toString(recipient->key_label());
					ckey->cipher = toByteArray(recipient->encrypted_fmk());
					ckey->keyserver_id = toString(server->keyserver_id());
					ckey->transaction_id = toString(server->transaction_id());
					keys.append(ckey);
				}
			} else {
				qWarning() << "Invalid file format";
			}
			break;
		case Capsule::SymmetricKeyCapsule:
			if(const auto *capsule = recipient->capsule_as_SymmetricKeyCapsule())
			{
				auto salt = capsule->salt();
				std::shared_ptr<CKeySymmetric> key(new CKeySymmetric(toByteArray(salt)));
				key->label = toString(recipient->key_label());
                key->cipher = toByteArray(recipient->encrypted_fmk());
                keys.append(key);
			}
			break;
		case Capsule::PBKDF2Capsule:
			if(const auto *capsule = recipient->capsule_as_PBKDF2Capsule()) {
				KDFAlgorithmIdentifier kdf_id = capsule->kdf_algorithm_identifier();
				if (kdf_id != KDFAlgorithmIdentifier::PBKDF2WithHmacSHA256) {
					qWarning() << "Unsupported KDF algorithm: skipping";
					continue;
				}
				auto salt = capsule->salt();
				auto pw_salt = capsule->password_salt();
				int32_t kdf_iter = capsule->kdf_iterations();
				std::shared_ptr<CKeySymmetric> key(new CKeySymmetric(toByteArray(salt)));
				key->label = toString(recipient->key_label());
                key->cipher = toByteArray(recipient->encrypted_fmk());
				key->pw_salt = toByteArray(pw_salt);
				key->kdf_iter = kdf_iter;
				keys.append(key);
			}
			break;
		default:
            keys.append(std::make_shared<CKey>(CKey::Unsupported));
			qWarning() << "Unsupported Key Details: skipping";
		}
	}
}

std::unique_ptr<CDoc2>
CDoc2::load(const QString& path)
{
	CDoc2 *cdoc = new CDoc2(path);
	return std::unique_ptr<CDoc2>(cdoc);
}

CKey::DecryptionStatus
CDoc2::canDecrypt(const QSslCertificate &cert) const
{
	std::shared_ptr<CKey> t = CKeyCD1::fromCertificate(cert);
	for (std::shared_ptr<CKey> key: keys) {
		switch (key->type) {
			case CKey::Type::CDOC1:
				if (*key == *t) return CKey::CAN_DECRYPT;
				break;
			case CKey::Type::SYMMETRIC_KEY:
				return CKey::DecryptionStatus::NEED_KEY;
			case CKey::Type::PUBLICKEY:
			case CKey::Type::SERVER:
				break;
		}
	}
	return CKey::DecryptionStatus::CANNOT_DECRYPT;
}

std::shared_ptr<CKey> CDoc2::getDecryptionKey(const QSslCertificate &cert) const
{
	if (cert.expiryDate() <= QDateTime::currentDateTimeUtc()) return {};
	std::shared_ptr<CKey> t = CKeyCD1::fromCertificate(cert);
	for (std::shared_ptr<CKey> key: keys) {
		switch (key->type) {
			case CKey::Type::CDOC1:
				if (*key == *t) return key;
				break;
			case CKey::Type::SYMMETRIC_KEY:
				return key;
			case CKey::Type::PUBLICKEY:
			case CKey::Type::SERVER:
				break;
		}
	}
	return {};
}

bool CDoc2::decryptPayload(const QByteArray &fmk)
{
	QFile ifs(path);
	if(!ifs.open(QFile::ReadOnly)) return false;
	if (noncePos < 0) return false;
	setLastError({});
	ifs.seek(noncePos);
	QByteArray cek = Crypto::expand(fmk, CEK);
	QByteArray nonce = ifs.read(NONCE_LEN);
#ifndef NDEBUG
	qDebug() << "cek" << cek.toHex();
	qDebug() << "nonce" << nonce.toHex();
#endif
	Crypto::Cipher dec(EVP_chacha20_poly1305(), cek, nonce, false);
	if(!dec.updateAAD(PAYLOAD + header_data + headerHMAC))
		return false;
	bool warning = false;
	files = cdoc20::TAR(std::unique_ptr<QIODevice>(new cdoc20::stream(&ifs, &dec))).files(warning);
	if(warning)
		setLastError(tr("CDoc contains additional payload data that is not part of content"));
	QByteArray tag = ifs.read(16);
	ifs.close();
#ifndef NDEBUG
	qDebug() << "tag" << tag.toHex();
#endif
	dec.setTag(tag);
	if(!dec.result())
		files.clear();
	return !files.empty();
}

class TmpFile : public QFile {
public:
	/* Existing file */
	std::filesystem::path current_name;
	/* Temporary file */
	std::filesystem::path tmp_name;

	TmpFile(const QString& name) : current_name(name.toStdString()) {}

	~TmpFile() {
		/* Close it to avoid overloaded close() to be called */
		if (isOpen()) QFile::close();
	}

	/* "Open" the file - by actually opening temporary in the same directory */
	bool open() {
		if (isOpen()) return false;
		tmp_name = current_name;
		tmp_name.replace_filename("CDOCXXXXXX.tmp");
		/* C++ is a mess here so we go the easy way */
		char *tmp_str = ::strdup(tmp_name.c_str());
		int tmp_handle = ::mkstemps(tmp_str, 4);
		tmp_name = tmp_str;
		::free (tmp_str);
		if (!QFile::open(tmp_handle, QFile::WriteOnly, QFileDevice::AutoCloseHandle)) {
			/* Have to close handle directly */
			::close(tmp_handle);
			::unlink(tmp_name.c_str());
			return false;
		}
		return true;
	}

	void close() {
		if (!isOpen()) return;
		QFile::close();
		/* Atomic rename */
		::rename(tmp_name.c_str(), current_name.c_str());
	}
};

bool CDoc2::save(const QString &_path)
{
	setLastError({});
	QByteArray fmk = Crypto::extract(Crypto::random(KEY_LEN), SALT);
	QByteArray cek = Crypto::expand(fmk, CEK);
	QByteArray hhk = Crypto::expand(fmk, HMAC);
#ifndef NDEBUG
	qDebug() << "fmk" << fmk.toHex();
	qDebug() << "cek" << cek.toHex();
	qDebug() << "hhk" << hhk.toHex();
#endif

	flatbuffers::FlatBufferBuilder builder;
	std::vector<flatbuffers::Offset<cdoc20::header::RecipientRecord>> recipients;
	auto toVector = [&builder](const QByteArray &data) {
		return builder.CreateVector((const uint8_t*)data.data(), size_t(data.length()));
	};
	auto toString = [&builder](const QString &data) {
		QByteArray utf8 = data.toUtf8();
		return builder.CreateString(utf8.data(), size_t(utf8.length()));
	};
	auto sendToServer = [this](std::shared_ptr<CKeyServer> key, const QByteArray &recipient_id, const QByteArray &key_material, QLatin1String type) {
		key->keyserver_id = Settings::CDOC2_DEFAULT_KEYSERVER;
		if(key->keyserver_id.isEmpty())
			return setLastError(QStringLiteral("keyserver_id cannot be empty"));
		QNetworkRequest req = cdoc20::req(key->keyserver_id);
		if(req.url().isEmpty())
			return setLastError(QStringLiteral("No valid config found for keyserver_id: %1").arg(key->keyserver_id));
		if(!cdoc20::checkConnection())
			return false;
		QScopedPointer<QNetworkAccessManager,QScopedPointerDeleteLater> nam(CheckConnection::setupNAM(req, Settings::CDOC2_POST_CERT));
		req.setRawHeader("x-expiry-time", QDateTime::currentDateTimeUtc().addMonths(6).toString(Qt::ISODate).toLatin1());
		QEventLoop e;
		QNetworkReply *reply = nam->post(req, QJsonDocument({
			{QLatin1String("recipient_id"), QLatin1String(recipient_id.toBase64())},
			{QLatin1String("ephemeral_key_material"), QLatin1String(key_material.toBase64())},
			{QLatin1String("capsule_type"), type},
		}).toJson());
		connect(reply, &QNetworkReply::finished, &e, &QEventLoop::quit);
		e.exec();
		if(reply->error() == QNetworkReply::NoError &&
			reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt() == 201)
			key->transaction_id = QString::fromLatin1(reply->rawHeader("Location")).remove(QLatin1String("/key-capsules/"));
		else
			return setLastError(reply->errorString());
		if(key->transaction_id.isEmpty())
			return setLastError(QStringLiteral("Failed to post key capsule"));
		return true;
	};

	for(std::shared_ptr<CKey> key: keys) {
		QString label;
		if (CKeyCD1::isCDoc1Key(*key)) {
			label = static_cast<const CKeyCD1 &>(*key).recipient;
		} else {
			label = static_cast<const CKeyCD2&>(*key).label;
		}
		if(key->pk_type == CKey::PKType::RSA) {
			QByteArray kek = Crypto::random(fmk.size());
			QByteArray xor_key = Crypto::xor_data(fmk, kek);
			auto publicKey = Crypto::fromRSAPublicKeyDer(key->key);
			if(!publicKey)
				return false;
			QByteArray encrytpedKek = Crypto::encrypt(publicKey.get(), RSA_PKCS1_OAEP_PADDING, kek);
#ifndef NDEBUG
			qDebug() << "publicKeyDer" << key->key.toHex();
			qDebug() << "kek" << kek.toHex();
			qDebug() << "xor" << xor_key.toHex();
			qDebug() << "encrytpedKek" << encrytpedKek.toHex();
#endif
			if(!Settings::CDOC2_USE_KEYSERVER) {
				auto rsaPublicKey = cdoc20::recipients::CreateRSAPublicKeyCapsule(builder,
					toVector(key->key), toVector(encrytpedKek));
				auto offs = cdoc20::header::CreateRecipientRecord(builder,
					cdoc20::recipients::Capsule::RSAPublicKeyCapsule, rsaPublicKey.Union(),
					toString(key->toKeyLabel()), toVector(xor_key), cdoc20::header::FMKEncryptionMethod::XOR);
				recipients.push_back(offs);
			} else {
				if (key->type != CKey::Type::SERVER) {
					return setLastError(QStringLiteral("Not a server key"));
				}
				const std::shared_ptr<CKeyServer> skey = std::static_pointer_cast<CKeyServer>(key);
				if(!sendToServer(skey, skey->key, encrytpedKek, QLatin1String("rsa")))
					return false;
				auto rsaKeyServer = cdoc20::recipients::CreateRsaKeyDetails(builder, toVector(skey->key));
				auto keyServer = cdoc20::recipients::CreateKeyServerCapsule(builder,
					cdoc20::recipients::KeyDetailsUnion::RsaKeyDetails,
					rsaKeyServer.Union(), toString(skey->keyserver_id), toString(skey->transaction_id));
				auto offs = cdoc20::header::CreateRecipientRecord(builder,
					cdoc20::recipients::Capsule::KeyServerCapsule, keyServer.Union(),
					toString(label), toVector(xor_key), cdoc20::header::FMKEncryptionMethod::XOR);
				recipients.push_back(offs);
			}
		} else {
			auto publicKey = Crypto::fromECPublicKeyDer(key->key, NID_secp384r1);
			if(!publicKey)
				return false;
			auto ephKey = Crypto::genECKey(publicKey.get());
			QByteArray sharedSecret = Crypto::derive(ephKey.get(), publicKey.get());
			QByteArray ephPublicKeyDer = Crypto::toPublicKeyDer(ephKey.get());
			QByteArray kekPm = Crypto::extract(sharedSecret, KEKPREMASTER);
			QByteArray info = KEK + cdoc20::header::EnumNameFMKEncryptionMethod(cdoc20::header::FMKEncryptionMethod::XOR) + key->key + ephPublicKeyDer;
			QByteArray kek = Crypto::expand(kekPm, info, fmk.size());
			QByteArray xor_key = Crypto::xor_data(fmk, kek);
	#ifndef NDEBUG
			qDebug() << "publicKeyDer" << key->key.toHex();
			qDebug() << "ephPublicKeyDer" << ephPublicKeyDer.toHex();
			qDebug() << "sharedSecret" << sharedSecret.toHex();
			qDebug() << "kekPm" << kekPm.toHex();
			qDebug() << "kek" << kek.toHex();
			qDebug() << "xor" << xor_key.toHex();
	#endif
			if(!Settings::CDOC2_USE_KEYSERVER) {
				auto eccPublicKey = cdoc20::recipients::CreateECCPublicKeyCapsule(builder,
					cdoc20::recipients::EllipticCurve::secp384r1, toVector(key->key), toVector(ephPublicKeyDer));
				auto offs = cdoc20::header::CreateRecipientRecord(builder,
					cdoc20::recipients::Capsule::ECCPublicKeyCapsule, eccPublicKey.Union(),
					toString(key->toKeyLabel()), toVector(xor_key), cdoc20::header::FMKEncryptionMethod::XOR);
				recipients.push_back(offs);
			} else {
				if (key->type != CKey::Type::SERVER) {
					return setLastError(QStringLiteral("Not a server key"));
				}
				const std::shared_ptr<CKeyServer> skey = std::static_pointer_cast<CKeyServer>(key);
				if(!sendToServer(skey, skey->key, ephPublicKeyDer, QLatin1String("ecc_secp384r1")))
					return false;
				auto eccKeyServer = cdoc20::recipients::CreateEccKeyDetails(builder,
					cdoc20::recipients::EllipticCurve::secp384r1, toVector(skey->key));
				auto keyServer = cdoc20::recipients::CreateKeyServerCapsule(builder,
					cdoc20::recipients::KeyDetailsUnion::EccKeyDetails,
					eccKeyServer.Union(), toString(skey->keyserver_id), toString(skey->transaction_id));
				auto offs = cdoc20::header::CreateRecipientRecord(builder,
					cdoc20::recipients::Capsule::KeyServerCapsule, keyServer.Union(),
					toString(key->toKeyLabel()), toVector(xor_key), cdoc20::header::FMKEncryptionMethod::XOR);
				recipients.push_back(offs);
			}
		}
	}

	auto offset = cdoc20::header::CreateHeader(builder, builder.CreateVector(recipients),
		cdoc20::header::PayloadEncryptionMethod::CHACHA20POLY1305);
	builder.Finish(offset);

	QByteArray header = QByteArray::fromRawData((const char*)builder.GetBufferPointer(), int(builder.GetSize()));
	QByteArray headerHMAC = Crypto::sign_hmac(hhk, header);
	QByteArray nonce = Crypto::random(NONCE_LEN);
#ifndef NDEBUG
	qDebug() << "hmac" << headerHMAC.toHex();
	qDebug() << "nonce" << nonce.toHex();
#endif
	Crypto::Cipher enc(EVP_chacha20_poly1305(), cek, nonce, true);
	enc.updateAAD(PAYLOAD + header + headerHMAC);
	auto header_len = qToBigEndian<uint32_t>(uint32_t(header.size()));

	/* Use TmpFile wrapper so the original will not be lost during error */
	TmpFile tmp(_path);
	if (!tmp.open()) {
		setLastError(tmp.errorString());
		return false;
	}
	/* Write contents to temporary */
	tmp.write(LABEL);
	tmp.write((const char*)&header_len, qint64(sizeof(header_len)));
	tmp.write(header);
	tmp.write(headerHMAC);
	tmp.write(nonce);
	if(!cdoc20::TAR(std::unique_ptr<QIODevice>(new cdoc20::stream(&tmp, &enc))).save(files)) {
		return false;
	}
	if(!enc.result()) {
		return false;
	}
	QByteArray tag = enc.tag();
#ifndef NDEBUG
	qDebug() << "tag" << tag.toHex();
#endif
	tmp.write(tag);
	tmp.close();
	this->path = _path;
	return true;
}

QByteArray CDoc2::fetchKeyMaterial(const CKeyServer& key)
{
	QNetworkRequest req = cdoc20::req(key.keyserver_id, key.transaction_id);
	if(req.url().isEmpty()) {
		setLastError(QStringLiteral("No valid config found for keyserver_id: %1").arg(key.keyserver_id));
		return {};
	}
	if(!cdoc20::checkConnection()) {
		return {};
	}
	auto authKey = dispatchToMain(&QSigner::key, qApp->signer());
	QScopedPointer<QNetworkAccessManager,QScopedPointerDeleteLater> nam(
		CheckConnection::setupNAM(req, qApp->signer()->tokenauth().cert(), authKey, Settings::CDOC2_GET_CERT));
	QEventLoop e;
	QNetworkReply *reply = nam->get(req);
	connect(reply, &QNetworkReply::finished, &e, &QEventLoop::quit);
	e.exec();
	if(authKey.handle()) {
		qApp->signer()->logout();
	}
	if(reply->error() != QNetworkReply::NoError && reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt() != 201) {
		setLastError(reply->errorString());
		return {};
	}
	QJsonObject json = QJsonDocument::fromJson(reply->readAll()).object();
	QByteArray key_material = QByteArray::fromBase64(json.value(QLatin1String("ephemeral_key_material")).toString().toLatin1());
	return std::move(key_material);
}

QByteArray CDoc2::getFMK(const CKey &_key, const QByteArray& secret)
{
	setLastError({});
    QByteArray kek;
    if (_key.type == CKey::Type::SYMMETRIC_KEY) {
        const CKeySymmetric &sk = static_cast<const CKeySymmetric&>(_key);
        qDebug() << "Secret:" << secret.toHex();
        if (sk.kdf_iter > 0) {
            // Password key
            // PasswordSalt_i = Capsule_i.PasswordSalt
            // PasswordKeyMaterial_i = PBKDF2(Password_i, PasswordSalt_i)
            QByteArray PasswordKeyMaterial_i = QPasswordDigestor::deriveKeyPbkdf2(QCryptographicHash::Sha256, secret, sk.pw_salt, sk.kdf_iter, 32);
            qDebug() << "PasswordKeyMaterial_i:" << PasswordKeyMaterial_i.toHex();
            // KeyMaterialSalt_i = Capsule_i.KeyMaterialSalt
            // EncryptedFMK_i = Container_i.EncryptedFMK
            // KEK_i = HKDF(KeyMaterialSalt_i, PasswordKeyMaterial_i)

            QByteArray info = KEK + cdoc20::header::EnumNameFMKEncryptionMethod(cdoc20::header::FMKEncryptionMethod::XOR) + secret;

            kek = Crypto::hkdf(PasswordKeyMaterial_i, sk.salt, info, 32, EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND);
            qDebug() << "kek:" << kek.toHex();
            // FMK = XOR(KEK_i, EncryptedFMK_i)
            // CEK = HKDF-Expand(FMK)

        }
    } else {
        QByteArray key_material;
        if(_key.type == CKey::Type::SERVER) {
            key_material = fetchKeyMaterial(static_cast<const CKeyServer&>(_key));
        } else if (_key.type == CKey::PUBLICKEY) {
            const CKeyPK& pk = static_cast<const CKeyPK&>(_key);
            if (_key.pk_type == CKey::PKType::RSA) {
                key_material = pk.encrypted_kek;
            } else {
                key_material = pk.publicKey;
            }
        }
#ifndef NDEBUG
        qDebug() << "publicKeyDer" << _key.key.toHex();
        qDebug() << "Key material" << key_material.toHex();
#endif
        if (_key.pk_type == CKey::PKType::RSA) {
            kek = qApp->signer()->decrypt([&key_material](QCryptoBackend *backend) {
                return backend->decrypt(key_material, true);
            });
        } else {
            kek = qApp->signer()->decrypt([&_key, &key_material](QCryptoBackend *backend) {
                QByteArray kekPm = backend->deriveHMACExtract(key_material, KEKPREMASTER, KEY_LEN);
#ifndef NDEBUG
                qDebug() << "kekPm" << kekPm.toHex();
#endif
                QByteArray info = KEK + cdoc20::header::EnumNameFMKEncryptionMethod(cdoc20::header::FMKEncryptionMethod::XOR) + _key.key + key_material;
                return Crypto::expand(kekPm, info, KEY_LEN);
            });
        }
    }

	if(kek.isEmpty()) {
		setLastError(QStringLiteral("Failed to derive key"));
		return {};
	}
	QByteArray fmk = Crypto::xor_data(_key.cipher, kek);
	QByteArray hhk = Crypto::expand(fmk, HMAC);
#ifndef NDEBUG
	qDebug() << "kek" << kek.toHex();
	qDebug() << "xor" << _key.cipher.toHex();
	qDebug() << "fmk" << fmk.toHex();
	qDebug() << "hhk" << hhk.toHex();
	qDebug() << "hmac" << headerHMAC.toHex();
#endif
	if(Crypto::sign_hmac(hhk, header_data) == headerHMAC)
		return fmk;
	setLastError(QStringLiteral("CDoc 2.0 hash mismatch"));
	return {};
}

int CDoc2::version()
{
	return 2;
}
