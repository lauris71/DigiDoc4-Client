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

#pragma once
<<<<<<< HEAD

#include "CryptoDoc.h"

#include <QtCore/QCryptographicHash>
#include <QtCore/QFile>

class QXmlStreamReader;
class QXmlStreamWriter;

using EVP_CIPHER = struct evp_cipher_st;

class CDoc1 final : private QFile
{
public:
	libcdoc::CKey::DecryptionStatus canDecrypt(const libcdoc::Certificate &cert) const;
	std::shared_ptr<libcdoc::CKey> getDecryptionKey(const libcdoc::Certificate &cert) const;
	bool decryptPayload(const std::vector<uint8_t> &fmk);
	bool save(const std::string &path);
	std::vector<uint8_t> getFMK(const libcdoc::CKey &key, const std::vector<uint8_t>& secret);

	bool setLastError(const std::string &msg) { return (lastError = msg).empty(); }

	static std::unique_ptr<CDoc1> load(const std::string& path);
protected:
	std::vector<std::shared_ptr<libcdoc::CKey>> keys;
	std::vector<libcdoc::IOEntry> files;
private:
	CDoc1() = default;
	CDoc1(const std::string &path);

	void writeDDoc(QIODevice *ddoc);

	static QByteArray fromBase64(QStringView data);
	static std::vector<libcdoc::IOEntry> readDDoc(QIODevice *ddoc);
	static void readXML(QIODevice *io, const std::function<void (QXmlStreamReader &)> &f);
	static void writeAttributes(QXmlStreamWriter &x, const QMap<QString,QString> &attrs);
	static void writeBase64Element(QXmlStreamWriter &x, const QString &ns, const QString &name, const QByteArray &data);
	static void writeElement(QXmlStreamWriter &x, const QString &ns, const QString &name, std::function<void ()> &&f = {});
	static void writeElement(QXmlStreamWriter &x, const QString &ns, const QString &name, const QMap<QString,QString> &attrs, std::function<void ()> &&f = {});

	std::string lastError;
	QString method, mime;
	QHash<QString,QString> properties;

	static const QString
		AES128CBC_MTH, AES192CBC_MTH, AES256CBC_MTH,
		AES128GCM_MTH, AES192GCM_MTH, AES256GCM_MTH,
		SHA256_MTH, SHA384_MTH, SHA512_MTH,
		RSA_MTH, CONCATKDF_MTH, AGREEMENT_MTH, KWAES256_MTH;
	static const QString DS, DENC, DSIG11, XENC11;
	static const QString MIME_ZLIB, MIME_DDOC, MIME_DDOC_OLD;
	static const QHash<QString, const EVP_CIPHER*> ENC_MTH;
	static const QHash<QString, QCryptographicHash::Algorithm> SHA_MTH;
};
=======
>>>>>>> 0a90362 (Cleared CDoc1)
