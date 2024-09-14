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

#include "CryptoDoc.h"

#include "Application.h"
#include "Crypto.h"
#include "TokenData.h"
#include "QCryptoBackend.h"
#include "QSigner.h"
#include "Settings.h"
#include "SslCertificate.h"
#include "Utils.h"
#include "dialogs/FileDialog.h"
#include "dialogs/WarningDialog.h"

#include <QtCore/QDebug>
#include <QtCore/QDir>
#include <QtCore/QFileInfo>
#include <QtCore/QRegularExpression>
#include <QtCore/QThread>
#include <QtCore/QUrl>
#include <QtCore/QUrlQuery>
#include <QtGui/QDesktopServices>
#include <QtNetwork/QSslKey>
#include <QtWidgets/QMessageBox>

#include <libcdoc/cdoc2.h>
#include <libcdoc/certificate.h>
#include <libcdoc/Crypto.h>

using namespace ria::qdigidoc4;

auto toHex = [](const std::vector<uint8_t>& data) -> QString {
	QByteArray ba(reinterpret_cast<const char *>(data.data()), data.size());
	return ba.toHex();
};

std::string
CryptoDoc::labelFromCertificate(const std::vector<uint8_t>& cert)
{
	// Test
	libcdoc::Certificate sslcert(cert);
	std::string name = sslcert.getCommonName();
	qDebug() << "COMMON NAME:" << name;
	name = sslcert.getGivenName();
	qDebug() << "GIVEN NAME:" << name;
	name = sslcert.getSurname();
	qDebug() << "SURNAME:" << name;
	name = sslcert.getSerialNumber();
	qDebug() << "SERIAL:" << name;
	std::vector<std::string> policies = sslcert.policies();


	QSslCertificate kcert(QByteArray(reinterpret_cast<const char *>(cert.data()), cert.size()), QSsl::Der);
	return [](const SslCertificate &c) {
		QString cn = c.subjectInfo(QSslCertificate::CommonName);
		QString gn = c.subjectInfo("GN");
		QString sn = c.subjectInfo("SN");
		if(!gn.isEmpty() || !sn.isEmpty())
			cn = QStringLiteral("%1 %2 %3").arg(gn, sn, c.personalCode());

		int certType = c.type();
		if(certType & SslCertificate::EResidentSubType)
			return QStringLiteral("%1 %2").arg(cn, CryptoDoc::tr("Digi-ID E-RESIDENT")).toStdString();
		if(certType & SslCertificate::DigiIDType)
			return QStringLiteral("%1 %2").arg(cn, CryptoDoc::tr("Digi-ID")).toStdString();
		if(certType & SslCertificate::EstEidType)
			return QStringLiteral("%1 %2").arg(cn, CryptoDoc::tr("ID-CARD")).toStdString();
		return cn.toStdString();
	}(kcert);
}

std::vector<uint8_t>
DDCryptoBackend::decryptRSA(const std::vector<uint8_t> &data, bool oaep) const
{
	QByteArray qdata(reinterpret_cast<const char *>(data.data()), data.size());
	QByteArray qkek = qApp->signer()->decrypt([&qdata, &oaep](QCryptoBackend *backend) {
			return backend->decrypt(qdata, oaep);
	});
	return std::vector<uint8_t>(qkek.cbegin(), qkek.cend());
}

const QString SHA256_MTH = QStringLiteral("http://www.w3.org/2001/04/xmlenc#sha256");
const QString SHA384_MTH = QStringLiteral("http://www.w3.org/2001/04/xmlenc#sha384");
const QString SHA512_MTH = QStringLiteral("http://www.w3.org/2001/04/xmlenc#sha512");
const QHash<QString, QCryptographicHash::Algorithm> SHA_MTH{
	{SHA256_MTH, QCryptographicHash::Sha256}, {SHA384_MTH, QCryptographicHash::Sha384}, {SHA512_MTH, QCryptographicHash::Sha512}
};

std::vector<uint8_t>
DDCryptoBackend::deriveConcatKDF(const std::vector<uint8_t> &publicKey, const std::string &digest, int keySize,
	const std::vector<uint8_t> &algorithmID, const std::vector<uint8_t> &partyUInfo, const std::vector<uint8_t> &partyVInfo) const
{
	QByteArray decryptedKey = qApp->signer()->decrypt([&publicKey, &digest, &keySize, &algorithmID, &partyUInfo, &partyVInfo](QCryptoBackend *backend) {
			QByteArray ba(reinterpret_cast<const char *>(publicKey.data()), publicKey.size());
			return backend->deriveConcatKDF(ba, SHA_MTH[QString::fromStdString(digest)],
				keySize,
				QByteArray(reinterpret_cast<const char *>(algorithmID.data()), algorithmID.size()),
				QByteArray(reinterpret_cast<const char *>(partyUInfo.data()), partyUInfo.size()),
				QByteArray(reinterpret_cast<const char *>(partyVInfo.data()), partyVInfo.size()));
	});
	return std::vector<uint8_t>(decryptedKey.cbegin(), decryptedKey.cend());
}

std::vector<uint8_t>
DDCryptoBackend::deriveHMACExtract(const std::vector<uint8_t> &key_material, const std::vector<uint8_t> &salt, int keySize) const
{
	QByteArray qkey_material(reinterpret_cast<const char *>(key_material.data()), key_material.size());
	QByteArray qsalt(reinterpret_cast<const char *>(salt.data()), salt.size());
	QByteArray qkekpm = qApp->signer()->decrypt([&qkey_material, &qsalt, &keySize](QCryptoBackend *backend) {
		return backend->deriveHMACExtract(qkey_material, qsalt, keySize);
	});
	return std::vector<uint8_t>(qkekpm.cbegin(), qkekpm.cend());
}

bool
DDCryptoBackend::getSecret(std::vector<uint8_t>& _secret, const std::string& _label)
{
	_secret = secret;
	return true;
}

class CryptoDoc::Private final: public QThread
{
	Q_OBJECT
public:
	bool warnIfNotWritable() const;
	void run() final;
	inline void waitForFinished()
	{
		QEventLoop e;
		connect(this, &Private::finished, &e, &QEventLoop::quit);
		start();
		e.exec();
	}

	//std::unique_ptr<libcdoc::CDoc> cdoc;
	/* INVARIANT: Either reader or writer but not both is not null */
	std::unique_ptr<libcdoc::CDocReader> reader;
	std::unique_ptr<libcdoc::CDocWriter> writer;

	QString			fileName;
	//bool			encrypted = false;
	//bool isEncrypted() const { return encrypted; }
	bool isEncrypted() const { return reader != nullptr; }
	CDocumentModel	*documents = new CDocumentModel(this);
	QStringList		tempFiles;
	// Decryption data
	QByteArray fmk;
	// Encryption data
	QString label;
	uint32_t kdf_iter;

	// libcdoc handlers
	DDConfiguration conf;
	DDCryptoBackend crypto;
	DDNetworkBackend network;

	std::vector<libcdoc::IOEntry> files;
	std::vector<std::shared_ptr<libcdoc::CKey>> keys;

	const std::vector<libcdoc::IOEntry> &getFiles() {
		return files;
	}
	std::unique_ptr<libcdoc::CDocWriter> createCDocWriter() {
		libcdoc::CDocWriter *w = libcdoc::CDocWriter::createWriter(Settings::CDOC2_DEFAULT ? 2 : 1, fileName.toStdString(),
																   &conf, &crypto, &network);
		return std::unique_ptr<libcdoc::CDocWriter>(w);
	}
	std::unique_ptr<libcdoc::CDocReader> createCDocReader(const std::string& filename) {
		libcdoc::CDocReader *r = libcdoc::CDocReader::createReader(filename,
																   &conf, &crypto, &network);
		if (!r) {
			WarningDialog::show(tr("Failed to open document"), tr("Unsupported file format"));
			return nullptr;
		}
		return std::unique_ptr<libcdoc::CDocReader>(r);
	}
private:
};

bool CryptoDoc::Private::warnIfNotWritable() const
{
	if(fileName.isEmpty()) {
		WarningDialog::show(CryptoDoc::tr("Container is not open"));
	} else if(!writer) {
		WarningDialog::show(CryptoDoc::tr("Container is encrypted"));
	} else {
		return false;
	}
	return true;
}

void CryptoDoc::Private::run()
{
	if(reader) {
		qCDebug(CRYPTO) << "Decrypt" << fileName;
		std::vector<uint8_t> pfmk(fmk.cbegin(), fmk.cend());
		//encrypted = !cdoc->decryptPayload(pfmk);
		files = reader->decryptPayload(pfmk);
		if (!files.empty()) {
			// Success, immediately create writer from reader
			keys.clear();
			writer = createCDocWriter();
			reader.reset();
		}
	} else if (writer) {
		qCDebug(CRYPTO) << "Encrypt" << fileName;
		if (crypto.secret.empty()) {
			if (writer->encrypt(fileName.toStdString(), files, keys)) {
				// Encryption successful, open new reader
				writer.reset();
				reader = createCDocReader(fileName.toStdString());
			}
		} else {
			auto key = std::make_shared<libcdoc::EncKeySymmetric>(libcdoc::Crypto::random(), libcdoc::Crypto::random(), kdf_iter);
			key->label = label.toStdString();
			keys.push_back(key);
			if (writer->encrypt(fileName.toStdString(), files, keys)) {
				// Encryption successful, open new reader
				reader = createCDocReader(fileName.toStdString());
				if (!reader) return;
				writer.reset();
			}
		}
	} else {
		qWarning() << "Neither reader nor writer is initialized";
	}
}

CDocumentModel::CDocumentModel(CryptoDoc::Private *doc)
: d( doc )
{}

bool CDocumentModel::addFile(const QString &file, const QString &mime)
{
	if(d->warnIfNotWritable()) return false;

	QFileInfo info(file);
	if(info.size() == 0) {
		WarningDialog::show(DocumentModel::tr("Cannot add empty file to the container."));
		return false;
	}
	if(d->writer->getVersion() == 1 && info.size() > 120*1024*1024) {
		WarningDialog::show(tr("Added file(s) exceeds the maximum size limit of the container (∼120MB). "
			"<a href='https://www.id.ee/en/article/encrypting-large-120-mb-files/'>Read more about it</a>"));
		return false;
	}
	bool present = false;
	for (auto file : d->files) {
		if (file.name == info.fileName().toStdString()) {
			present = true;
			break;
		}
	}
	if (present) {
		WarningDialog::show(DocumentModel::tr("Cannot add the file to the envelope. File '%1' is already in container.")
							.arg(FileDialog::normalized(info.fileName())));
		return false;
	}

	std::filesystem::path p(file.toStdString());
	int64_t size = std::filesystem::file_size(p);
	auto data = std::make_shared<std::ifstream>(file.toStdString());
	std::string name = QFileInfo(file).fileName().toStdString();
	std::string id = QStringLiteral("D%1").arg(d->files.size()).toStdString();
	d->files.push_back({
								 name,
								 id,
								 mime.toStdString(),
								 size,
								 data,
							 });
	emit added(FileDialog::normalized(QString::fromStdString(name)));
	return true;
}

void CDocumentModel::addTempReference(const QString &file)
{
	d->tempFiles.append(file);
}

QString CDocumentModel::copy(int row, const QString &dst) const
{
	auto files = [this, row] {
		if (d->reader || d->writer) {
			return d->files;
		} else {
			return std::vector<libcdoc::IOEntry>();
		}
	};
	const libcdoc::IOEntry &file = d->getFiles().at(row);
	if( QFile::exists(dst)) QFile::remove(dst);
	file.stream->seekg(0);
	if(QFile f(dst); f.open(QFile::WriteOnly) && copyIODevice(file.stream.get(), &f) == file.size)
		return dst;
	WarningDialog::show(tr("Failed to save file '%1'").arg(dst));
	return {};
}

QString CDocumentModel::data(int row) const
{
	return FileDialog::normalized(QString::fromStdString(d->getFiles().at(row).name));
}

quint64 CDocumentModel::fileSize(int row) const
{
	return d->getFiles().at(row).size;
}

QString CDocumentModel::mime(int row) const
{
	return FileDialog::normalized(QString::fromStdString(d->getFiles().at(row).mime));
}

void CDocumentModel::open(int row)
{
	if(d->isEncrypted())
		return;
	QString path = FileDialog::tempPath(FileDialog::safeName(data(row)));
	if(!verifyFile(path))
		return;
	if(copy(row, path).isEmpty())
		return;
	d->tempFiles.append(path);
	FileDialog::setReadOnly(path);
	if(FileDialog::isSignedPDF(path))
		Application::showClient({ std::move(path) }, false, false, true);
	else
		QDesktopServices::openUrl(QUrl::fromLocalFile(path));
}

bool CDocumentModel::removeRow(int row)
{
	if(d->warnIfNotWritable())
		return false;

	if(row >= d->files.size()) {
		WarningDialog::show(DocumentModel::tr("Internal error"));
		return false;
	}

	d->files.erase(d->files.begin() + row);
	emit removed(row);
	return true;
}

int CDocumentModel::rowCount() const
{
	return int(d->getFiles().size());
}

QString CDocumentModel::save(int row, const QString &path) const
{
	if(d->isEncrypted())
		return {};

	int zone = FileDialog::fileZone(d->fileName);
	QString fileName = copy(row, path);
	QFileInfo f(fileName);
	if(!f.exists())
		return {};
	FileDialog::setFileZone(fileName, zone);
	return fileName;
}

CryptoDoc::CryptoDoc( QObject *parent )
	: QObject(parent)
	, d(new Private)
{
	const_cast<QLoggingCategory&>(CRYPTO()).setEnabled(QtDebugMsg,
		QFile::exists(QStringLiteral("%1/%2.log").arg(QDir::tempPath(), Application::applicationName())));
}

CryptoDoc::~CryptoDoc() { clear(); delete d; }

bool
CryptoDoc::supportsSymmetricKeys() const
{
	return d->writer && d->writer->getVersion() >= 2;
}

bool CryptoDoc::addEncryptionKey(std::shared_ptr<libcdoc::EncKey> key )
{
	if(d->warnIfNotWritable())
		return false;
	for (std::shared_ptr<libcdoc::EncKey> k: d->keys) {
		if (k->isTheSameRecipient(*key)) {
			WarningDialog::show(tr("Key already exists"));
			return false;
		}
	}
	d->keys.push_back(key);
	return true;
}

bool CryptoDoc::canDecrypt(const QSslCertificate &cert)
{
	if (!d->reader) return false;
	QByteArray der = cert.toDer();
	libcdoc::Certificate cc(std::vector<uint8_t>(der.cbegin(), der.cend()));
	libcdoc::CKey::DecryptionStatus dec_stat = d->reader->canDecrypt(cc);
	return (dec_stat == libcdoc::CKey::CAN_DECRYPT) || (dec_stat == libcdoc::CKey::DecryptionStatus::NEED_KEY);
}

void CryptoDoc::clear( const QString &file )
{
	for(const QString &f: qAsConst(d->tempFiles))
	{
		//reset read-only attribute to enable delete file
		FileDialog::setReadOnly(f, false);
		QFile::remove(f);
	}
	d->tempFiles.clear();
	d->reader.reset();
	d->fileName = file;
	d->writer = d->createCDocWriter();
}

ContainerState CryptoDoc::state() const
{
	return d->isEncrypted() ? EncryptedContainer : UnencryptedContainer;
}

bool
CryptoDoc::decrypt(std::shared_ptr<libcdoc::CKey> key, const QByteArray& secret)
{
	if(d->fileName.isEmpty()) {
		WarningDialog::show(tr("Container is not open"));
		return false;
	}
	if(!d->reader)
		return true;

	if (key == nullptr) {
		QByteArray der = qApp->signer()->tokenauth().cert().toDer();
		libcdoc::Certificate cc(std::vector<uint8_t>(der.cbegin(), der.cend()));
		key = d->reader->getDecryptionKey(cc);
	}
	if((key == nullptr) || (key->isSymmetric() && secret.isEmpty())) {
		WarningDialog::show(tr("You do not have the key to decrypt this document"));
		return false;
	}

	if(d->reader->getVersion() == 2 && (key->type == libcdoc::CKey::Type::SERVER) && !Settings::CDOC2_NOTIFICATION.isSet())
	{
		auto *dlg = new WarningDialog(tr("You must enter your PIN code twice in order to decrypt the CDOC2 container. "
			"The first PIN entry is required for authentication to the key server referenced in the CDOC2 container. "
			"Second PIN entry is required to decrypt the CDOC2 container."), Application::mainWindow());
		dlg->setCancelText(WarningDialog::Cancel);
		dlg->addButton(WarningDialog::OK, QMessageBox::Ok);
		dlg->addButton(tr("DON'T SHOW AGAIN"), QMessageBox::Ignore);
		switch (dlg->exec())
		{
		case QMessageBox::Ok: break;
		case QMessageBox::Ignore:
			Settings::CDOC2_NOTIFICATION = true;
			break;
		default: return false;
		}
	}

	d->crypto.secret.assign(secret.cbegin(), secret.cend());
	std::vector<uint8_t> fmk = d->reader->getFMK(*key);
	d->fmk = QByteArray(reinterpret_cast<const char *>(fmk.data()), fmk.size());
#ifndef NDEBUG
	qDebug() << "FMK (Transport key)" << d->fmk.toHex();
#endif
	if(d->fmk.isEmpty()) {
		const std::string& msg = d->reader->getLastError();
		WarningDialog::show(tr("Failed to decrypt document. Please check your internet connection and network settings."), QString::fromStdString(msg));
		return false;
	}

	d->waitForFinished();
	if(d->reader) {
		const std::string& msg = d->reader->getLastError();
		if (msg.empty()) {
			WarningDialog::show(tr("Error parsing document"));
		} else {
			WarningDialog::show(QString::fromStdString(msg));
		}
	}
	return !d->isEncrypted();
}

DocumentModel* CryptoDoc::documentModel() const { return d->documents; }

bool CryptoDoc::encrypt( const QString &filename, const QString& label, const QByteArray& secret, uint32_t kdf_iter)
{
	if(!filename.isEmpty()) d->fileName = filename;
	if(d->fileName.isEmpty()) {
		WarningDialog::show(tr("Container is not open"));
		return false;
	}
	// I think the correct semantics is to fail if container is already encrypted
	if(d->reader) return false;
	if (secret.isEmpty()) {
		// Encrypt for address list
		if(d->keys.empty())
		{
			WarningDialog::show(tr("No keys specified"));
			return false;
		}
	} else {
		// Encrypt with symmetric key
		d->label = label;
		d->crypto.secret.assign(secret.cbegin(), secret.cend());
		d->kdf_iter = kdf_iter;
	}
	d->waitForFinished();
	d->label.clear();
	d->crypto.secret.clear();
	if(d->isEncrypted()) {
		open(d->fileName);
	} else {
		WarningDialog::show(tr("Failed to encrypt document. Please check your internet connection and network settings."),
							QString::fromStdString(d->writer->getLastError()));
	}
	return d->isEncrypted();
}

QString CryptoDoc::fileName() const { return d->fileName; }

const std::vector<std::shared_ptr<libcdoc::CKey>>&
CryptoDoc::keys() const
{
	if (d->writer) {
		return d->keys;
	} else {
		return d->reader->getKeys();
	}
}

bool CryptoDoc::move(const QString &to)
{
	if(!d->isEncrypted())
	{
		d->fileName = to;
		return true;
	}

	return false;
}

bool CryptoDoc::open( const QString &file )
{
	clear(file);
	d->reader = d->createCDocReader(file.toStdString());
	if (!d->reader) return false;
	d->writer.reset();
	// fixme: This seems wrong
	//if(!d->isEncrypted()) {
	//	WarningDialog::show(tr("Failed to open document"),
	//						QString::fromStdString(d->cdoc->lastError));
	//	return false;
	//}
	Application::addRecent( file );
	return true;
}

void CryptoDoc::removeKey( int id )
{
	if(!d->warnIfNotWritable())
		d->keys.erase(d->keys.begin() + id);
}

bool CryptoDoc::saveCopy(const QString &filename)
{
	if(QFileInfo(filename) == QFileInfo(d->fileName))
		return true;
	if(QFile::exists(filename))
		QFile::remove(filename);
	return QFile::copy(d->fileName, filename);
}

#include "CryptoDoc.moc"
