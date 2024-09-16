#define __CDOCSUPPORT_CPP__

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

#include <QtCore/QBuffer>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonObject>
#include <QtCore/QtEndian>
#include <QtCore/QTemporaryFile>
#include <QtNetwork/QNetworkAccessManager>
#include <QtNetwork/QSslKey>
#include <QtCore/QJsonDocument>

#include "Application.h"
#include "CheckConnection.h"
#include "Colors.h"
#include "QSigner.h"
#include "Settings.h"
#include "TokenData.h"
#include "Utils.h"
#include "effects/FadeInNotification.h"

#include "CDocSupport.h"

bool
checkConnection()
{
	if(CheckConnection().check())
		return true;
	return dispatchToMain([] {
		auto *notification = new FadeInNotification(Application::mainWindow(),
			ria::qdigidoc4::colors::WHITE, ria::qdigidoc4::colors::MANTIS, 110);
		notification->start(QCoreApplication::translate("MainWindow", "Check internet connection"), 750, 3000, 1200);
		return false;
	});
}

QNetworkRequest
request(const QString &keyserver_id, const QString &transaction_id = {}) {
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

std::string
DDConfiguration::getValue(const std::string& param)
{
	if (param == libcdoc::Configuration::USE_KEYSERVER) {
		return (Settings::CDOC2_USE_KEYSERVER) ? "true" : "false";
	}
	return {};
}

std::pair<std::string,std::string>
DDNetworkBackend::sendKey (libcdoc::CDocWriter *writer, const std::vector<uint8_t> &recipient_id, const std::vector<uint8_t> &key_material, const std::string &type)
{
	std::string keyserver_id = Settings::CDOC2_DEFAULT_KEYSERVER;
	if(keyserver_id.empty()) {
		writer->setLastError(t_("keyserver_id cannot be empty"));
		return {};
	}
	QNetworkRequest req = request(QString::fromStdString(keyserver_id));
	if(req.url().isEmpty()) {
		writer->setLastError(t_("No valid config found for keyserver_id: ") + keyserver_id);
		return {};
	}
	if(!checkConnection()) {
		return {};
	}
	QScopedPointer<QNetworkAccessManager,QScopedPointerDeleteLater> nam(CheckConnection::setupNAM(req, Settings::CDOC2_POST_CERT));
	QEventLoop e;
	QNetworkReply *reply = nam->post(req, QJsonDocument({
		{QLatin1String("recipient_id"), QLatin1String(QByteArray(reinterpret_cast<const char *>(recipient_id.data()), recipient_id.size()).toBase64())},
		{QLatin1String("ephemeral_key_material"), QLatin1String(QByteArray(reinterpret_cast<const char *>(key_material.data()), key_material.size()).toBase64())},
		{QLatin1String("capsule_type"), QLatin1String(type)},
	}).toJson());
	connect(reply, &QNetworkReply::finished, &e, &QEventLoop::quit);
	e.exec();
	QString transaction_id;
	if(reply->error() == QNetworkReply::NoError &&
		reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt() == 201) {
		transaction_id = QString::fromLatin1(reply->rawHeader("Location")).remove(QLatin1String("/key-capsules/"));
	} else {
		writer->setLastError(reply->errorString().toStdString());
		return {};
	}
	if(transaction_id.isEmpty())
		writer->setLastError(t_("Failed to post key capsule"));
	return {keyserver_id, transaction_id.toStdString()};
};

std::vector<uint8_t>
DDNetworkBackend::fetchKey(libcdoc::CDocReader *reader, const libcdoc::CKeyServer& key)
{
	QNetworkRequest req = request(QString::fromStdString(key.keyserver_id), QString::fromStdString(key.transaction_id));
	if(req.url().isEmpty()) {
		reader->setLastError(t_("No valid config found for keyserver_id:") + key.keyserver_id);
		return {};
	}
	if(!checkConnection()) {
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
		reader->setLastError(reply->errorString().toStdString());
		return {};
	}
	QJsonObject json = QJsonDocument::fromJson(reply->readAll()).object();
	QByteArray key_material = QByteArray::fromBase64(json.value(QLatin1String("ephemeral_key_material")).toString().toLatin1());
	return std::vector<uint8_t>(key_material.cbegin(), key_material.cend());
}

TempListConsumer::~TempListConsumer()
{
	if (ofs) delete ofs;
}

int64_t
TempListConsumer::write(const uint8_t *src, size_t size)
{
	if (!ofs) return OUTPUT_ERROR;
	libcdoc::IOEntry& file = files.back();
	ofs->write((const char *) src, size);
	if (!ofs) return OUTPUT_STREAM_ERROR;
	file.size += size;
	return size;
}

bool
TempListConsumer::close()
{
	libcdoc::IOEntry& file = files.back();
	if (fstream) {
		fstream->close();
		file.stream = std::make_shared<std::ifstream>(tmp_name);
		fstream = nullptr;
		ofs = nullptr;
		return true;
	} else if (sstream) {
		file.stream = std::shared_ptr<std::istream>(sstream);
		file.stream->seekg(0);
		sstream = nullptr;
		ofs = nullptr;
		return true;
	} else {
		return false;
	}
}

bool
TempListConsumer::isError()
{
	return sstream && sstream->bad();
}

bool
TempListConsumer::open(const std::string& name, int64_t size)
{
	if (ofs) return false;
	files.push_back({name, {}, "application/octet-stream", 0, nullptr});
	if ((size < 0) || (size > MAX_VEC_SIZE)) {
		char name[L_tmpnam];
		// fixme:
		std::tmpnam(name);
		fstream = new std::ofstream(name);
		ofs = fstream;
	} else {
		sstream = new std::stringstream(std::ios_base::out | std::ios_base::in);
		ofs = sstream;
	}
	return true;
}
