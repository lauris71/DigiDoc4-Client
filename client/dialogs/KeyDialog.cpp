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

#include "KeyDialog.h"
#include "ui_KeyDialog.h"

#include "CryptoDoc.h"
#include "Styles.h"
#include "SslCertificate.h"
#include "effects/Overlay.h"
#include "dialogs/CertificateDetails.h"

#include <memory>

KeyDialog::KeyDialog(const CDKey &k, QWidget *parent )
	: QDialog( parent )
{
	auto d = std::make_unique<Ui::KeyDialog>();
	d->setupUi(this);
#if defined (Q_OS_WIN)
	d->buttonLayout->setDirection(QBoxLayout::RightToLeft);
#endif
	setWindowFlags(Qt::Dialog|Qt::CustomizeWindowHint);
	setAttribute(Qt::WA_DeleteOnClose);
	new Overlay(this);

	QFont condensed = Styles::font(Styles::Condensed, 12);
	QFont regular = Styles::font(Styles::Regular, 14);
	d->close->setFont(condensed);
	d->showCert->setFont(condensed);
	d->view->header()->setFont(regular);
	d->view->setFont(regular);
	d->view->setHeaderLabels({tr("Attribute"), tr("Value")});

	connect(d->close, &QPushButton::clicked, this, &KeyDialog::accept);
	if (k.rcpt.isCertificate()) {
		QSslCertificate kcert(QByteArray(reinterpret_cast<const char *>(k.rcpt.cert.data()), k.rcpt.cert.size()), QSsl::Der);
		connect(d->showCert, &QPushButton::clicked, this, [this, cert=kcert] {
			CertificateDetails::showCertificate(cert, this);
		});
		d->showCert->setHidden(kcert.isNull());
	} else if (k.lock.isCertificate()) {
		std::vector<uint8_t> cert = k.lock.getBytes(libcdoc::Lock::Params::CERT);
			QSslCertificate kcert(QByteArray(reinterpret_cast<const char *>(cert.data()), cert.size()), QSsl::Der);
			connect(d->showCert, &QPushButton::clicked, this, [this, c=kcert] {
				CertificateDetails::showCertificate(c, this);
			});
			d->showCert->setHidden(kcert.isNull());
	} else {
		d->showCert->setHidden(true);
	}

	auto addItem = [&](const QString &parameter, const QString &value) {
		if(value.isEmpty())
			return;
		auto *i = new QTreeWidgetItem(d->view);
		i->setText(0, parameter);
		i->setText(1, value);
		d->view->addTopLevelItem(i);
	};

	auto addItemStr = [&](const QString &parameter, const std::string &value) {
		if(value.empty())
			return;
		auto *i = new QTreeWidgetItem(d->view);
		i->setText(0, parameter);
		i->setText(1, QString::fromStdString(value));
		d->view->addTopLevelItem(i);
	};

	bool adjust_size = false;
	if (k.lock.isCDoc1()) {
		std::vector<uint8_t> cert = k.lock.getBytes(libcdoc::Lock::Params::CERT);
		std::string cdigest = k.lock.getString(libcdoc::Lock::Params::CONCAT_DIGEST);
		QSslCertificate kcert(QByteArray(reinterpret_cast<const char *>(cert.data()), cert.size()), QSsl::Der);
		addItem(tr("Recipient"), k.dec_key.label);
		addItem(tr("ConcatKDF digest method"), QString::fromStdString(cdigest));
		addItem(tr("Expiry date"), cd1key.cert.expiryDate().toLocalTime().toString(QStringLiteral("dd.MM.yyyy hh:mm:ss")));
        addItem(tr("Issuer"), SslCertificate(cd1key.cert).issuerInfo(QSslCertificate::CommonName));
		d->view->resizeColumnToContents( 0 );
	if (k.lock.type == libcdoc::Lock::SERVER) {
		const libcdoc::LockServer& sk = static_cast<const libcdoc::LockServer&>(*k.dec_key);
        addItem(tr("Key server ID"), QString::fromUtf8(k.lock.getString(libcdoc::Lock::Params::KEYSERVER_ID)));
        addItem(tr("Transaction ID"), QString::fromUtf8(k.lock.getString(libcdoc::Lock::Params::TRANSACTION_ID)));
    }
	d->view->resizeColumnToContents( 0 );
	adjustSize();
}
