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
	if (k.enc_key && k.enc_key->isCertificate()) {
		const libcdoc::EncKeyCert& kd = static_cast<const libcdoc::EncKeyCert&>(*k.enc_key);
		QSslCertificate kcert(QByteArray(reinterpret_cast<const char *>(kd.cert.data()), kd.cert.size()), QSsl::Der);
		connect(d->showCert, &QPushButton::clicked, this, [this, cert=kcert] {
			CertificateDetails::showCertificate(cert, this);
		});
		d->showCert->setHidden(kcert.isNull());
	} else if (k.dec_key && k.dec_key->isCertificate()) {
			const libcdoc::CKeyCert& kd = static_cast<const libcdoc::CKeyCert&>(*k.dec_key);
			QSslCertificate kcert(QByteArray(reinterpret_cast<const char *>(kd.cert.data()), kd.cert.size()), QSsl::Der);
			connect(d->showCert, &QPushButton::clicked, this, [this, cert=kcert] {
				CertificateDetails::showCertificate(cert, this);
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
	if (k.dec_key && k.dec_key->isCDoc1()) {
		const libcdoc::CKeyCDoc1& kd = static_cast<const libcdoc::CKeyCDoc1&>(*k.dec_key);
		addItem(tr("Recipient"), cd1key.label);
		addItem(tr("ConcatKDF digest method"), cd1key.concatDigest);
		addItem(tr("Expiry date"), cd1key.cert.expiryDate().toLocalTime().toString(QStringLiteral("dd.MM.yyyy hh:mm:ss")));
        addItem(tr("Issuer"), SslCertificate(cd1key.cert).issuerInfo(QSslCertificate::CommonName));
		d->view->resizeColumnToContents( 0 );
	if (k.dec_key && (k.dec_key->type == libcdoc::CKey::SERVER)) {
		const libcdoc::CKeyServer& sk = static_cast<const libcdoc::CKeyServer&>(*k.dec_key);
        addItem(tr("Key server ID"), sk.keyserver_id);
        addItem(tr("Transaction ID"), sk.transaction_id);
    }
	d->view->resizeColumnToContents( 0 );
	adjustSize();
}
