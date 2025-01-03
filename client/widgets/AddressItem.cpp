/*
 * QDigiDoc4
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

#include <QDebug>
#include <qsslcertificate.h>
#include <qsslkey.h>

#include "AddressItem.h"
#include "ui_AddressItem.h"

#include "CryptoDoc.h"
#include "SslCertificate.h"
#include "dialogs/KeyDialog.h"

using namespace ria::qdigidoc4;

class AddressItem::Private: public Ui::AddressItem
{
public:
	QString code;
	CDKey key;
	QString label;
	bool yourself = false;
};

AddressItem::AddressItem(const CDKey& key, QWidget *parent, bool showIcon)
	: Item(parent)
	, ui(new Private)
{
	ui->key = key;
	ui->setupUi(this);
	if(showIcon)
		ui->icon->load(QStringLiteral(":/images/icon_Krypto_small.svg"));
	ui->icon->setVisible(showIcon);
	ui->name->setAttribute(Qt::WA_TransparentForMouseEvents, true);
	ui->expire->setAttribute(Qt::WA_TransparentForMouseEvents, true);
	ui->idType->setAttribute(Qt::WA_TransparentForMouseEvents, true);
    if(!ui->key->unsupported)
		setCursor(Qt::PointingHandCursor);

	connect(ui->add, &QToolButton::clicked, this, [this]{ emit add(this);});
    if (key->isSymmetric()) {
        ui->decrypt->show();
        connect(ui->decrypt, &QToolButton::clicked, this, [this]{ emit decrypt(ui->key);});
    } else {
        ui->decrypt->hide();
    }

	if (key.lock.isSymmetric()) {
		ui->decrypt->show();
		connect(ui->decrypt, &QToolButton::clicked, this, [this]{ emit decrypt(&ui->key.lock);});
	} else {
		ui->code = {};
        ui->label = key->label;
	}

	ui->add->setFont(Styles::font(Styles::Condensed, 12));
	ui->added->setFont(ui->add->font());

	if (ui->key.rcpt.isCertificate()) {
		QSslCertificate kcert(QByteArray(reinterpret_cast<const char *>(ui->key.rcpt.cert.data()), ui->key.rcpt.cert.size()), QSsl::Der);
		ui->code = SslCertificate(kcert).personalCode().toHtmlEscaped();
		ui->label = (!kcert.subjectInfo("GN").isEmpty() && !kcert.subjectInfo("SN").isEmpty() ?
						 kcert.subjectInfo("GN").join(' ') + " " + kcert.subjectInfo("SN").join(' ') :
						 kcert.subjectInfo("CN").join(' ')).toHtmlEscaped();
	} else if (ui->key.lock.isCertificate()) {
			std::vector<uint8_t> cert = ui->key.lock.getBytes(libcdoc::Lock::Params::CERT);
			QSslCertificate kcert(QByteArray(reinterpret_cast<const char *>(cert.data()), cert.size()), QSsl::Der);
			ui->code = SslCertificate(kcert).personalCode().toHtmlEscaped();
			ui->label = (!kcert.subjectInfo("GN").isEmpty() && !kcert.subjectInfo("SN").isEmpty() ?
							 kcert.subjectInfo("GN").join(' ') + " " + kcert.subjectInfo("SN").join(' ') :
							 kcert.subjectInfo("CN").join(' ')).toHtmlEscaped();
	} else {
		ui->code.clear();
		if (ui->key.rcpt.type != libcdoc::Recipient::Type::NONE) {
			ui->label = QString::fromStdString(key.rcpt.label).toHtmlEscaped();
		} else if (ui->key.lock.isValid()) {
			ui->label = QString::fromStdString(key.lock.label).toHtmlEscaped();
		}
	}
	if(ui->label.isEmpty()) {
		if (ui->key.rcpt.isPKI()) {
			ui->label = QString::fromUtf8(reinterpret_cast<const char *>(ui->key.rcpt.rcpt_key.data()), ui->key.rcpt.rcpt_key.size());
		} else if (ui->key.lock.type == libcdoc::Lock::PUBLIC_KEY) {
			std::vector<uint8_t> key_material = ui->key.lock.getBytes(libcdoc::Lock::Params::KEY_MATERIAL);
			ui->label = QString::fromUtf8(reinterpret_cast<const char *>(key_material.data()), key_material.size());
		}
	}
	setIdType();
	showButton(AddressItem::Remove);
}

AddressItem::~AddressItem()
{
	delete ui;
}

void AddressItem::changeEvent(QEvent* event)
{
	if (event->type() == QEvent::LanguageChange)
	{
		ui->retranslateUi(this);
		setName();
		setIdType();
	}
	QWidget::changeEvent(event);
}

const CDKey& AddressItem::getKey() const
{
	return ui->key;
}

void AddressItem::idChanged(const SslCertificate &cert)
{
	QByteArray qder = cert.toDer();
	std::vector<uint8_t> sder = std::vector<uint8_t>(qder.cbegin(), qder.cend());

	if (!ui->key.rcpt.isEmpty()) {
		ui->yourself = ui->key.rcpt.isTheSameRecipient(sder);
	} else if (ui->key.lock.isValid()) {
		QSslKey pkey = cert.publicKey();
		QByteArray der = pkey.toDer();
		ui->yourself = ui->key.lock.hasTheSameKey(std::vector<uint8_t>(der.cbegin(), der.cend()));
	}
	setName();
}

void AddressItem::initTabOrder(QWidget *item)
{
	setTabOrder(item, ui->name);
	setTabOrder(ui->name, ui->idType);
	setTabOrder(ui->idType, ui->expire);
	setTabOrder(ui->expire, ui->remove);
	setTabOrder(ui->remove, ui->added);
	setTabOrder(ui->added, lastTabWidget());
}

QWidget* AddressItem::lastTabWidget()
{
	return ui->add;
}

void AddressItem::mouseReleaseEvent(QMouseEvent * /*event*/)
{
	if(!ui->key->unsupported)
        (new KeyDialog(*ui->key))->open();
}

void AddressItem::setName()
{
	ui->name->setText(QStringLiteral("%1 <span style=\"font-weight:normal;\">%2</span>")
		.arg(ui->label.toHtmlEscaped(), (ui->yourself ? ui->code + tr(" (Yourself)") : ui->code).toHtmlEscaped()));
	if(ui->name->text().isEmpty())
		ui->name->hide();
}

void AddressItem::showButton(ShowToolButton show)
{
	ui->remove->setVisible(show == Remove);
	ui->add->setVisible(show == Add);
	ui->added->setVisible(show == Added);
}

void AddressItem::stateChange(ContainerState state)
{
	ui->remove->setVisible(state == UnencryptedContainer);
}

void AddressItem::setIdType()
{
	if (!ui->key.lock.isValid()) return;
	if (ui->key.lock.isPKI()) {
		if (ui->key.lock.isCertificate()) {
			std::vector<uint8_t> cc = ui->key.lock.getBytes(libcdoc::Lock::Params::CERT);
			QSslCertificate kcert(QByteArray(reinterpret_cast<const char *>(cc.data()), cc.size()), QSsl::Der);
            ui->idType->setHidden(false);
            QString str;
            SslCertificate cert(ckd->cert);
            SslCertificate::CertType type = cert.type();
    		if(ui->key->unsupported)
				str = "Unsupported";
            else if(type & SslCertificate::DigiIDType)
                str = tr("digi-ID");
            else if(type & SslCertificate::EstEidType)
                str = tr("ID-card");
            else if(type & SslCertificate::MobileIDType)
                str = tr("mobile-ID");
            else if(type & SslCertificate::TempelType)
            {
                if(cert.keyUsage().contains(SslCertificate::NonRepudiation))
                    str = tr("e-Seal");
                else if(cert.enhancedKeyUsage().contains(SslCertificate::ClientAuth))
                    str = tr("Authentication certificate");
                else
                    str = tr("Certificate for Encryption");
            }
			else
			{
        		auto items = ui->key->fromKeyLabel();
				void(QT_TR_NOOP("ID-CARD"));
				ui->idType->setText(tr(items[QStringLiteral("type")].toUtf8().data()));
				if(QString server_exp = items[QStringLiteral("server_exp")]; !server_exp.isEmpty())
				{
					auto date = QDateTime::fromSecsSinceEpoch(server_exp.toLongLong(), Qt::UTC);
					bool canDecrypt = QDateTime::currentDateTimeUtc() < date;
					ui->expire->setProperty("label", canDecrypt ? QStringLiteral("good") : QStringLiteral("error"));
					ui->expire->setText(canDecrypt ? QStringLiteral("%1 %2").arg(
					tr("Decryption is possible until:"), date.toLocalTime().toString(QStringLiteral("dd.MM.yyyy"))) :
					tr("Decryption has expired"));
				}
			}
			if(!cert.isNull())
			{
				ui->expire->setProperty("label", QStringLiteral("default"));
				ui->expire->setText(QStringLiteral("%1 %2").arg(
					cert.isValid() ? tr("Expires on") : tr("Expired on"),
					cert.expiryDate().toLocalTime().toString(QStringLiteral("dd.MM.yyyy"))));
			}
            if(!str.isEmpty())
                str += QStringLiteral(" - ");
            QDateTime date(cert.expiryDate().toLocalTime());
            ui->idType->setText(QStringLiteral("%1%2 %3").arg(str,
                                                              cert.isValid() ? tr("Expires on") : tr("Expired on"),
                                                              date.toLocalTime().toString(QStringLiteral("dd. MMMM yyyy"))));
        } else {
            QString type = (pki->pk_type == CKey::PKType::RSA) ? "RSA" : "ECC";
            ui->idType->setHidden(false);
            ui->idType->setText(type + " public key");
        }
 	} else if ((ui->key.lock.type == libcdoc::Lock::Type::SYMMETRIC_KEY || ui->key.lock.type == libcdoc::Lock::Type::PASSWORD)) {
        ui->idType->setHidden(false);
        if (ui->key.lock.type == libcdoc::Lock::Type::PASSWORD) {
            ui->idType->setText("Password derived key");
        } else {
            ui->idType->setText("Symmetric key");
        }
    } else {
        ui->idType->setHidden(false);
        ui->idType->setText("Unknown key type");
	}
	ui->idType->setHidden(ui->idType->text().isEmpty());
	ui->expire->setHidden(ui->expire->text().isEmpty());
}

