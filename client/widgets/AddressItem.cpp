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
	std::shared_ptr<CKey> key;
	QString label;
	bool yourself = false;
};

AddressItem::AddressItem(std::shared_ptr<CKey> key, QWidget *parent, bool showIcon)
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

    if (ui->key->isCDoc1()) {
		std::shared_ptr<CKeyCDoc1> key = std::static_pointer_cast<CKeyCDoc1>(ui->key);
		ui->code = SslCertificate(key->cert).personalCode().toHtmlEscaped();
		ui->label = (!key->cert.subjectInfo("GN").isEmpty() && !key->cert.subjectInfo("SN").isEmpty() ?
				key->cert.subjectInfo("GN").join(' ') + " " + key->cert.subjectInfo("SN").join(' ') :
				key->cert.subjectInfo("CN").join(' '));
	} else {
		ui->code = {};
        ui->label = key->label;
	}
    if(ui->label.isEmpty() && ui->key->type == CKey::PUBLIC_KEY) {
        const CKeyPublicKey& pk = static_cast<const CKeyPublicKey&>(*ui->key);
        ui->label = pk.fromKeyLabel().value(QStringLiteral("cn"), key->label);
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

const std::shared_ptr<CKey> AddressItem::getKey() const
{
	return ui->key;
}

void AddressItem::idChanged(const SslCertificate &cert)
{
    auto key = CKeyCDoc1::fromCertificate(cert);
    ui->yourself = !key->rcpt_key.isNull() && ui->key == key;
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
	ui->expire->clear();
    if (ui->key->isPKI()) {
        std::shared_ptr<CKeyPKI> pki = std::static_pointer_cast<CKeyPKI>(ui->key);
        if (ui->key->isCertificate()) {
            std::shared_ptr<CKeyCert> ckd = std::static_pointer_cast<CKeyCert>(ui->key);
            ui->idType->setHidden(false);
            QString str;
            SslCertificate cert(ckd->cert);
            SslCertificate::CertType type = cert.type();
    		if(ui->key->unsupported)
			{
				ui->label = tr("Unsupported cryptographic algorithm or recipient type");
				ui->idType->clear();
			}
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
    } else if (ui->key->isSymmetric()) {
        std::shared_ptr<CKeySymmetric> ckd = std::static_pointer_cast<CKeySymmetric>(ui->key);
        ui->idType->setHidden(false);
        if (ckd->kdf_iter > 0) {
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

