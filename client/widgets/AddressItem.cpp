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
#include "DateTime.h"
#include "SslCertificate.h"
#include "Styles.h"
#include "dialogs/KeyDialog.h"

using namespace ria::qdigidoc4;

class AddressItem::Private: public Ui::AddressItem
{
public:
	QString code;
	std::shared_ptr<libcdoc::CKey> key;
	QString label;
	bool yourself = false;
};

AddressItem::AddressItem(std::shared_ptr<libcdoc::CKey> key, QWidget *parent, bool showIcon)
	: Item(parent)
	, ui(new Private)
{
	ui->key = key;
	ui->setupUi(this);
	if(showIcon)
		ui->icon->load(QStringLiteral(":/images/icon_Krypto_small.svg"));
	ui->icon->setVisible(showIcon);
	ui->name->setFont(Styles::font(Styles::Regular, 14, QFont::DemiBold));
	ui->name->installEventFilter(this);
	ui->idType->setFont(Styles::font(Styles::Regular, 11));
	ui->idType->installEventFilter(this);

	ui->remove->setIcons(QStringLiteral("/images/icon_remove.svg"), QStringLiteral("/images/icon_remove_hover.svg"),
		QStringLiteral("/images/icon_remove_pressed.svg"), 17, 17);
	ui->remove->init(LabelButton::White);
	connect(ui->add, &QToolButton::clicked, this, [this]{ emit add(this);});
	connect(ui->remove, &LabelButton::clicked, this, [this]{ emit remove(this);});

	if (key->isSymmetric()) {
		ui->decrypt->show();
		connect(ui->decrypt, &QToolButton::clicked, this, [this]{ emit decrypt(ui->key);});
	} else {
		ui->decrypt->hide();
	}

	ui->add->setFont(Styles::font(Styles::Condensed, 12));
	ui->added->setFont(ui->add->font());

	if (ui->key->isCertificate()) {
		std::shared_ptr<libcdoc::CKeyCert> kd = std::static_pointer_cast<libcdoc::CKeyCert>(ui->key);
		QSslCertificate kcert(QByteArray(reinterpret_cast<const char *>(kd->cert.data()), kd->cert.size()), QSsl::Der);
		ui->code = SslCertificate(kcert).personalCode().toHtmlEscaped();
		ui->label = (!kcert.subjectInfo("GN").isEmpty() && !kcert.subjectInfo("SN").isEmpty() ?
						 kcert.subjectInfo("GN").join(' ') + " " + kcert.subjectInfo("SN").join(' ') :
						 kcert.subjectInfo("CN").join(' ')).toHtmlEscaped();
	} else {
		ui->code.clear();
		ui->label = QString::fromStdString(key->label).toHtmlEscaped();
	}
	if(ui->label.isEmpty() && ui->key->type == libcdoc::CKey::PUBLIC_KEY) {
		const libcdoc::CKeyPublicKey& pk = static_cast<const libcdoc::CKeyPublicKey&>(*ui->key);
		ui->label = QString::fromUtf8(reinterpret_cast<const char *>(pk.key_material.data()), pk.key_material.size());
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

bool AddressItem::eventFilter(QObject *o, QEvent *e)
{
	if((o == ui->name || o == ui->idType) && e->type() == QEvent::MouseButtonRelease)
	{
		(new KeyDialog(*ui->key, this))->open();
		return true;
	}
	return Item::eventFilter(o, e);
}

const std::shared_ptr<libcdoc::CKey> AddressItem::getKey() const
{
	return ui->key;
}

void AddressItem::idChanged(std::shared_ptr<libcdoc::CKey> key)
{
	ui->yourself = key->isTheSameRecipient(*ui->key);
	setName();
}

void AddressItem::idChanged(const SslCertificate &cert)
{
	QByteArray qder = cert.toDer();
	std::vector<uint8_t> sder = std::vector<uint8_t>(qder.cbegin(), qder.cend());
	idChanged(std::make_shared<libcdoc::CKeyCert>(CryptoDoc::labelFromCertificate(sder), sder));
}

void AddressItem::initTabOrder(QWidget *item)
{
	setTabOrder(item, ui->name);
	setTabOrder(ui->name, ui->idType);
	setTabOrder(ui->idType, ui->remove);
	setTabOrder(ui->remove, ui->added);
	setTabOrder(ui->added, lastTabWidget());
}

QWidget* AddressItem::lastTabWidget()
{
	return ui->add;
}

void AddressItem::mouseReleaseEvent(QMouseEvent * /*event*/)
{
	(new KeyDialog(*ui->key, this))->open();
}

void AddressItem::setName()
{
	QString str = QStringLiteral("%1 <span style=\"font-weight:normal;\">%2</span>").arg(ui->label, ui->yourself ? ui->code + tr(" (Yourself)") : ui->code);
	qDebug() << "SetName:" << str;
	ui->name->setText(str);
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
	if (ui->key->isPKI()) {
		std::shared_ptr<libcdoc::CKeyPKI> pki = std::static_pointer_cast<libcdoc::CKeyPKI>(ui->key);
		if (ui->key->isCertificate()) {
			std::shared_ptr<libcdoc::CKeyCert> ckd = std::static_pointer_cast<libcdoc::CKeyCert>(ui->key);
			QSslCertificate kcert(QByteArray(reinterpret_cast<const char *>(ckd->cert.data()), ckd->cert.size()), QSsl::Der);
			ui->idType->setHidden(false);
			QString str;
			SslCertificate cert(kcert);
			SslCertificate::CertType type = cert.type();
			if(type & SslCertificate::DigiIDType)
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

			if(!str.isEmpty())
				str += QStringLiteral(" - ");
			DateTime date(cert.expiryDate().toLocalTime());
			ui->idType->setText(QStringLiteral("%1%2 %3").arg(str,
															  cert.isValid() ? tr("Expires on") : tr("Expired on"),
															  date.formatDate(QStringLiteral("dd. MMMM yyyy"))));
		} else {
			QString type = (pki->pk_type == libcdoc::CKey::PKType::RSA) ? "RSA" : "ECC";
			ui->idType->setHidden(false);
			ui->idType->setText(type + " public key");
		}
	} else if (ui->key->isSymmetric()) {
		std::shared_ptr<libcdoc::CKeySymmetric> ckd = std::static_pointer_cast<libcdoc::CKeySymmetric>(ui->key);
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
}

