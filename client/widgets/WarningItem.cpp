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

#include "WarningItem.h"
#include "ui_WarningItem.h"

#include "VerifyCert.h"

#include <QtCore/QUrl>
#include <QtGui/QDesktopServices>

using namespace ria::qdigidoc4;

WarningItem::WarningItem(WarningText warningText, QWidget *parent)
	: StyledWidget(parent)
	, ui(new Ui::WarningItem)
	, warnText(warningText)
{
	ui->setupUi(this);
	lookupWarning();
	connect(ui->warningAction, &QToolButton::clicked, this, [this] {
		if(url.startsWith(QLatin1String("http")))
			QDesktopServices::openUrl(QUrl(url));
		else
			Q_EMIT linkActivated(url);
	});
}

WarningItem::~WarningItem()
{
	delete ui;
}

int WarningItem::page() const
{
	return _page;
}

void WarningItem::changeEvent(QEvent* event)
{
	if (event->type() == QEvent::LanguageChange)
	{
		ui->retranslateUi(this);
		lookupWarning();
	}
}

void WarningItem::mousePressEvent(QMouseEvent */*event*/)
{
	// this warning should not be closed if there are zero-byte(empty) files in the container
	if (warnText.type != EmptyFileWarning)
		deleteLater();
}

void WarningItem::lookupWarning()
{
	switch(warnText.type)
	{
	case CertExpiredError:
		setObjectName("WarningItemError");
		ui->warningText->setText(tr("Certificates have expired!"));
		url = tr("https://www.politsei.ee/en/instructions/applying-for-an-id-card-for-an-adult/");
		break;
	case CertExpiryWarning:
		ui->warningText->setText(tr("Certificates expire soon!"));
		url = tr("https://www.politsei.ee/en/instructions/applying-for-an-id-card-for-an-adult/");
		break;
	case UnblockPin1Warning:
		ui->warningText->setText(QStringLiteral("%1 %2").arg(
			VerifyCert::tr("PIN%1 has been blocked because PIN%1 code has been entered incorrectly 3 times.").arg(1),
			VerifyCert::tr("Unblock to reuse PIN%1.").arg(1)));
		url = QStringLiteral("#unblock-PIN1");
		ui->warningAction->setText(VerifyCert::tr("Unblock"));
		ui->warningAction->setAccessibleName(ui->warningAction->text().toLower());
		break;
	case UnblockPin2Warning:
		ui->warningText->setText(QStringLiteral("%1 %2").arg(
			VerifyCert::tr("PIN%1 has been blocked because PIN%1 code has been entered incorrectly 3 times.").arg(2),
			VerifyCert::tr("Unblock to reuse PIN%1.").arg(2)));
		url = QStringLiteral("#unblock-PIN2");
		ui->warningAction->setText(VerifyCert::tr("Unblock"));
		ui->warningAction->setAccessibleName(ui->warningAction->text().toLower());
		break;
	// SignDetails
	case InvalidSignatureError:
		setObjectName("WarningItemError");
		ui->warningText->setText(tr("%n signatures are not valid!", nullptr, warnText.counter));
		url = tr("https://www.id.ee/en/article/digital-signing-and-electronic-signatures/");
		_page = SignDetails;
		break;
	case InvalidTimestampError:
		setObjectName("WarningItemError");
		ui->warningText->setText(tr("%n timestamps are not valid!", nullptr, warnText.counter));
		url = tr("https://www.id.ee/en/article/digital-signing-and-electronic-signatures/");
		_page = SignDetails;
		break;
	case UnknownSignatureWarning:
		ui->warningText->setText(tr("%n signatures are unknown!", nullptr, warnText.counter));
		url = tr("https://www.id.ee/en/article/digital-signing-and-electronic-signatures/");
		_page = SignDetails;
		break;
	case UnknownTimestampWarning:
		ui->warningText->setText(tr("%n timestamps are unknown!", nullptr, warnText.counter));
		url = tr("https://www.id.ee/en/article/digital-signing-and-electronic-signatures/");
		_page = SignDetails;
		break;
	case UnsupportedAsicSWarning:
		ui->warningText->setText(tr("This ASiC-S container contains XAdES signature. "
			"You are not allowed to add or remove signatures to this container."));
		url = tr("https://www.id.ee/en/article/digidoc-container-format-life-cycle-2/");
		_page = SignDetails;
		break;
	case UnsupportedAsicCadesWarning:
		ui->warningText->setText(tr("This container contains CAdES signature. "
			"You are not allowed to add or remove signatures to this container."));
		url = tr("https://www.id.ee/en/article/digidoc-container-format-life-cycle-2/");
		_page = SignDetails;
		break;
	case UnsupportedDDocWarning:
		ui->warningText->setText(tr("The current file is a DigiDoc container that is not supported officially any longer. "
			"You are not allowed to add or remove signatures to this container."));
		url = tr("https://www.id.ee/en/article/digidoc-container-format-life-cycle-2/");
		_page = SignDetails;
		break;
	case UnsupportedCDocWarning:
		ui->warningText->setText(tr("The encrypted container contains a cryptographic algorithm or recipient type that is not supported in this DigiDoc4 application version. "
			"Please make sure that you are using the latest DigiDoc4 application version."));
		url = tr("https://www.id.ee/en/article/install-id-software/");
		_page = CryptoDetails;
		break;
	case EmptyFileWarning:
		ui->warningText->setText(tr("An empty file is attached to the container. "
			"Remove the empty file from the container to sign."));
		ui->warningAction->hide();
		_page = SignDetails;
		break;
	default: break;
	}
}

WarningType WarningItem::warningType() const
{
	return warnText.type;
}
