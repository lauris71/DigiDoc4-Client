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

#pragma once

#include "common_enums.h"
#include "widgets/MainAction.h"

#include <memory>

namespace Ui {
class ContainerPage;
}

class CKey;
class CryptoDoc;
class DigiDoc;
class QSslCertificate;
class SignatureItem;
class SslCertificate;
struct WarningText;

class ContainerPage final : public QWidget
{
	Q_OBJECT

public:
	explicit ContainerPage( QWidget *parent = nullptr );
	~ContainerPage() final;

	void cardChanged(const SslCertificate &cert, bool isBlocked = false);
	void clear();
	void clearPopups();
	void setHeader(const QString &file);
	void togglePrinting(bool enable);
	void transition(CryptoDoc *container, const QSslCertificate &cert);
	void transition(DigiDoc* container);

signals:
	void action(int code, const QString &info1 = {}, const QString &info2 = {});
	void addFiles(const QStringList &files);
	void certChanged(const SslCertificate &cert);
	void fileRemoved(int row);
	void moved(const QString &to);
	void removed(int row);
	void warning(const WarningText &warningText);

private:
	void changeEvent(QEvent* event) final;
	bool checkAction(int code, const QString& selectedCard, const QString& selectedMobile);
	void elideFileName();
	bool eventFilter(QObject *o, QEvent *e) final;
	void forward(int code);
	void showMainAction(const QList<ria::qdigidoc4::Actions> &actions);
	void showSigningButton();
	void updateDecryptionButton();
	void updatePanes(ria::qdigidoc4::ContainerState state);
	void translateLabels();

	Ui::ContainerPage *ui;
	std::unique_ptr<MainAction> mainAction;
	QString cardInReader;
	QString fileName;
	QString mobileCode;

	const char *cancelText = QT_TR_NOOP("Cancel");
	const char *convertText = QT_TR_NOOP("Encrypt");
	bool isSupported = false;
	bool hasEmptyFile = false;
	bool isSeal = false;
	bool isExpired = false;
	bool isBlocked = false;
};
