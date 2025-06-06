/*
 * QEstEidUtil
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

#include "QSmartCard.h"

#include "QPCSC.h"
#include "SslCertificate.h"
#include "TokenData.h"

#include <QtCore/QStringList>
#include <QtCore/QVariant>


#define APDU QByteArray::fromHex

class Card
{
public:
	virtual ~Card() = default;
	virtual QPCSCReader::Result change(QPCSCReader *reader, QSmartCardData::PinType type, const QString &pin, const QString &newpin) const = 0;
	virtual bool loadPerso(QPCSCReader *reader, QSmartCardDataPrivate *d) const = 0;
	virtual QPCSCReader::Result replace(QPCSCReader *reader, QSmartCardData::PinType type, const QString &puk, const QString &pin) const = 0;
	virtual QByteArray sign(QPCSCReader *reader, const QByteArray &dgst) const = 0;
	static QPCSCReader::Result transfer(QPCSCReader *reader,  bool verify, const QByteArray &apdu,
		QSmartCardData::PinType type, quint8 newPINOffset, bool requestCurrentPIN);
	virtual bool updateCounters(QPCSCReader *reader, QSmartCardDataPrivate *d) const = 0;

	static QByteArrayView parseFCI(const QByteArray &data, quint8 expectedTag);

	static const QByteArray CHANGE;
	static const QByteArray READBINARY;
	static const QByteArray REPLACE;
	static const QByteArray VERIFY;
};

class IDEMIACard: public Card
{
public:
	QPCSCReader::Result change(QPCSCReader *reader, QSmartCardData::PinType type, const QString &pin, const QString &newpin) const final;
	bool loadPerso(QPCSCReader *reader, QSmartCardDataPrivate *d) const final;
	QPCSCReader::Result replace(QPCSCReader *reader, QSmartCardData::PinType type, const QString &puk, const QString &pin) const final;
	QByteArray sign(QPCSCReader *reader, const QByteArray &dgst) const final;
	bool updateCounters(QPCSCReader *reader, QSmartCardDataPrivate *d) const final;

	static bool isSupported(const QByteArray &atr);
	static QByteArray pinTemplate(const QString &pin);

	static const QByteArray AID, AID_OT, AID_QSCD, ATR_COSMO8, ATR_COSMOX;
};

class QSmartCard::Private
{
public:
	static QSharedPointer<QPCSCReader> connect(const QString &reader);
	QSmartCard::ErrorType handlePinResult(QPCSCReader *reader, const QPCSCReader::Result &response, bool forceUpdate);

	QSharedPointer<QPCSCReader> reader;
	std::unique_ptr<Card> card;
	TokenData		token;
	QSmartCardData	t;
};

class QSmartCardDataPrivate: public QSharedData
{
public:
	QString card, reader;
	QHash<QSmartCardData::PersonalDataType,QVariant> data;
	SslCertificate authCert, signCert;
	QHash<QSmartCardData::PinType,quint8> retry;
	bool pinpad = false;
};
