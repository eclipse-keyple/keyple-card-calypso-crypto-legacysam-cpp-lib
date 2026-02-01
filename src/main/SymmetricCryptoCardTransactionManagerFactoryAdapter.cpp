/******************************************************************************
 * Copyright (c) 2025 Calypso Networks Association https://calypsonet.org/    *
 *                                                                            *
 * See the NOTICE file(s) distributed with this work for additional           *
 * information regarding copyright ownership.                                 *
 *                                                                            *
 * This program and the accompanying materials are made available under the   *
 * terms of the Eclipse Public License 2.0 which is available at              *
 * http://www.eclipse.org/legal/epl-2.0                                       *
 *                                                                            *
 * SPDX-License-Identifier: EPL-2.0                                           *
 ******************************************************************************/

#include "keyple/card/calypso/crypto/legacysam/SymmetricCryptoCardTransactionManagerFactoryAdapter.hpp"

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "keyple/card/calypso/crypto/legacysam/CardTransactionUtil.hpp"
#include "keyple/card/calypso/crypto/legacysam/CommandGetChallenge.hpp"
#include "keyple/card/calypso/crypto/legacysam/DtoAdapters.hpp"
#include "keyple/card/calypso/crypto/legacysam/SymmetricCryptoCardTransactionManagerAdapter.hpp"
#include "keyple/core/util/HexUtil.hpp"
#include "keyple/core/util/cpp/exception/IllegalStateException.hpp"
#include "keypop/calypso/card/transaction/UnexpectedCommandStatusException.hpp"
#include "keypop/calypso/crypto/symmetric/SymmetricCryptoException.hpp"

namespace keyple {
namespace card {
namespace calypso {
namespace crypto {
namespace legacysam {

using keyple::core::util::HexUtil;
using keyple::core::util::cpp::exception::IllegalStateException;
using keypop::calypso::card::transaction::UnexpectedCommandStatusException;
using keypop::calypso::crypto::symmetric::SymmetricCryptoException;

SymmetricCryptoCardTransactionManagerFactoryAdapter::
    SymmetricCryptoCardTransactionManagerFactoryAdapter(
        std::shared_ptr<ProxyReaderApi> samReader,
        std::shared_ptr<LegacySamAdapter> sam,
        std::shared_ptr<ContextSettingAdapter> contextSetting)
: mSamReader(samReader)
, mSam(sam)
, mIsExtendedModeSupported(
      mSam->getProductType() == ProductType::SAM_C1
      || mSam->getProductType() == ProductType::HSM_C1)
, mMaxCardApduLengthSupported(
      contextSetting->getContactReaderPayloadCapacity() != nullptr
          ? std::min(
                mSam->getMaxDigestDataLength(),
                *contextSetting->getContactReaderPayloadCapacity())
          : mSam->getMaxDigestDataLength())
{
}

bool
SymmetricCryptoCardTransactionManagerFactoryAdapter::isExtendedModeSupported()
    const
{
    return mIsExtendedModeSupported;
}

int
SymmetricCryptoCardTransactionManagerFactoryAdapter::
    getMaxCardApduLengthSupported() const
{
    return mMaxCardApduLengthSupported;
}

void
SymmetricCryptoCardTransactionManagerFactoryAdapter::
    preInitTerminalSessionContext()
{
    processCommand(
        std::make_shared<CommandGetChallenge>(
            std::make_shared<DtoAdapters::CommandContextDto>(
                mSam, nullptr, nullptr),
            8));
}

std::shared_ptr<SymmetricCryptoCardTransactionManagerSpi>
SymmetricCryptoCardTransactionManagerFactoryAdapter::
    createCardTransactionManager(
        const std::vector<uint8_t>& cardKeyDiversifier,
        bool useExtendedMode,
        const std::vector<std::vector<uint8_t>>& transactionAuditData)
{
    if (useExtendedMode && !mIsExtendedModeSupported) {
        throw IllegalStateException(
            "The extended mode is not supported by the crypto service");
    }

    return std::make_shared<SymmetricCryptoCardTransactionManagerAdapter>(
        mSamReader,
        mSam,
        cardKeyDiversifier,
        useExtendedMode,
        mMaxCardApduLengthSupported,
        transactionAuditData);
}

void
SymmetricCryptoCardTransactionManagerFactoryAdapter::processCommand(
    std::shared_ptr<Command> command)
{
    std::vector<std::vector<uint8_t>> transactionAuditData;
    try {
        /* Get the list of C-APDU to transmit */
        auto apduRequests = CardTransactionUtil::getApduRequests({command});

        /* Wrap the list of C-APDUs into a card request */
        auto cardRequest = std::make_shared<DtoAdapters::CardRequestAdapter>(
            apduRequests, true);

        /* Transmit the commands to the SAM */
        auto cardResponse = CardTransactionUtil::transmitCardRequest(
            cardRequest, mSamReader, mSam, transactionAuditData);

        auto apduResponse
            = cardResponse
                  ->getApduResponses()[0];  // Assuming only one response.
        command->parseResponse(apduResponse);

    } catch (const CommandException& e) {
        auto commandRef = command->getCommandRef();
        const std::string sw
            = command->getApduResponse()
                  ? HexUtil::toHex(
                        static_cast<std::uint16_t>(
                            command->getApduResponse()->getStatusWord()))
                  : "null";

        const std::string errorMessage
            = CardTransactionUtil::MSG_SAM_COMMAND_ERROR
              + "while processing response to SAM command: "
              + commandRef.getName() + "[" + sw + "]";

        const std::string detailedErrorMessage
            = CardTransactionUtil::MSG_SAM_COMMAND_ERROR
              + "while processing response to SAM command: "
              + commandRef.getName() + "[" + sw + "]"
              + CardTransactionUtil::getTransactionAuditDataAsString(
                  transactionAuditData, mSam);

        throw SymmetricCryptoException(
            errorMessage,
            UnexpectedCommandStatusException(detailedErrorMessage, e));
    }
}

} /* namespace legacysam */
} /* namespace crypto */
} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
