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

#include "keyple/card/calypso/crypto/legacysam/LegacySamSelectionExtensionAdapter.hpp"

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "keyple/card/calypso/crypto/legacysam/AccessForbiddenException.hpp"
#include "keyple/card/calypso/crypto/legacysam/CommandGetData.hpp"
#include "keyple/card/calypso/crypto/legacysam/CommandReadCeilings.hpp"
#include "keyple/card/calypso/crypto/legacysam/CommandReadCounter.hpp"
#include "keyple/card/calypso/crypto/legacysam/CommandReadKeyParameters.hpp"
#include "keyple/card/calypso/crypto/legacysam/CommandReadParameters.hpp"
#include "keyple/card/calypso/crypto/legacysam/CommandUnlock.hpp"
#include "keyple/card/calypso/crypto/legacysam/LegacySamConstants.hpp"
#include "keyple/core/util/HexUtil.hpp"
#include "keyple/core/util/KeypleAssert.hpp"
#include "keyple/core/util/cpp/exception/IllegalStateException.hpp"
#include "keypop/calypso/card/transaction/InconsistentDataException.hpp"
#include "keypop/calypso/card/transaction/UnexpectedCommandStatusException.hpp"
#include "keypop/card/ChannelControl.hpp"
#include "keypop/card/ParseException.hpp"

namespace keyple {
namespace card {
namespace calypso {
namespace crypto {
namespace legacysam {

using keyple::core::util::Assert;
using keyple::core::util::HexUtil;
using keyple::core::util::cpp::exception::IllegalStateException;
using keypop::calypso::card::transaction::InconsistentDataException;
using keypop::calypso::card::transaction::UnexpectedCommandStatusException;
using keypop::card::ChannelControl;
using keypop::card::ParseException;

using CardRequestAdapter = DtoAdapters::CardRequestAdapter;
using CardSelectionRequestAdapter = DtoAdapters::CardSelectionRequestAdapter;

const int LegacySamSelectionExtensionAdapter::SW_NOT_LOCKED = 0x6985;
const std::string LegacySamSelectionExtensionAdapter::MSG_SAM_COMMAND_ERROR
    = "A SAM command error occurred ";

const std::unique_ptr<Logger> LegacySamSelectionExtensionAdapter::mLogger
    = LoggerFactory::getLogger(typeid(LegacySamSelectionExtensionAdapter));

LegacySamSelectionExtensionAdapter::LegacySamSelectionExtensionAdapter()
: mLegacySamAdapter(std::make_shared<LegacySamAdapter>(ProductType::SAM_C1))
, mContext(
      std::make_shared<DtoAdapters::CommandContextDto>(
          mLegacySamAdapter, nullptr, nullptr))
, mUnlockSettingType(UnlockSettingType::UNSET)
{
}

std::unique_ptr<CardSelectionRequestSpi>
LegacySamSelectionExtensionAdapter::getCardSelectionRequest()
{
    std::vector<std::shared_ptr<ApduRequestSpi>> cardSelectionApduRequests;
    switch (mUnlockSettingType) {
    case UnlockSettingType::UNLOCK_DATA: {
        auto commandUnlock = std::make_shared<CommandUnlock>(
            mUnlockProductType, mUnlockDataBytes);
        commandUnlock->getApduRequest()->addSuccessfulStatusWord(SW_NOT_LOCKED);
        mCommands.push_back(commandUnlock);
    }
        /* No break */
        /* FALLTHRU */
    case UnlockSettingType::UNSET:
        for (const auto& command : mCommands) {
            cardSelectionApduRequests.push_back(command->getApduRequest());
        }
        break;
    case UnlockSettingType::DYNAMIC_MODE_PROVIDER:
        /* Do not add command for now when using an Unlock Data provider */
        mCommandGetChallenge
            = std::make_shared<CommandGetChallenge>(mContext, 8);
        cardSelectionApduRequests.push_back(
            mCommandGetChallenge->getApduRequest());
        break;
    default:
        break;
    }

    if (cardSelectionApduRequests.empty()) {
        return std::unique_ptr<CardSelectionRequestAdapter>(
            new CardSelectionRequestAdapter(nullptr));
    }

    return std::unique_ptr<CardSelectionRequestAdapter>(
        new CardSelectionRequestAdapter(
            std::make_shared<DtoAdapters::CardRequestAdapter>(
                cardSelectionApduRequests, false)));
}

std::shared_ptr<SmartCardSpi>
LegacySamSelectionExtensionAdapter::parse(
    const std::shared_ptr<CardSelectionResponseApi>& cardSelectionResponseApi)
{
    try {
        mLegacySamAdapter->parseSelectionResponse(cardSelectionResponseApi);
        auto cardResponse = getCardResponse(cardSelectionResponseApi);
        parseCardResponse(cardResponse);
    } catch (const std::exception& e) {
        throw ParseException("Invalid SAM response: " + std::string(e.what()));
    }
    if (mLegacySamAdapter->getProductType() == ProductType::UNKNOWN
        && cardSelectionResponseApi->getSelectApplicationResponse() == nullptr
        && cardSelectionResponseApi->getPowerOnData().empty()) {
        throw ParseException(
            "Unable to create a LegacySam: no power-on data and no FCI "
            "provided");
    }
    return mLegacySamAdapter;
}

std::shared_ptr<CardResponseApi>
LegacySamSelectionExtensionAdapter::getCardResponse(
    std::shared_ptr<CardSelectionResponseApi> cardSelectionResponseApi)
{
    std::shared_ptr<CardResponseApi> cardResponse
        = cardSelectionResponseApi->getCardResponse();

    if (mUnlockSettingType == UnlockSettingType::STATIC_MODE_PROVIDER
        || mUnlockSettingType == UnlockSettingType::DYNAMIC_MODE_PROVIDER) {
        if (mTargetSamReader == nullptr) {
            throw std::logic_error("targetSamReader is not set");
        }

        std::vector<uint8_t> unlockData;
        if (mUnlockSettingType == UnlockSettingType::STATIC_MODE_PROVIDER) {
            unlockData = mStaticUnlockDataProvider->getUnlockData(
                mLegacySamAdapter->getSerialNumber());
        } else {
            mCommandGetChallenge->parseResponse(
                cardResponse->getApduResponses()[0]);
            unlockData = mDynamicUnlockDataProvider->getUnlockData(
                mLegacySamAdapter->getSerialNumber(),
                mLegacySamAdapter->popChallenge());
        }

        auto unlockCommand = std::make_shared<CommandUnlock>(
            mLegacySamAdapter->getProductType(), unlockData);
        unlockCommand->getApduRequest()->addSuccessfulStatusWord(
            0x6985);  // SW_NOT_LOCKED
        mCommands.insert(mCommands.begin(), unlockCommand);

        std::vector<std::shared_ptr<ApduRequestSpi>> cardSelectionApduRequests;
        for (const auto& command : mCommands) {
            cardSelectionApduRequests.push_back(command->getApduRequest());
        }

        auto cardRequest = std::make_shared<DtoAdapters::CardRequestAdapter>(
            cardSelectionApduRequests, false);

        cardResponse
            = std::dynamic_pointer_cast<ProxyReaderApi>(mTargetSamReader)
                  ->transmitCardRequest(cardRequest, ChannelControl::KEEP_OPEN);
    }
    return cardResponse;
}

void
LegacySamSelectionExtensionAdapter::parseCardResponse(
    std::shared_ptr<CardResponseApi> cardResponse)
{
    std::vector<std::shared_ptr<ApduResponseApi>> apduResponses;
    if (cardResponse) {
        apduResponses = cardResponse->getApduResponses();
    }

    if (mCommands.size() != apduResponses.size()) {
        throw std::logic_error("Mismatch in the number of requests/responses");
    }
    if (!mCommands.empty()) {
        parseApduResponses(mCommands, apduResponses);
    }
}

void
LegacySamSelectionExtensionAdapter::parseApduResponses(
    const std::vector<std::shared_ptr<Command>>& commands,
    const std::vector<std::shared_ptr<ApduResponseApi>>& apduResponses)
{
    /*
     * If there are more responses than requests, then we are unable to fill the
     * card image. In this case we stop processing immediately because it may be
     * a case of fraud, and we throw adesynchronized exception.
     */
    if (apduResponses.size() > commands.size()) {
        throw InconsistentDataException(
            "The number of commands/responses does not match: nb commands = "
            + std::to_string(commands.size())
            + ", nb responses = " + std::to_string(apduResponses.size()));
    }

    /*
     * We go through all the responses (and not the requests) because there may
     * be fewer in the case of an error that occurred in strict mode. In this
     * case the last response will raise an exception.
     */
    for (size_t i = 0; i < apduResponses.size(); i++) {
        try {
            commands[i]->parseResponse(apduResponses[i]);

        } catch (const CommandException& e) {
            if (dynamic_cast<const AccessForbiddenException*>(&e)
                && dynamic_cast<const CommandUnlock*>(commands[i].get())) {
                mLogger->warn("SAM not locked or already unlocked\n");

            } else {
                throw UnexpectedCommandStatusException(
                    MSG_SAM_COMMAND_ERROR
                        + " while processing responses to SAM commands: "
                        + commands[i]->getCommandRef().getName(),
                    e);
            }
        }
    }

    /*
     * Finally, if no error has occurred and there are fewer responses than
     * requests, then we throw a desynchronized exception.
     */
    if (apduResponses.size() < commands.size()) {
        throw InconsistentDataException(
            "The number of commands/responses does not match: nb commands = "
            + std::to_string(commands.size())
            + ", nb responses = " + std::to_string(apduResponses.size()));
    }
}

LegacySamSelectionExtension&
LegacySamSelectionExtensionAdapter::setUnlockData(
    const std::string& unlockData, ProductType productType)
{
    if (mUnlockSettingType != UnlockSettingType::UNSET) {
        throw std::logic_error(
            "A setting to unlock the SAM has already been set");
    }

    Assert::getInstance()
        .notEmpty(unlockData, "unlockData")
        .isTrue(unlockData.length() == 32, "unlock data length")
        .isHexString(unlockData, "unlockData");

    mUnlockProductType = productType;
    mUnlockDataBytes = HexUtil::toByteArray(unlockData);
    mUnlockSettingType = UnlockSettingType::UNLOCK_DATA;

    return *this;
}

LegacySamSelectionExtension&
LegacySamSelectionExtensionAdapter::setUnlockData(const std::string& unlockData)
{
    return setUnlockData(unlockData, ProductType::SAM_C1);
}

LegacySamSelectionExtension&
LegacySamSelectionExtensionAdapter::setStaticUnlockDataProvider(
    std::shared_ptr<LegacySamStaticUnlockDataProviderSpi>
        staticUnlockDataProvider)
{
    if (mUnlockSettingType != UnlockSettingType::UNSET) {
        throw IllegalStateException(
            "A setting to unlock the SAM has already been set");
    }
    Assert::getInstance().notNull(
        staticUnlockDataProvider, "staticUnlockDataProvider");

    mStaticUnlockDataProvider = std::move(staticUnlockDataProvider);
    mUnlockSettingType = UnlockSettingType::STATIC_MODE_PROVIDER;

    return *this;
}

LegacySamSelectionExtension&
LegacySamSelectionExtensionAdapter::setStaticUnlockDataProvider(
    std::shared_ptr<LegacySamStaticUnlockDataProviderSpi>
        staticUnlockDataProvider,
    std::shared_ptr<CardReader> targetSamReader)
{
    Assert::getInstance().notNull(targetSamReader, "targetSamReader");

    mTargetSamReader = std::move(targetSamReader);

    return setStaticUnlockDataProvider(std::move(staticUnlockDataProvider));
}

LegacySamSelectionExtension&
LegacySamSelectionExtensionAdapter::setDynamicUnlockDataProvider(
    std::shared_ptr<LegacySamDynamicUnlockDataProviderSpi>
        dynamicUnlockDataProvider)
{
    if (mUnlockSettingType != UnlockSettingType::UNSET) {
        throw IllegalStateException(
            "A setting to unlock the SAM has already been set");
    }

    Assert::getInstance().notNull(
        dynamicUnlockDataProvider, "dynamicUnlockDataProvider");

    mDynamicUnlockDataProvider = std::move(dynamicUnlockDataProvider);
    mUnlockSettingType = UnlockSettingType::DYNAMIC_MODE_PROVIDER;

    return *this;
}

LegacySamSelectionExtension&
LegacySamSelectionExtensionAdapter::setDynamicUnlockDataProvider(
    std::shared_ptr<LegacySamDynamicUnlockDataProviderSpi>
        dynamicUnlockDataProvider,
    std::shared_ptr<CardReader> targetSamReader)
{
    Assert::getInstance().notNull(targetSamReader, "targetSamReader");

    mTargetSamReader = std::move(targetSamReader);

    return setDynamicUnlockDataProvider(std::move(dynamicUnlockDataProvider));
}

LegacySamSelectionExtension&
LegacySamSelectionExtensionAdapter::prepareReadSamParameters()
{
    mCommands.push_back(std::make_shared<CommandReadParameters>(mContext));

    return *this;
}

LegacySamSelectionExtension&
LegacySamSelectionExtensionAdapter::prepareReadSystemKeyParameters(
    SystemKeyType systemKeyType)
{
    mCommands.push_back(
        std::make_shared<CommandReadKeyParameters>(mContext, systemKeyType));

    return *this;
}

LegacySamSelectionExtension&
LegacySamSelectionExtensionAdapter::prepareReadWorkKeyParameters(
    int recordNumber)
{
    Assert::getInstance().isInRange(
        recordNumber,
        LegacySamConstants::MIN_KEY_RECORD_NUMBER,
        LegacySamConstants::MAX_KEY_RECORD_NUMBER,
        "recordNumber");

    mCommands.push_back(
        std::make_shared<CommandReadKeyParameters>(mContext, recordNumber));

    return *this;
}

LegacySamSelectionExtension&
LegacySamSelectionExtensionAdapter::prepareReadWorkKeyParameters(
    uint8_t kif, uint8_t kvc)
{
    mCommands.push_back(
        std::make_shared<CommandReadKeyParameters>(mContext, kif, kvc));

    return *this;
}

LegacySamSelectionExtension&
LegacySamSelectionExtensionAdapter::prepareReadCounterStatus(int counterNumber)
{
    Assert::getInstance().isInRange(
        counterNumber,
        LegacySamConstants::MIN_COUNTER_NUMBER,
        LegacySamConstants::MAX_COUNTER_NUMBER,
        "counterNumber");

    for (const auto& command : mCommands) {
        auto readCounterCommand
            = std::dynamic_pointer_cast<CommandReadCounter>(command);
        if (readCounterCommand
            && readCounterCommand->getCounterFileRecordNumber()
                   == LegacySamConstants::COUNTER_TO_RECORD_LOOKUP
                       [counterNumber]) {
            // already scheduled
            return *this;
        }
    }
    mCommands.push_back(
        std::make_shared<CommandReadCounter>(
            mContext,
            LegacySamConstants::COUNTER_TO_RECORD_LOOKUP[counterNumber]));
    mCommands.push_back(
        std::make_shared<CommandReadCeilings>(
            mContext,
            LegacySamConstants::COUNTER_TO_RECORD_LOOKUP[counterNumber]));

    return *this;
}

LegacySamSelectionExtension&
LegacySamSelectionExtensionAdapter::prepareReadAllCountersStatus()
{
    for (int i = 0; i < 3; i++) {
        mCommands.push_back(std::make_shared<CommandReadCounter>(mContext, i));
        mCommands.push_back(std::make_shared<CommandReadCeilings>(mContext, i));
    }

    return *this;
}

LegacySamSelectionExtension&
LegacySamSelectionExtensionAdapter::prepareGetData(GetDataTag tag)
{
    mCommands.push_back(std::make_shared<CommandGetData>(mContext, tag));

    return *this;
}

LegacySamSelectionExtension&
LegacySamSelectionExtensionAdapter::prepareGetChallengeIfNeeded()
{
    if (mCommands.empty()
        || mCommands.back()->getCommandRef() != CommandRef::GET_CHALLENGE) {
        mCommands.push_back(std::make_shared<CommandGetChallenge>(mContext, 8));
    }

    return *this;
}

LegacySamSelectionExtension&
LegacySamSelectionExtensionAdapter::setSamReader(
    std::shared_ptr<CardReader> targetSamReader)
{
    mTargetSamReader = std::move(targetSamReader);

    return *this;
}

} /* namespace legacysam */
} /* namespace crypto */
} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
