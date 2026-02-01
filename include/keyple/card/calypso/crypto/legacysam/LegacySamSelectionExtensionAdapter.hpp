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

#pragma once

#include <memory>
#include <string>
#include <vector>

#include "keyple/card/calypso/crypto/legacysam/Command.hpp"
#include "keyple/card/calypso/crypto/legacysam/CommandGetChallenge.hpp"
#include "keyple/card/calypso/crypto/legacysam/LegacySamAdapter.hpp"
#include "keyple/core/util/cpp/Logger.hpp"
#include "keyple/core/util/cpp/LoggerFactory.hpp"
#include "keypop/calypso/crypto/legacysam/GetDataTag.hpp"
#include "keypop/calypso/crypto/legacysam/sam/LegacySamSelectionExtension.hpp"
#include "keypop/calypso/crypto/legacysam/spi/LegacySamDynamicUnlockDataProviderSpi.hpp"
#include "keypop/calypso/crypto/legacysam/spi/LegacySamStaticUnlockDataProviderSpi.hpp"
#include "keypop/card/CardResponseApi.hpp"
#include "keypop/card/spi/CardSelectionExtensionSpi.hpp"
#include "keypop/reader/CardReader.hpp"

namespace keyple {
namespace card {
namespace calypso {
namespace crypto {
namespace legacysam {

using keyple::core::util::cpp::Logger;
using keyple::core::util::cpp::LoggerFactory;
using keypop::calypso::crypto::legacysam::GetDataTag;
using keypop::calypso::crypto::legacysam::sam::LegacySamSelectionExtension;
using keypop::calypso::crypto::legacysam::spi::
    LegacySamDynamicUnlockDataProviderSpi;
using keypop::calypso::crypto::legacysam::spi::
    LegacySamStaticUnlockDataProviderSpi;
using keypop::card::CardResponseApi;
using keypop::card::spi::CardSelectionExtensionSpi;
using keypop::reader::CardReader;

/**
 * Adapter of LegacySamSelectionExtension.
 *
 * If not specified, the SAM product type used for unlocking is
 * LegacyProductType::SAM_C1.
 *
 * @since 0.1.0
 */
class LegacySamSelectionExtensionAdapter final
: public LegacySamSelectionExtension,
  public CardSelectionExtensionSpi {
public:
    /**
     * Creates a LegacySamSelectionExtension.
     *
     * @since 0.1.0
     */
    LegacySamSelectionExtensionAdapter();

    /**
     * {@inheritDoc}
     *
     * @since 0.1.0
     */
    std::unique_ptr<CardSelectionRequestSpi> getCardSelectionRequest() override;

    /**
     * {@inheritDoc}
     *
     * @since 0.1.0
     */
    std::shared_ptr<SmartCardSpi> parse(
        const std::shared_ptr<CardSelectionResponseApi>&
            cardSelectionResponseApi) override;

    /**
     * {@inheritDoc}
     *
     * @since 0.4.0
     */
    LegacySamSelectionExtension& setUnlockData(
        const std::string& unlockData, ProductType productType) override;

    /**
     * {@inheritDoc}
     *
     * @since 0.1.0
     */
    LegacySamSelectionExtension&
    setUnlockData(const std::string& unlockData) override;

    /**
     * {@inheritDoc}
     *
     * @since 0.5.0
     */
    LegacySamSelectionExtension& setStaticUnlockDataProvider(
        std::shared_ptr<LegacySamStaticUnlockDataProviderSpi>
            staticUnlockDataProvider) override;

    /**
     * {@inheritDoc}
     *
     * @since 0.5.0
     */
    LegacySamSelectionExtension& setStaticUnlockDataProvider(
        std::shared_ptr<LegacySamStaticUnlockDataProviderSpi>
            staticUnlockDataProvider,
        std::shared_ptr<CardReader> targetSamReader) override;

    /**
     * {@inheritDoc}
     *
     * @since 0.5.0
     */
    LegacySamSelectionExtension& setDynamicUnlockDataProvider(
        std::shared_ptr<LegacySamDynamicUnlockDataProviderSpi>
            dynamicUnlockDataProvider) override;

    /**
     * {@inheritDoc}
     *
     * @since 0.5.0
     */
    LegacySamSelectionExtension& setDynamicUnlockDataProvider(
        std::shared_ptr<LegacySamDynamicUnlockDataProviderSpi>
            dynamicUnlockDataProvider,
        std::shared_ptr<CardReader> targetSamReader) override;

    /**
     * {@inheritDoc}
     *
     * @since 0.9.0
     */
    LegacySamSelectionExtension& prepareReadSamParameters() override;

    /**
     * {@inheritDoc}
     *
     * @since 0.4.0
     */
    LegacySamSelectionExtension&
    prepareReadSystemKeyParameters(SystemKeyType systemKeyType) override;

    /**
     * {@inheritDoc}
     *
     * @since 0.9.0
     */
    LegacySamSelectionExtension&
    prepareReadWorkKeyParameters(int recordNumber) override;

    /**
     * {@inheritDoc}
     *
     * @since 0.9.0
     */
    LegacySamSelectionExtension&
    prepareReadWorkKeyParameters(uint8_t kif, uint8_t kvc) override;

    /**
     * {@inheritDoc}
     *
     * @since 0.4.0
     */
    LegacySamSelectionExtension&
    prepareReadCounterStatus(int counterNumber) override;

    /**
     * {@inheritDoc}
     *
     * @since 0.4.0
     */
    LegacySamSelectionExtension& prepareReadAllCountersStatus() override;

    /**
     * {@inheritDoc}
     *
     * @since 0.6.0
     */
    LegacySamSelectionExtension& prepareGetData(GetDataTag tag) override;

    /**
     * Schedules the execution of a "Get Challenge" command if the last command
     * is not a "Get Challenge" command.
     *
     * Once this command is processed, the challenge (as an 8-byte byte array)
     * can be access using the LegacySamAdapter::popChallenge() method.
     *
     * @return The current instance.
     * @since 0.8.0
     */
    LegacySamSelectionExtension& prepareGetChallengeIfNeeded();

    /**
     * Provides the CardReader for communicating with the SAM during the
     * unlocking process when involving a static or a dynamic unlock data
     * providers.
     *
     * @param targetSamReader The card reader used to communicate with the
     * target SAM.
     * @return The current instance.
     * @since 0.5.0
     */
    LegacySamSelectionExtension&
    setSamReader(std::shared_ptr<CardReader> targetSamReader);

private:
    /**
     *
     */
    enum class UnlockSettingType {
        UNSET,
        UNLOCK_DATA,
        STATIC_MODE_PROVIDER,
        DYNAMIC_MODE_PROVIDER
    };

    /**
     *
     */
    static const int SW_NOT_LOCKED;

    /**
     *
     */
    static const std::string MSG_SAM_COMMAND_ERROR;

    /**
     *
     */
    static const std::unique_ptr<Logger> mLogger;

    /**
     *
     */
    std::shared_ptr<LegacySamAdapter> mLegacySamAdapter;

    /**
     *
     */
    std::shared_ptr<CommandContextDto> mContext;

    /**
     *
     */
    std::vector<std::shared_ptr<Command>> mCommands;

    /**
     *
     */
    std::shared_ptr<CardReader> mTargetSamReader;

    /**
     *
     */
    std::shared_ptr<CommandGetChallenge> mCommandGetChallenge;

    /**
     *
     */
    UnlockSettingType mUnlockSettingType;

    /**
     *
     */
    std::shared_ptr<LegacySamStaticUnlockDataProviderSpi>
        mStaticUnlockDataProvider;

    /**
     *
     */
    std::shared_ptr<LegacySamDynamicUnlockDataProviderSpi>
        mDynamicUnlockDataProvider;

    /**
     *
     */
    std::vector<uint8_t> mUnlockDataBytes;

    /**
     *
     */
    ProductType mUnlockProductType;

    /**
     * Returns the card response and handles the unlock command if needed.
     *
     * @param cardSelectionResponseApi The response to the initial card
     * selection request.
     * @return The updated card response after handling the unlock command.
     * @throw AbstractApduException if an error occurs while handling the unlock
     * command.
     */
    std::shared_ptr<CardResponseApi> getCardResponse(
        std::shared_ptr<CardSelectionResponseApi> cardSelectionResponseApi);

    /**
     * Parses the APDU responses returned by the SAM to all commands.
     *
     * @param cardResponse The card response.
     */
    void parseCardResponse(std::shared_ptr<CardResponseApi> cardResponse);

    /**
     * Parses the APDU responses and updates the LegacySam image.
     *
     * @param commands The list of commands that get the responses.
     * @param apduResponses The APDU responses returned by the SAM to all
     * commands.
     */
    static void parseApduResponses(
        const std::vector<std::shared_ptr<Command>>& commands,
        const std::vector<std::shared_ptr<ApduResponseApi>>& apduResponses);
};

} /* namespace legacysam */
} /* namespace crypto */
} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
