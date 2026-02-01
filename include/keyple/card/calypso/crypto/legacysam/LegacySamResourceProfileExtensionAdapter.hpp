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

#include "keyple/card/calypso/crypto/legacysam/LegacySamSelectionExtensionAdapter.hpp"
#include "keyple/core/service/resource/spi/CardResourceProfileExtension.hpp"
#include "keyple/core/util/cpp/Logger.hpp"
#include "keyple/core/util/cpp/LoggerFactory.hpp"
#include "keypop/reader/ReaderApiFactory.hpp"
#include "keypop/reader/selection/spi/SmartCard.hpp"

namespace keyple {
namespace card {
namespace calypso {
namespace crypto {
namespace legacysam {

using keyple::core::service::resource::spi::CardResourceProfileExtension;
using keyple::core::util::cpp::Logger;
using keyple::core::util::cpp::LoggerFactory;
using keypop::reader::ReaderApiFactory;
using keypop::reader::selection::spi::SmartCard;

/**
 * Adapter of CardResourceProfileExtension dedicated to SAM identification.
 *
 * @since 0.1.0
 */
class LegacySamResourceProfileExtensionAdapter final
: public CardResourceProfileExtension {
public:
    /**
     * @param samSelectionExtension The LegacySamSelectionExtension.
     * @param powerOnDataRegex The power on data regex.
     * @since 0.1.0
     */
    LegacySamResourceProfileExtensionAdapter(
        std::shared_ptr<LegacySamSelectionExtensionAdapter>
            samSelectionExtension,
        const std::string& powerOnDataRegex);

    /**
     * {@inheritDoc}
     *
     * @since 0.1.0
     */
    std::shared_ptr<SmartCard> matches(
        std::shared_ptr<CardReader> reader,
        std::shared_ptr<ReaderApiFactory> readerApiFactory) override;

    /**
     * {@inheritDoc}
     *
     * @since 0.8.0
     */
    std::shared_ptr<SmartCard>
    matches(const std::shared_ptr<SmartCard> smartCard) override;

private:
    /**
     *
     */
    const std::unique_ptr<Logger> mLogger = LoggerFactory::getLogger(
        typeid(LegacySamResourceProfileExtensionAdapter));
    /**
     *
     */
    std::shared_ptr<LegacySamSelectionExtensionAdapter>
        mLegacySamSelectionExtension;

    /**
     *
     */
    const std::string mPowerOnDataRegex;
};

} /* namespace legacysam */
} /* namespace crypto */
} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
