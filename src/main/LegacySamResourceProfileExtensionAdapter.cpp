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

#include "keyple/card/calypso/crypto/legacysam/LegacySamResourceProfileExtensionAdapter.hpp"

#include <memory>
#include <regex>
#include <string>

#include "keyple/core/util/cpp/exception/Exception.hpp"
#include "keypop/reader/selection/CardSelectionResult.hpp"

namespace keyple {
namespace card {
namespace calypso {
namespace crypto {
namespace legacysam {

using keyple::core::util::cpp::exception::Exception;
using keypop::reader::selection::CardSelectionResult;

LegacySamResourceProfileExtensionAdapter::
    LegacySamResourceProfileExtensionAdapter(
        std::shared_ptr<LegacySamSelectionExtensionAdapter>
            samSelectionExtension,
        const std::string& powerOnDataRegex)
: mLegacySamSelectionExtension(samSelectionExtension)
, mPowerOnDataRegex(powerOnDataRegex)
{
}

std::shared_ptr<SmartCard>
LegacySamResourceProfileExtensionAdapter::matches(
    std::shared_ptr<CardReader> reader,
    std::shared_ptr<ReaderApiFactory> readerApiFactory)
{
    /* Is SAM inserted? */
    if (!reader->isCardPresent()) {
        return nullptr;
    }

    /* Init the SAM selector */
    auto cardSelector = readerApiFactory->createBasicCardSelector();
    if (!mPowerOnDataRegex.empty()) {
        cardSelector->filterByPowerOnData(mPowerOnDataRegex);
    }

    /*
     * Associate the provided reader to the prepared LegacySAM selection
     * extension and prepare an additional "Get Challenge" command for network
     * optimization.
     */
    mLegacySamSelectionExtension->setSamReader(reader);
    mLegacySamSelectionExtension->prepareGetChallengeIfNeeded();

    /* Prepare the SAM selection scenario */
    auto samCardSelectionManager
        = readerApiFactory->createCardSelectionManager();
    samCardSelectionManager->prepareSelection(
        cardSelector, mLegacySamSelectionExtension);

    /* Process the SAM selection scenario */
    std::shared_ptr<CardSelectionResult> samCardSelectionResult = nullptr;
    try {
        samCardSelectionResult
            = samCardSelectionManager->processCardSelectionScenario(reader);

    } catch (const Exception& e) {
        mLogger->error("SAM selection failed: %\n", e.getMessage());
    }

    return samCardSelectionResult ? samCardSelectionResult->getActiveSmartCard()
                                  : nullptr;
}

std::shared_ptr<SmartCard>
LegacySamResourceProfileExtensionAdapter::matches(
    const std::shared_ptr<SmartCard> smartCard)
{
    auto legacySamAdapter
        = std::dynamic_pointer_cast<LegacySamAdapter>(smartCard);
    if (!legacySamAdapter) {
        return nullptr;
    }

    if (!mPowerOnDataRegex.empty()) {
        std::regex regex(mPowerOnDataRegex);
        if (!std::regex_match(smartCard->getPowerOnData(), regex)) {
            return nullptr;
        }
    }

    return smartCard;
}

} /* namespace legacysam */
} /* namespace crypto */
} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
