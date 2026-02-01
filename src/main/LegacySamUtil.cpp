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

#include "keyple/card/calypso/crypto/legacysam/LegacySamUtil.hpp"

#include <memory>
#include <string>
#include <vector>

#include "keyple/core/util/ByteArrayUtil.hpp"
#include "keyple/core/util/cpp/exception/IllegalArgumentException.hpp"

namespace keyple {
namespace card {
namespace calypso {
namespace crypto {
namespace legacysam {

using keyple::core::util::ByteArrayUtil;
using keyple::core::util::cpp::exception::IllegalArgumentException;

const std::string
LegacySamUtil::buildPowerOnDataFilter(
    const LegacySam::ProductType productType,
    const std::string& serialNumberRegex)
{
    std::string snRegex;

    /* Check if serialNumber is defined. */
    if (serialNumberRegex.empty()) {
        /* Match all serial numbers. */
        snRegex = ".{8}";

    } else {
        /* Match the provided serial number (could be a regex substring). */
        snRegex = serialNumberRegex;
    }

    /*
     * build the final Atr regex according to the SAM subtype and serial number
     * if any.
     *
     * The header is starting with 3B, its total length is 4 or 6 bytes (8 or 10
     * hex digits)
     */
    std::string applicationTypeMask;

    switch (productType) {
    case LegacySam::ProductType::SAM_C1:
    case LegacySam::ProductType::HSM_C1:
        applicationTypeMask = "C1";
        break;
    case LegacySam::ProductType::SAM_S1DX:
        applicationTypeMask = "D?";
        break;
    case LegacySam::ProductType::SAM_S1E1:
        applicationTypeMask = "E1";
        break;
    case LegacySam::ProductType::NONE:
        /* match any ATR */
        return ".*";
    default:
        throw IllegalArgumentException("Unknown SAM subtype");
    }

    return "3B(.{6}|.{10})805A..80" + applicationTypeMask + ".{6}" + snRegex
           + "829000";
}

uint32_t
LegacySamUtil::convertDateToBcdLong(uint32_t year, uint32_t month, uint32_t day)
{
    uint32_t bcdYear = static_cast<uint32_t>(
        (year / 1000) << 12 | (year / 100 % 10) << 8 | (year % 100 / 10) << 4
        | (year % 10));
    uint32_t bcdMonth = static_cast<uint32_t>((month / 10) << 4 | (month % 10));
    uint32_t bcdDay = static_cast<uint32_t>((day / 10) << 4 | (day % 10));

    return (bcdYear << 16) | (bcdMonth << 8) | bcdDay;
}

std::vector<uint8_t>
LegacySamUtil::computeStaticModeChallenge(
    std::shared_ptr<DtoAdapters::TargetSamContextDto> samContext,
    SystemKeyType systemKeyType)
{
    // compute the challenge
    std::vector<std::uint8_t> challenge(8);

    if (!samContext->getSystemKeyTypeToCounterNumberMap().empty()) {
        auto keyCounterNumberIt
            = samContext->getSystemKeyTypeToCounterNumberMap().find(
                systemKeyType);
        if (keyCounterNumberIt
            != samContext->getSystemKeyTypeToCounterNumberMap().end()) {
            auto keyCounterNumber = keyCounterNumberIt->second;
            auto counterValueIt
                = samContext->getCounterNumberToCounterValueMap().find(
                    keyCounterNumber);
            if (counterValueIt
                == samContext->getCounterNumberToCounterValueMap().end()) {
                auto counterValue = counterValueIt->second;
                ByteArrayUtil::copyBytes(counterValue, challenge, 5, 3);

                // increment counter
                samContext
                    ->getCounterNumberToCounterValueMap()[keyCounterNumber]
                    = counterValue + 1;
            }
        }
    }

    return challenge;
}

} /* namespace legacysam */
} /* namespace crypto */
} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
