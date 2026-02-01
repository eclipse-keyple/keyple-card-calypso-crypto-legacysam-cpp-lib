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

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "keyple/card/calypso/crypto/legacysam/DtoAdapters.hpp"
#include "keypop/calypso/crypto/legacysam/sam/LegacySam.hpp"

namespace keyple {
namespace card {
namespace calypso {
namespace crypto {
namespace legacysam {

using keyple::card::calypso::crypto::legacysam::DtoAdapters;
using keypop::calypso::crypto::legacysam::sam::LegacySam;

/**
 * Util to help with Legacy SAM specificities.
 *
 * @since 0.4.0
 */
class LegacySamUtil final {
public:
    /**
     * Create a regular expression to be used as "Power on data" filter in the
     * selection process.
     *
     * <p>Two criteria are available:
     *
     * <ul>
     *   <li>A filter to target SAMs having a specific LegacySam.ProductType.
     *   <li>A filter to target SAMs having a serial number matching a specific
     *       regular expression.
     * </ul>
     *
     * <p>Concerning the serial number, the regular expression is based on a
     * hexadecimal representation of the number.
     *
     * <p>Example:
     *
     * <ul>
     *   <li>A filter targeting all SAMs having an 8-byte serial number starting
     *       with A0h would be "^A0.{6}$".
     *   <li>A filter targeting a SAM having the exact serial number 12345678h
     *       would be "12345678".
     * </ul>
     *
     * <p>Both argument are optional and can be null.
     *
     * @param productType The target SAM product type.
     * @param serialNumberRegex A regular expression matching the SAM serial
     * number.
     * @return A not empty string containing a regular
     * @throw IllegalArgumentException If productType is null.
     * @throw IllegalArgumentException If serialNumberRegex is null, empty or
     * invalid.
     * @since 0.4.0
     */
    static const std::string buildPowerOnDataFilter(
        const LegacySam::ProductType productType,
        const std::string& serialNumber);

    /**
     * Converts the provided date into a long. It is in BCD format 0xYYYYMMDD,
     * where YYYY represents the four-digit year, MM the two-digit month, and DD
     * the two-digit day.
     *
     * @param year The year (0-9999).
     * @param month The month (1-99).
     * @param day The day (1-99).
     * @return A long in BCD format.
     * @since 0.6.0
     */
    static uint32_t
    convertDateToBcdLong(uint32_t year, uint32_t month, uint32_t day);

    /**
     * Computes a challenge for static mode using the provided SAM context and
     * system key type.
     *
     * @param samContext The context containing details about the SAM.
     * @param systemKeyType The type of system key to use for the challenge.
     * @return A byte array representing the computed challenge.
     * @since 0.9.0
     */
    static std::vector<uint8_t> computeStaticModeChallenge(
        std::shared_ptr<DtoAdapters::TargetSamContextDto> samContext,
        SystemKeyType systemKeyType);

private:
    /**
     * Private constructor
     */
    LegacySamUtil() = default;
};

} /* namespace legacysam */
} /* namespace crypto */
} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
