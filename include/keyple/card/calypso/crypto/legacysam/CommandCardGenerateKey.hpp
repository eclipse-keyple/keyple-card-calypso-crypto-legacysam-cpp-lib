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
#include <map>
#include <memory>
#include <vector>

#include "keyple/card/calypso/crypto/legacysam/Command.hpp"
#include "keyple/card/calypso/crypto/legacysam/DtoAdapters.hpp"

namespace keyple {
namespace card {
namespace calypso {
namespace crypto {
namespace legacysam {

using CommandContextDto = DtoAdapters::CommandContextDto;
using StatusProperties = Command::StatusProperties;

/**
 * Builds the Give Random APDU command.
 *
 * @since 2.0.1
 */
class KEYPLECARDCALYPSOCRYPTOLEGACYSAM_API CommandCardGenerateKey final
: public virtual Command {
public:
    /**
     * Constructor
     *
     * <p>If bot KIF and KVC of the ciphering are equal to 0, the source key is
     * ciphered with the null key.
     *
     * @param context The command context.
     * @param cipheringKif The KIF of the ciphering key.
     * @param cipheringKvc The KVC of the ciphering key.
     * @param sourceKif The KIF of the source key.
     * @param sourceKvc The KVC of the source key.
     * @since 2.0.1
     */
    CommandCardGenerateKey(
        std::shared_ptr<CommandContextDto> context,
        uint8_t cipheringKif,
        uint8_t cipheringKvc,
        uint8_t sourceKif,
        uint8_t sourceKvc);

    /**
     * Gets the 32 bytes of ciphered data.
     *
     * @return the ciphered data byte array or null if the operation failed
     * @since 2.0.1
     */
    const std::vector<uint8_t>& getCipheredData() const;

    /**
     * {@inheritDoc}
     *
     * @since 0.3.0
     */
    void finalizeRequest() override;

    /**
     * {@inheritDoc}
     *
     * @since 0.3.0
     */
    bool isControlSamRequiredToFinalizeRequest() const override;

    /**
     * {@inheritDoc}
     *
     * @since 0.3.0
     */
    void parseResponse(std::shared_ptr<ApduResponseApi> apduResponse) override;

    /**
     * {@inheritDoc}
     *
     * @since 0.1.0
     */
    const std::map<int, const std::shared_ptr<StatusProperties>>&
    getStatusTable() const override;

private:
    /**
     *
     */
    std::vector<std::uint8_t> mCipheredData;

    /**
     *
     */
    static const std::map<int, const std::shared_ptr<StatusProperties>>
        STATUS_TABLE;
};

} /* namespace legacysam */
} /* namespace crypto */
} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
