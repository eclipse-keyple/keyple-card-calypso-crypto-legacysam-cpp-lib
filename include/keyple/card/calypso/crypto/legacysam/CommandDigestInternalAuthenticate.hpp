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
 * Builds the Digest Internal Authenticate APDU command.
 *
 * <p>This outgoing command generates the signature to send to the card in a
 * Manage Secure Session command during a secure session in Extended Mode.
 *
 * @since 2.3.1
 */
class KEYPLECARDCALYPSOCRYPTOLEGACYSAM_API CommandDigestInternalAuthenticate
: public virtual Command {
public:
    /**
     * Constructor
     *
     * @param context The command context.
     * @since 2.3.1
     */
    explicit CommandDigestInternalAuthenticate(
        std::shared_ptr<CommandContextDto> context);

    /**
     * Gets the terminal signature.
     *
     * @return An 8-byte byte array.
     * @since 2.3.1
     */
    const std::vector<uint8_t>& getTerminalSignature() const;

    /**
     * {@inheritDoc}
     *
     * @since 0.4.0
     */
    void finalizeRequest() override;

    /**
     * {@inheritDoc}
     *
     * @since 0.4.0
     */
    bool isControlSamRequiredToFinalizeRequest() const override;

    /**
     * {@inheritDoc}
     *
     * @since 0.4.0
     */
    void
    parseResponse(const std::shared_ptr<ApduResponseApi> apduResponse) override;

    /**
     * {@inheritDoc}
     *
     * @since 2.3.1
     */
    const std::map<int, const std::shared_ptr<StatusProperties>>&
    getStatusTable() const override;

private:
    /**
     *
     */
    static const std::map<int, const std::shared_ptr<StatusProperties>>
        STATUS_TABLE;

    /**
     *
     */
    std::vector<uint8_t> mTerminalSignature;
};

} /* namespace legacysam */
} /* namespace crypto */
} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
