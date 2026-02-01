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
 * Builds the Digest Update APDU command.
 *
 * <p>This command have to be sent twice for each command executed during a
 * session. First time for the command sent and second time for the answer
 * received.
 *
 * @since 2.0.1
 */
class KEYPLECARDCALYPSOCRYPTOLEGACYSAM_API CommandDigestUpdate
: public virtual Command {
public:
    /**
     * Constructor
     *
     * @param context The command context.
     * @param encryptedSession the encrypted session flag, true if encrypted.
     * @param digestData all bytes from command sent by the card or response
     * from the command.
     * @throw IllegalArgumentException If the digest data is null or has a
     * length &gt; 255
     * @since 2.0.1
     */
    CommandDigestUpdate(
        std::shared_ptr<CommandContextDto> context,
        bool encryptedSession,
        const std::vector<uint8_t>& digestData);

    /**
     * Return the command output.
     *
     * @return A not null byte array.
     * @since 0.4.0
     */
    const std::vector<std::uint8_t>& getProcessedData() const;

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
    /*
     *
     */
    std::vector<uint8_t> mProcessedData;

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
