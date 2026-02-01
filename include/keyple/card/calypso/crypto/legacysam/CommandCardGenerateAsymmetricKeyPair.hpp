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
#include "keypop/calypso/crypto/legacysam/transaction/KeyPairContainer.hpp"

namespace keyple {
namespace card {
namespace calypso {
namespace crypto {
namespace legacysam {

using keypop::calypso::crypto::legacysam::transaction::KeyPairContainer;

using CommandContextDto = DtoAdapters::CommandContextDto;
using KeyPairContainerAdapter = DtoAdapters::KeyPairContainerAdapter;
using StatusProperties = Command::StatusProperties;

/**
 * Builds the "Card Generate Asymmetric Key Pair" SAM command.
 *
 * @since 0.6.0
 */
class KEYPLECARDCALYPSOCRYPTOLEGACYSAM_API
    CommandCardGenerateAsymmetricKeyPair final : public virtual Command {
public:
    /**
     * Constructor
     *
     * <p>The OID of the key to generate is "06082A8648CE3D030107" (P-256 curve
     * as referenced in FIPS PUB 186-4 publication).
     *
     * @param context The command context.
     * @param keyPairContainer The key pair container.
     * @since 0.6.0
     */
    CommandCardGenerateAsymmetricKeyPair(
        std::shared_ptr<CommandContextDto> context,
        std::shared_ptr<KeyPairContainer> keyPairContainer);

    /**
     * {@inheritDoc}
     *
     * @since 0.6.0
     */
    void finalizeRequest() override;

    /**
     * {@inheritDoc}
     *
     * @since 0.6.0
     */
    bool isControlSamRequiredToFinalizeRequest() const override;

    /**
     * {@inheritDoc}
     *
     * @since 0.6.0
     */
    void parseResponse(std::shared_ptr<ApduResponseApi> apduResponse) override;

    /**
     * {@inheritDoc}
     *
     * @since 0.6.0
     */
    const std::map<int, const std::shared_ptr<StatusProperties>>&
    getStatusTable() const override;

private:
    /**
     *
     */
    std::shared_ptr<KeyPairContainerAdapter> mKeyPairContainer;

    /**
     * @since 0.6.0
     */
    static const std::map<int, const std::shared_ptr<StatusProperties>>
        STATUS_TABLE;
};

} /* namespace legacysam */
} /* namespace crypto */
} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
