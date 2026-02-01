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

using BasicSignatureComputationDataAdapter
    = DtoAdapters::BasicSignatureComputationDataAdapter;
using BasicSignatureVerificationDataAdapter
    = DtoAdapters::BasicSignatureVerificationDataAdapter;
using CommandContextDto = DtoAdapters::CommandContextDto;
using StatusProperties = Command::StatusProperties;

/**
 * The "Data Cipher" command.
 *
 * @since 2.0.0
 */
class KEYPLECARDCALYPSOCRYPTOLEGACYSAM_API CommandDataCipher
: public virtual Command {
public:
    /**
     * Constructor
     *
     * @param context The command context.
     * @param signatureComputationData The signature computation data
     * (optional).
     * @param signatureVerificationData The signature computation data
     * (optional).
     * @since 0.1.0
     */
    CommandDataCipher(
        std::shared_ptr<CommandContextDto> context,
        std::shared_ptr<BasicSignatureComputationDataAdapter>
            signatureComputationData,
        std::shared_ptr<BasicSignatureVerificationDataAdapter>
            signatureVerificationData);

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
    static const std::map<int, const std::shared_ptr<StatusProperties>>
        STATUS_TABLE;

    /**
     *
     */
    std::shared_ptr<BasicSignatureComputationDataAdapter>
        mSignatureComputationData;

    /**
     *
     */
    std::shared_ptr<BasicSignatureVerificationDataAdapter>
        mSignatureVerificationData;
};

} /* namespace legacysam */
} /* namespace crypto */
} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
