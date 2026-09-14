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
#include "keypop/calypso/crypto/legacysam/transaction/LegacyCardCertificateComputationData.hpp"

namespace keyple {
namespace card {
namespace calypso {
namespace crypto {
namespace legacysam {

using keypop::calypso::crypto::legacysam::transaction::
    LegacyCardCertificateComputationData;

using CommandContextDto = DtoAdapters::CommandContextDto;
using LegacyCardCertificateComputationDataAdapter
    = DtoAdapters::LegacyCardCertificateComputationDataAdapter;
using StatusProperties = Command::StatusProperties;

/**
 * Builds the "PSO Compute Certificate" SAM command.
 *
 * @since 0.6.0
 */
class KEYPLECARDCALYPSOCRYPTOLEGACYSAM_API CommandPsoComputeCertificate
: public virtual Command {
public:
    /**
     * Constructor
     *
     * <p>The "Card Public Key Data" data object (tag DF25) is a byte array
     * containing the certificate metadata and optionally the card ECC public
     * key.
     *
     * @param context The command context.
     * @param data A byte array of length 66 or 130 depending on whether the ECC
     * key is included or not.
     * @since 0.1.0
     */
    CommandPsoComputeCertificate(
        std::shared_ptr<CommandContextDto> context,
        std::shared_ptr<LegacyCardCertificateComputationData> data);

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
    std::shared_ptr<LegacyCardCertificateComputationDataAdapter> mData;

    /**
     *
     */
    static const std::map<int, const std::shared_ptr<StatusProperties>>
        STATUS_TABLE;

    /**
     * Generates the public key data for the card certificate generation.
     *
     * @return A byte array containing the public key data.
     */
    std::vector<std::uint8_t> generateCardPublicKeyData(
        std::shared_ptr<LegacyCardCertificateComputationDataAdapter> data);
};

} /* namespace legacysam */
} /* namespace crypto */
} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
