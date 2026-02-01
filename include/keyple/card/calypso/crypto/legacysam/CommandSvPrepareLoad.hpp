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
#include "keypop/calypso/crypto/symmetric/SvCommandSecurityDataApi.hpp"

namespace keyple {
namespace card {
namespace calypso {
namespace crypto {
namespace legacysam {

using keypop::calypso::crypto::symmetric::SvCommandSecurityDataApi;

using CommandContextDto = DtoAdapters::CommandContextDto;
using StatusProperties = Command::StatusProperties;

/**
 * Builds the SV Prepare Debit or Undebit APDU command.
 *
 * @since 2.0.1
 */
class KEYPLECARDCALYPSOCRYPTOLEGACYSAM_API CommandSvPrepareLoad final
: public virtual Command {
public:
    /**
     * Constructor
     *
     * <p>Build the SvPrepareLoad APDU from the SvGet command and response, the
     * SvReload partial command
     *
     * @param context The command context.
     * @param data The SV input/output command data.
     * @since 2.0.1
     */
    CommandSvPrepareLoad(
        std::shared_ptr<CommandContextDto> context,
        std::shared_ptr<SvCommandSecurityDataApi> data);

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
    void parseResponse(std::shared_ptr<ApduResponseApi> apduResponse) override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.1
     */
    const std::map<int, const std::shared_ptr<StatusProperties>>&
    getStatusTable() const override;

private:
    /**
     *
     */
    std::shared_ptr<SvCommandSecurityDataApi> mData;

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
