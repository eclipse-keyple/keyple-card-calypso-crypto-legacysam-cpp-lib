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
#include "keyple/card/calypso/crypto/legacysam/CommandRef.hpp"
#include "keyple/card/calypso/crypto/legacysam/LegacySamConstants.hpp"
#include "keypop/calypso/crypto/legacysam/GetDataTag.hpp"

namespace keyple {
namespace card {
namespace calypso {
namespace crypto {
namespace legacysam {

using keypop::calypso::crypto::legacysam::GetDataTag;

using StatusProperties = Command::StatusProperties;

/**
 * Builds the Get Data APDU command.
 *
 * @since 0.6.0
 */
class KEYPLECARDCALYPSOCRYPTOLEGACYSAM_API CommandGetData
: public virtual Command {
public:
    /**
     * Constructor
     *
     * @param context The command context.
     * @param tag The tag to retrieve the data for.
     * @since 0.6.0
     */
    CommandGetData(
        std::shared_ptr<DtoAdapters::CommandContextDto> context,
        GetDataTag tag);

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
    const LegacySamConstants::TagInfo mTagInfo;

    /**
     *
     */
    static int getExpectedTotalLength(GetDataTag tag);
};

} /* namespace legacysam */
} /* namespace crypto */
} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
