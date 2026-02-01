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

#include <map>
#include <memory>

#include "keyple/card/calypso/crypto/legacysam/Command.hpp"
#include "keyple/card/calypso/crypto/legacysam/CommandRef.hpp"

namespace keyple {
namespace card {
namespace calypso {
namespace crypto {
namespace legacysam {

using StatusProperties = Command::StatusProperties;

/**
 * Builds the "Read Key Parameters" SAM command.
 *
 * @since 0.3.0
 */
class KEYPLECARDCALYPSOCRYPTOLEGACYSAM_API CommandReadKeyParameters
: public virtual Command {
public:
    /**
     * Constructor
     *
     * @param context The command context.
     * @param systemKeyType The type of the system key.
     * @since 0.3.0
     */
    CommandReadKeyParameters(
        std::shared_ptr<DtoAdapters::CommandContextDto> context,
        SystemKeyType systemKeyType);

    /**
     * Constructor
     *
     * @param context The command context.
     * @param kif The KIF of the key.
     * @param kvc The KVC of the key.
     * @since 0.9.0
     */
    CommandReadKeyParameters(
        std::shared_ptr<DtoAdapters::CommandContextDto> context,
        const std::uint8_t kif,
        const std::uint8_t kvc);

    /**
     * Constructor
     *
     * @param context The command context.
     * @param recordNumber the record number
     * @since 0.9.0
     */
    CommandReadKeyParameters(
        std::shared_ptr<DtoAdapters::CommandContextDto> context,
        int recordNumber);

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
    static const int SW_KEY_NOT_FOUND;

    /**
     *
     */
    static const int SW_DATA_NOT_SIGNED_WARNING;

    /**
     *
     */
    static const std::map<int, const std::shared_ptr<StatusProperties>>
        STATUS_TABLE;

    /**
     *
     */
    const SystemKeyType mSystemKeyType;

    /**
     *
     */
    std::uint16_t mKifKvc;

    /**
     *
     */
    const int mRecordNumber;
};

} /* namespace legacysam */
} /* namespace crypto */
} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
