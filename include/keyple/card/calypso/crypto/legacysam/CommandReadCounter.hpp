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

namespace keyple {
namespace card {
namespace calypso {
namespace crypto {
namespace legacysam {

using StatusProperties = Command::StatusProperties;

/**
 * Builds the Read Event Counter APDU command.
 *
 * @since 0.1.0
 */
class KEYPLECARDCALYPSOCRYPTOLEGACYSAM_API CommandReadCounter
: public virtual Command {
public:
    /**
     * Constructor
     *
     * @param context The command context.
     * @param counterFileRecordNumber The number of the counter file record to
     * read (in range [0..2].
     * @since 0.1.0
     */
    CommandReadCounter(
        std::shared_ptr<DtoAdapters::CommandContextDto> context,
        int counterFileRecordNumber);

    /**
     * Retrieves the record number of the counter file that will be modified by
     * this command.
     *
     * @return An int.
     * @since 0.3.0
     */
    int getCounterFileRecordNumber() const;

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
    static const int SW_DATA_NOT_SIGNED_WARNING;

    /**
     *
     */
    int mCounterFileRecordNumber;

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
