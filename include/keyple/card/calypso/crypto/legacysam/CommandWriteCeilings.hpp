/******************************************************************************
 * Copyright (c) 2019 Calypso Networks Association https://calypsonet.org/    *
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
#include "keyple/card/calypso/crypto/legacysam/DtoAdapters.hpp"
#include "keyple/card/calypso/crypto/legacysam/LegacySamConstants.hpp"
#include "keypop/calypso/crypto/legacysam/CounterIncrementAccess.hpp"

namespace keyple {
namespace card {
namespace calypso {
namespace crypto {
namespace legacysam {

using CommandContextDto = DtoAdapters::CommandContextDto;
using StatusProperties = Command::StatusProperties;
using TargetSamContextDto = DtoAdapters::TargetSamContextDto;

/**
 * Builds the Write Ceilings APDU command.
 *
 * @since 0.1.0
 */
class KEYPLECARDCALYPSOCRYPTOLEGACYSAM_API CommandWriteCeilings final
: public virtual Command {
public:
    /**
     * Constructor
     *
     * @param context The command context.
     * @param targetSamContext The target SAM context.
     * @param counterNumber The number of the counter whose ceiling is to be
     * written (in range [0..26]).
     * @param ceilingValue The ceiling value.
     * @since 0.1.0
     */
    CommandWriteCeilings(
        std::shared_ptr<CommandContextDto> context,
        std::shared_ptr<TargetSamContextDto> targetSamContext,
        int counterNumber,
        int ceilingValue);

    /**
     * Constructor
     *
     * @param context The command context.
     * @param counterNumber The number of the counter whose ceiling is to be
     * written (in range [0..26]).
     * @param ceilingValue The ceiling value.
     * @since 0.9.0
     */
    CommandWriteCeilings(
        std::shared_ptr<CommandContextDto> context,
        int counterNumber,
        int ceilingValue);

    /**
     * Constructor
     *
     * @param context The command context.
     * @param targetSamContext The target SAM context.
     * @param counterNumber The number of the counter whose ceiling is to be
     * written (in range [0..26]).
     * @param ceilingValue The ceiling value.
     * @param counterIncrementAccess The counter incrementation configuration.
     * @since 0.1.0
     */
    CommandWriteCeilings(
        std::shared_ptr<CommandContextDto> context,
        std::shared_ptr<TargetSamContextDto> targetSamContext,
        int counterNumber,
        int ceilingValue,
        CounterIncrementAccess counterIncrementAccess);

    /**
     * Constructor
     *
     * @param context The command context.
     * @param counterNumber The number of the counter whose ceiling is to be
     * written (in range [0..26]).
     * @param ceilingValue The ceiling value.
     * @param counterIncrementAccess The counter incrementation configuration.
     * @since 0.1.0
     */
    CommandWriteCeilings(
        std::shared_ptr<CommandContextDto> context,
        int counterNumber,
        int ceilingValue,
        CounterIncrementAccess counterIncrementAccess);

    /**
     * Add a counter to be updated.
     *
     * <p>This command allows the upper layer to create a unique command when
     * counters belongs to the same record into the SAM.
     *
     * @param counterNumber The counter number (in range [0..26]).
     * @param ceilingValue The ceiling value to be written (in range
     * [0..16777210]).
     * @param counterIncrementAccess True if free incrementing of the counter
     * should be allowed.
     * @since 0.3.0
     */
    void addCounter(
        int counterNumber,
        int ceilingValue,
        CounterIncrementAccess counterIncrementAccess);

    /**
     * Returns the target counter file record.
     *
     * @return -1 if the command is not targeting a record.
     * @since 0.3.0
     */
    int getCounterFileRecordNumber() const;

    /**
     * {@inheritDoc}
     *
     * @since 0.1.0
     */
    const std::map<int, const std::shared_ptr<StatusProperties>>&
    getStatusTable() const override;

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

private:
    /**
     * Computes the plain data block in the case of a multiple counter writing.
     */
    void computePlainData();

    /**
     *
     */
    std::shared_ptr<DtoAdapters::TargetSamContextDto> mTargetSamContext;

    /**
     *
     */
    std::vector<uint8_t> mPlainData;

    /**
     *
     */
    std::map<int, CounterIncrementAccess>
        mCounterNumberToManualCounterIncrementAuthorizedMap;

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
