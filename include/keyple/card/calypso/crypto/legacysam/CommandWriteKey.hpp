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

/**
 * Builds the Write Key APDU command.
 *
 * @since 0.9.0
 */
class KEYPLECARDCALYPSOCRYPTOLEGACYSAM_API CommandWriteKey final
: public virtual Command {
public:
    /**
     * Constructor
     *
     * @param context The command context.
     * @param systemKeyType The type of the system key to transfer.
     * @param kvc The KVC of the key to transfer.
     * @param keyParameters The key parameters.
     * @param isTransferredKeyDiversified true if the transferred key needs to
     * be diversified.
     * @since 0.9.0
     */
    CommandWriteKey(
        std::shared_ptr<CommandContextDto> context,
        SystemKeyType systemKeyType,
        std::uint8_t kvc,
        const std::vector<std::uint8_t>& keyParameters,
        bool isTransferredKeyDiversified);

    /**
     * Constructor
     *
     * @param context The command context.
     * @param kif The KIF of the key to transfer.
     * @param kvc The KVC of the key to transfer.
     * @param targetRecordNumber The number of the record where to write the
     * key.
     * @param keyParameters The key parameters.
     * @param isTransferredKeyDiversified true if the transferred key needs to
     * be diversified.
     * @since 0.9.0
     */
    CommandWriteKey(
        std::shared_ptr<CommandContextDto> context,
        std::uint8_t kif,
        std::uint8_t kvc,
        int targetRecordNumber,
        const std::vector<std::uint8_t>& keyParameters,
        bool isTransferredKeyDiversified);

    /**
     * Constructor
     *
     * @param context The command context.
     * @param kif The KIF of the key to transfer.
     * @param kvc The KVC of the key to transfer.
     * @param targetRecordNumber The number of the record where to write the
     * key.
     * @param keyParameters The key parameters.
     * @param diversifier The diversifier to use as ArbitraryDiversifier.
     * @since 0.9.0
     */
    CommandWriteKey(
        std::shared_ptr<CommandContextDto> context,
        std::uint8_t kif,
        std::uint8_t kvc,
        int targetRecordNumber,
        const std::vector<std::uint8_t>& keyParameters,
        const std::vector<std::uint8_t>& diversifier);

    /**
     * Constructor
     *
     * @param context The command context.
     * @param lockIndex The index of the lock file.
     * @param lockParameters The lock permissions parameters.
     * @since 0.9.0
     */
    CommandWriteKey(
        std::shared_ptr<CommandContextDto> context,
        std::uint8_t lockIndex,
        std::uint8_t lockParameters,
        bool isTransferredLockDiversified);

    /**
     * Constructor
     *
     * @param context The command context.
     * @param plainLockDataBlock A 48-byte byte array representing the lock data
     * block including the lock file.
     * @since 0.9.0
     */
    CommandWriteKey(
        std::shared_ptr<CommandContextDto> context,
        const std::vector<std::uint8_t>& plainLockDataBlock);

    /**
     * {@inheritDoc}
     *
     * @since 0.9.0
     */
    void finalizeRequest() override;

    /**
     * {@inheritDoc}
     *
     * @since 0.9.0
     */
    bool isControlSamRequiredToFinalizeRequest() const override;

    /**
     * {@inheritDoc}
     *
     * @since 0.9.0
     */
    void parseResponse(std::shared_ptr<ApduResponseApi> apduResponse) override;

    /**
     * {@inheritDoc}
     *
     * @since 0.9.0
     */
    const std::map<int, const std::shared_ptr<StatusProperties>>&
    getStatusTable() const override;

    /**
     * Builds a plain data block for a lock file using the provided lock index,
     * lock parameters, and lock value.
     *
     * @param lockIndex The index of the lock file.
     * @param lockParameters The lock permissions parameters.
     * @param lockValue The lock value.
     * @return A 48-byte byte array representing the plain data block.
     * @since 0.9.0
     */
    static std::vector<std::uint8_t> buildPlainLockDataBlock(
        std::uint8_t lockIndex,
        std::uint8_t lockParameters,
        const std::vector<std::uint8_t>& lockValue);

private:
    /**
     *
     */
    const std::uint8_t mTargetKeyReference;

    /**
     *
     */
    const SystemKeyType mCipheringKeyType;

    /**
     *
     */
    const std::uint8_t mSourceKeyKif;

    /**
     *
     */
    const std::uint8_t mSourceKeyKvc;

    /**
     *
     */
    std::vector<std::uint8_t> mKeyParameters;

    /**
     *
     */
    const bool mIsTransferredObjectDiversified;

    /**
     *
     */
    std::uint8_t mCipheringKeyKvc;

    /**
     * Either ciphered or plain data block.
     */
    std::vector<std::uint8_t> mWriteKeyCommandData;

    /**
     *
     */
    const std::vector<std::uint8_t> mArbitraryDiversifier;

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
