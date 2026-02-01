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
#include <memory>
#include <vector>

#include "keyple/card/calypso/crypto/legacysam/CommonTransactionManagerAdapter.hpp"
#include "keypop/calypso/crypto/legacysam/transaction/SecureWriteTransactionManager.hpp"

namespace keyple {
namespace card {
namespace calypso {
namespace crypto {
namespace legacysam {

using keypop::calypso::crypto::legacysam::transaction::
    SecureWriteTransactionManager;

/**
 * Adapter of SecureWriteTransactionManager.
 *
 * @since 0.9.0
 */
class SecureWriteTransactionManagerAdapter final
: public CommonTransactionManagerAdapter,
  public SecureWriteTransactionManager,
  public std::enable_shared_from_this<SecureWriteTransactionManagerAdapter> {
public:
    /**
     * Constructor
     *
     * @param targetSamReader The reader through which the target SAM
     * communicates.
     * @param targetSam The target legacy SAM.
     * @param controlSamReader The reader through which the control SAM
     * communicates.
     * @param controlSam The control legacy SAM.
     */
    SecureWriteTransactionManagerAdapter(
        std::shared_ptr<ProxyReaderApi> targetSamReader,
        std::shared_ptr<LegacySamAdapter> targetSam,
        std::shared_ptr<ProxyReaderApi> controlSamReader,
        std::shared_ptr<LegacySamAdapter> controlSam);

    /**
     * {@inheritDoc}
     *
     * @since 0.9.0
     */
    SecureWriteTransactionManager&
    prepareWriteSamParameters(const std::vector<uint8_t>& parameters) override;

    /**
     * {@inheritDoc}
     *
     * @since 0.9.0
     */
    SecureWriteTransactionManager& prepareTransferSystemKey(
        SystemKeyType systemKeyType,
        uint8_t kvc,
        const std::vector<uint8_t>& systemKeyParameters) override;

    /**
     * {@inheritDoc}
     *
     * @since 0.9.0
     */
    SecureWriteTransactionManager& prepareTransferSystemKeyDiversified(
        SystemKeyType systemKeyType,
        uint8_t kvc,
        const std::vector<uint8_t>& systemKeyParameters) override;

    /**
     * {@inheritDoc}
     *
     * @since 0.9.0
     */
    SecureWriteTransactionManager& prepareTransferWorkKey(
        uint8_t kif,
        uint8_t kvc,
        const std::vector<uint8_t>& workKeyParameters,
        int targetRecordNumber) override;

    /**
     * {@inheritDoc}
     *
     * @since 0.9.0
     */
    SecureWriteTransactionManager& prepareTransferWorkKeyDiversified(
        uint8_t kif,
        uint8_t kvc,
        const std::vector<uint8_t>& workKeyParameters,
        int targetRecordNumber) override;

    /**
     * {@inheritDoc}
     *
     * @since 0.9.0
     */
    SecureWriteTransactionManager& prepareTransferWorkKeyDiversified(
        uint8_t kif,
        uint8_t kvc,
        const std::vector<uint8_t>& workKeyParameters,
        int targetRecordNumber,
        const std::vector<uint8_t>& diversifier) override;

    /**
     * {@inheritDoc}
     *
     * @since 0.9.0
     */
    SecureWriteTransactionManager&
    prepareTransferLock(uint8_t lockIndex, uint8_t lockParameters) override;

    /**
     * {@inheritDoc}
     *
     * @since 0.9.0
     */
    SecureWriteTransactionManager& prepareTransferLockDiversified(
        uint8_t lockIndex, uint8_t lockParameters) override;

    /**
     * {@inheritDoc}
     *
     * @since 0.9.0
     */
    SecureWriteTransactionManager& preparePlainWriteLock(
        uint8_t lockIndex,
        uint8_t lockParameters,
        const std::vector<uint8_t>& lockValue) override;

    /**
     * {@inheritDoc}
     *
     * @since 0.9.0
     */
    SecureWriteTransactionManager&
    prepareWriteCounterCeiling(int counterNumber, int ceilingValue) override;

    /**
     * {@inheritDoc}
     *
     * @since 0.9.0
     */
    SecureWriteTransactionManager& prepareWriteCounterConfiguration(
        int counterNumber,
        int ceilingValue,
        CounterIncrementAccess counterIncrementAccess) override;

    /**
     * {@inheritDoc}
     *
     * @since 0.9.0
     */
    SecureWriteTransactionManager& processCommands() override;

private:
    SecureWriteTransactionManager& prepareTransferSystemKeyInternal(
        SystemKeyType systemKeyType,
        uint8_t kvc,
        const std::vector<uint8_t>& systemKeyParameters,
        bool isDiversified);

    SecureWriteTransactionManager& prepareTransferWorkKeyInternal(
        uint8_t kif,
        uint8_t kvc,
        const std::vector<uint8_t>& workKeyParameters,
        int targetRecordNumber,
        bool diversified,
        const std::vector<uint8_t>& diversifier);

    SecureWriteTransactionManager& prepareTransferLockInternal(
        uint8_t lockIndex, uint8_t lockParameters, bool isDiversified);
};

} /* namespace legacysam */
} /* namespace crypto */
} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
