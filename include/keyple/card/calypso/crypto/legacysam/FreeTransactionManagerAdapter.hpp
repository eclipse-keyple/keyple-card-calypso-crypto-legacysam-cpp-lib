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
#include <memory>
#include <string>
#include <vector>

#include "keyple/card/calypso/crypto/legacysam/CommonTransactionManagerAdapter.hpp"
#include "keyple/card/calypso/crypto/legacysam/DtoAdapters.hpp"
#include "keypop/calypso/crypto/legacysam/GetDataTag.hpp"
#include "keypop/calypso/crypto/legacysam/transaction/FreeTransactionManager.hpp"
#include "keypop/calypso/crypto/legacysam/transaction/SignatureComputationDataBase.hpp"
#include "keypop/calypso/crypto/legacysam/transaction/SignatureVerificationDataBase.hpp"

namespace keyple {
namespace card {
namespace calypso {
namespace crypto {
namespace legacysam {

using keypop::calypso::crypto::legacysam::GetDataTag;
using keypop::calypso::crypto::legacysam::transaction::FreeTransactionManager;
using keypop::calypso::crypto::legacysam::transaction::
    SignatureComputationDataBase;
using keypop::calypso::crypto::legacysam::transaction::
    SignatureVerificationDataBase;

/**
 * Adapter of FreeTransactionManager.
 *
 * @since 0.1.0
 */
class FreeTransactionManagerAdapter final
: public CommonTransactionManagerAdapter,
  public FreeTransactionManager {
public:
    /**
     * Constructs a new instance with the specified target SAM context and
     * security settings.
     *
     * @param targetSamReader The reader through which the target SAM
     * communicates.
     * @param targetSam The target legacy SAM.
     * @since 0.3.0
     */
    FreeTransactionManagerAdapter(
        std::shared_ptr<ProxyReaderApi> targetSamReader,
        std::shared_ptr<LegacySamAdapter> targetSam);

    /**
     * {@inheritDoc}
     *
     * @since 0.6.0
     */
    FreeTransactionManager& prepareGetData(GetDataTag tag) override;

    /**
     * {@inheritDoc}
     *
     * @since 0.6.0
     */
    FreeTransactionManager& prepareGenerateCardAsymmetricKeyPair(
        std::shared_ptr<KeyPairContainer> keyPairContainer) override;

    /**
     * {@inheritDoc}
     *
     * @since 0.6.0
     */
    FreeTransactionManager& prepareComputeCardCertificate(
        std::shared_ptr<LegacyCardCertificateComputationData> data) override;

    /**
     * {@inheritDoc}
     *
     * @since 0.9.0
     */
    FreeTransactionManager& preparePlainWriteLock(
        uint8_t lockIndex,
        uint8_t lockParameters,
        const std::vector<uint8_t>& lockValue) override;

    /**
     * {@inheritDoc}
     *
     * @since 0.1.0
     */
    FreeTransactionManager& prepareComputeSignature(
        std::shared_ptr<SignatureComputationDataBase> data) override;

    /**
     * {@inheritDoc}
     *
     * @since 0.1.0
     */
    FreeTransactionManager& prepareVerifySignature(
        std::shared_ptr<SignatureVerificationDataBase> data) override;

    /**
     * {@inheritDoc}
     *
     * @since 0.9.0
     */
    FreeTransactionManager& prepareReadSamParameters() override;

    /**
     * {@inheritDoc}
     *
     * @since 0.3.0
     */
    FreeTransactionManager&
    prepareReadSystemKeyParameters(SystemKeyType systemKeyType) override;

    /**
     * {@inheritDoc}
     *
     * @since 0.9.0
     */
    FreeTransactionManager&
    prepareReadWorkKeyParameters(int recordNumber) override;

    /**
     * {@inheritDoc}
     *
     * @since 0.9.0
     */
    FreeTransactionManager&
    prepareReadWorkKeyParameters(uint8_t kif, uint8_t kvc) override;

    /**
     * {@inheritDoc}
     *
     * @since 0.1.0
     */
    FreeTransactionManager&
    prepareReadCounterStatus(int counterNumber) override;

    /**
     * {@inheritDoc}
     *
     * @since 0.1.0
     */
    FreeTransactionManager& prepareReadAllCountersStatus() override;

    /**
     * {@inheritDoc}
     *
     * @since 0.3.0
     */
    std::string exportTargetSamContextForAsyncTransaction() override;

    /**
     * {@inheritDoc}
     *
     * @since 0.1.0
     */
    FreeTransactionManager& processCommands() override;

private:
    /**
     *
     */
    static const std::string MSG_INPUT_OUTPUT_DATA;
    static const std::string MSG_SIGNATURE_SIZE;
    static const std::string MSG_KEY_DIVERSIFIER_SIZE_IS_IN_RANGE_1_8;

    /**
     * Prepares a "SelectDiversifier" command using a specific or the default
     * key diversifier if it is not already selected.
     *
     * @param specificKeyDiversifier The specific key diversifier (optional).
     * @since 0.1.0
     */
    void prepareSelectDiversifierIfNeeded(
        const std::vector<uint8_t>& specificKeyDiversifier);

    /**
     * Prepares a "SelectDiversifier" command using the default key diversifier
     * if it is not already selected.
     *
     * @since 0.1.0
     */
    void prepareSelectDiversifierIfNeeded();

    /**
     * Prepares a "SelectDiversifier" command using the current key diversifier.
     */
    void prepareSelectDiversifier();

    /**
     *
     */
    std::vector<std::uint8_t> mSamKeyDiversifier;

    /**
     *
     */
    std::vector<std::uint8_t> mCurrentKeyDiversifier;
};

} /* namespace legacysam */
} /* namespace crypto */
} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
