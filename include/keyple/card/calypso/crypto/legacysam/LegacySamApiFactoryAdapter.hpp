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

#include <memory>
#include <string>

#include "keyple/card/calypso/crypto/legacysam/ContextSettingAdapter.hpp"
#include "keypop/calypso/card/transaction/spi/SymmetricCryptoCardTransactionManagerFactory.hpp"
#include "keypop/calypso/crypto/legacysam/LegacySamApiFactory.hpp"
#include "keypop/calypso/crypto/legacysam/sam/LegacySam.hpp"
#include "keypop/calypso/crypto/legacysam/sam/LegacySamSelectionExtension.hpp"
#include "keypop/calypso/crypto/legacysam/transaction/AsyncTransactionCreatorManager.hpp"
#include "keypop/calypso/crypto/legacysam/transaction/AsyncTransactionExecutorManager.hpp"
#include "keypop/calypso/crypto/legacysam/transaction/BasicSignatureComputationData.hpp"
#include "keypop/calypso/crypto/legacysam/transaction/BasicSignatureVerificationData.hpp"
#include "keypop/calypso/crypto/legacysam/transaction/FreeTransactionManager.hpp"
#include "keypop/calypso/crypto/legacysam/transaction/KeyPairContainer.hpp"
#include "keypop/calypso/crypto/legacysam/transaction/LegacyCardCertificateComputationData.hpp"
#include "keypop/calypso/crypto/legacysam/transaction/SecureWriteTransactionManager.hpp"
#include "keypop/calypso/crypto/legacysam/transaction/SecuritySetting.hpp"
#include "keypop/calypso/crypto/legacysam/transaction/TraceableSignatureComputationData.hpp"
#include "keypop/calypso/crypto/legacysam/transaction/TraceableSignatureVerificationData.hpp"
#include "keypop/reader/CardReader.hpp"

namespace keyple {
namespace card {
namespace calypso {
namespace crypto {
namespace legacysam {

using keypop::calypso::card::transaction::spi::
    SymmetricCryptoCardTransactionManagerFactory;
using keypop::calypso::crypto::legacysam::LegacySamApiFactory;
using keypop::calypso::crypto::legacysam::sam::LegacySam;
using keypop::calypso::crypto::legacysam::sam::LegacySamSelectionExtension;
using keypop::calypso::crypto::legacysam::transaction::
    AsyncTransactionCreatorManager;
using keypop::calypso::crypto::legacysam::transaction::
    AsyncTransactionExecutorManager;
using keypop::calypso::crypto::legacysam::transaction::
    BasicSignatureComputationData;
using keypop::calypso::crypto::legacysam::transaction::
    BasicSignatureVerificationData;
using keypop::calypso::crypto::legacysam::transaction::FreeTransactionManager;
using keypop::calypso::crypto::legacysam::transaction::KeyPairContainer;
using keypop::calypso::crypto::legacysam::transaction::
    LegacyCardCertificateComputationData;
using keypop::calypso::crypto::legacysam::transaction::
    SecureWriteTransactionManager;
using keypop::calypso::crypto::legacysam::transaction::SecuritySetting;
using keypop::calypso::crypto::legacysam::transaction::
    TraceableSignatureComputationData;
using keypop::calypso::crypto::legacysam::transaction::
    TraceableSignatureVerificationData;
using keypop::reader::CardReader;

/**
 * Adapter of LegacySamApiFactory.
 *
 * @since 0.4.0
 */
class LegacySamApiFactoryAdapter final : public LegacySamApiFactory {
public:
    /**
     * {@inheritDoc}
     *
     * @since 0.4.0
     */
    std::shared_ptr<LegacySamSelectionExtension>
    createLegacySamSelectionExtension() override;

    /**
     * {@inheritDoc}
     *
     * @since 0.4.0
     */
    std::shared_ptr<SymmetricCryptoCardTransactionManagerFactory>
    createSymmetricCryptoCardTransactionManagerFactory(
        std::shared_ptr<CardReader> samReader,
        std::shared_ptr<LegacySam> sam) override;

    /**
     * {@inheritDoc}
     *
     * @since 0.4.0
     */
    std::shared_ptr<SecuritySetting> createSecuritySetting() override;

    /**
     * {@inheritDoc}
     *
     * @since 0.4.0
     */
    std::shared_ptr<FreeTransactionManager> createFreeTransactionManager(
        std::shared_ptr<CardReader> samReader,
        std::shared_ptr<LegacySam> sam) override;

    /**
     * {@inheritDoc}
     *
     * @since 0.9.0
     */
    std::shared_ptr<SecureWriteTransactionManager>
    createSecureWriteTransactionManager(
        std::shared_ptr<CardReader> samReader,
        std::shared_ptr<LegacySam> sam,
        std::shared_ptr<SecuritySetting> securitySetting) override;

    /**
     * {@inheritDoc}
     *
     * @since 0.4.0
     */
    std::shared_ptr<AsyncTransactionCreatorManager>
    createAsyncTransactionCreatorManager(
        const std::string& targetSamContext,
        std::shared_ptr<SecuritySetting> securitySetting) override;

    /**
     * {@inheritDoc}
     *
     * @since 0.4.0
     */
    std::shared_ptr<AsyncTransactionExecutorManager>
    createAsyncTransactionExecutorManager(
        std::shared_ptr<CardReader> samReader,
        std::shared_ptr<LegacySam> sam,
        const std::string& samCommands) override;

    /**
     * {@inheritDoc}
     *
     * @since 0.6.0
     */
    std::shared_ptr<KeyPairContainer> createKeyPairContainer() override;

    /**
     * {@inheritDoc}
     *
     * @since 0.6.0
     */
    std::shared_ptr<LegacyCardCertificateComputationData>
    createLegacyCardCertificateComputationData() override;

    /**
     * {@inheritDoc}
     *
     * @since 0.4.0
     */
    std::shared_ptr<BasicSignatureComputationData>
    createBasicSignatureComputationData() override;

    /**
     * {@inheritDoc}
     *
     * @since 0.4.0
     */
    std::shared_ptr<TraceableSignatureComputationData>
    createTraceableSignatureComputationData() override;

    /**
     * {@inheritDoc}
     *
     * @since 0.4.0
     */
    std::shared_ptr<BasicSignatureVerificationData>
    createBasicSignatureVerificationData() override;

    /**
     * {@inheritDoc}
     *
     * @since 0.4.0
     */
    std::shared_ptr<TraceableSignatureVerificationData>
    createTraceableSignatureVerificationData() override;

    /**
     * @brief Constructs a LegacySamApiFactoryAdapter.
     * @param contextSetting The context setting.
     * @since 0.4.0
     */
    explicit LegacySamApiFactoryAdapter(
        std::shared_ptr<ContextSettingAdapter> contextSetting);

private:
    /**
     *
     */
    static const std::string
        MSG_THE_PROVIDED_SAM_READER_MUST_IMPLEMENT_PROXY_READER_API;
    static const std::string
        MSG_THE_PROVIDED_SAM_MUST_BE_AN_INSTANCE_OF_LEGACY_SAM_ADAPTER;

    /**
     *
     */
    std::shared_ptr<ContextSettingAdapter> mContextSetting;
};

} /* namespace legacysam */
} /* namespace crypto */
} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
