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
#include <vector>

#include "keyple/card/calypso/crypto/legacysam/Command.hpp"
#include "keyple/card/calypso/crypto/legacysam/ContextSettingAdapter.hpp"
#include "keyple/card/calypso/crypto/legacysam/LegacySamAdapter.hpp"
#include "keypop/calypso/card/transaction/spi/SymmetricCryptoCardTransactionManagerFactory.hpp"
#include "keypop/calypso/crypto/symmetric/spi/SymmetricCryptoCardTransactionManagerFactorySpi.hpp"
#include "keypop/calypso/crypto/symmetric/spi/SymmetricCryptoCardTransactionManagerSpi.hpp"
#include "keypop/card/ProxyReaderApi.hpp"

namespace keyple {
namespace card {
namespace calypso {
namespace crypto {
namespace legacysam {

using keypop::calypso::card::transaction::spi::
    SymmetricCryptoCardTransactionManagerFactory;
using keypop::calypso::crypto::symmetric::spi::
    SymmetricCryptoCardTransactionManagerFactorySpi;
using keypop::calypso::crypto::symmetric::spi::
    SymmetricCryptoCardTransactionManagerSpi;
using keypop::card::ProxyReaderApi;

/**
 * Adapter of SymmetricCryptoCardTransactionManagerFactory.
 *
 * @since 0.4.0
 */
class SymmetricCryptoCardTransactionManagerFactoryAdapter final
: public SymmetricCryptoCardTransactionManagerFactory,
  public SymmetricCryptoCardTransactionManagerFactorySpi {
public:
    /**
     * @brief Constructs a SymmetricCryptoCardTransactionManagerFactoryAdapter.
     * @param samReader The SAM reader.
     * @param sam The SAM.
     * @param contextSetting The context setting.
     * @since 0.4.0
     */
    SymmetricCryptoCardTransactionManagerFactoryAdapter(
        std::shared_ptr<ProxyReaderApi> samReader,
        std::shared_ptr<LegacySamAdapter> sam,
        std::shared_ptr<ContextSettingAdapter> contextSetting);

    /**
     * {@inheritDoc}
     *
     * @since 2.3.1
     */
    bool isExtendedModeSupported() const override;

    /**
     * {@inheritDoc}
     *
     * @since 2.3.1
     */
    int getMaxCardApduLengthSupported() const override;

    /**
     * {@inheritDoc}
     *
     * @since 0.4.0
     */
    void preInitTerminalSessionContext() override;

    /**
     * {@inheritDoc}
     *
     * @since 2.3.1
     */
    std::shared_ptr<SymmetricCryptoCardTransactionManagerSpi>
    createCardTransactionManager(
        const std::vector<uint8_t>& cardKeyDiversifier,
        bool useExtendedMode,
        const std::vector<std::vector<uint8_t>>& transactionAuditData) override;

private:
    /**
     *
     */
    void processCommand(std::shared_ptr<Command> command);

    /**
     *
     */
    std::shared_ptr<ProxyReaderApi> mSamReader;

    /**
     *
     */
    std::shared_ptr<LegacySamAdapter> mSam;

    /**
     *
     */
    bool mIsExtendedModeSupported;

    /**
     *
     */
    int mMaxCardApduLengthSupported;
};

} /* namespace legacysam */
} /* namespace crypto */
} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
