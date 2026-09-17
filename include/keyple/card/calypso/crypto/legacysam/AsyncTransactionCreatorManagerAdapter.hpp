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

#include "keyple/card/calypso/crypto/legacysam/CommonTransactionManagerAdapter.hpp"
#include "keyple/card/calypso/crypto/legacysam/DtoAdapters.hpp"
#include "keyple/card/calypso/crypto/legacysam/KeypleCardCalypsoCryptoLegacySamExport.hpp"
#include "keypop/calypso/crypto/legacysam/transaction/AsyncTransactionCreatorManager.hpp"
#include "keypop/calypso/crypto/legacysam/transaction/SecuritySetting.hpp"
#include "keypop/reader/ChannelControl.hpp"

namespace keyple {
namespace card {
namespace calypso {
namespace crypto {
namespace legacysam {

using keypop::calypso::crypto::legacysam::transaction::
    AsyncTransactionCreatorManager;
using keypop::calypso::crypto::legacysam::transaction::SecuritySetting;
using keypop::reader::ChannelControl;

using TargetSamContextDto = DtoAdapters::TargetSamContextDto;

/**
 * Adapter of AsyncTransactionCreatorManager.
 *
 * @since 0.3.0
 */
class KEYPLECARDCALYPSOCRYPTOLEGACYSAM_API
    AsyncTransactionCreatorManagerAdapter final
: public CommonTransactionManagerAdapter,
  public AsyncTransactionCreatorManager {
public:
    /**
     * Constructs a new instance with the specified target SAM context and
     * security settings.
     *
     * @param targetSamContextJson The target SAM context as a JSON String.
     * @param securitySetting An instance of {@link SecuritySetting}.
     * @since 0.3.0
     */
    AsyncTransactionCreatorManagerAdapter(
        const std::string& targetSamContextJson,
        const std::shared_ptr<SecuritySetting> securitySetting);

    /**
     * {@inheritDoc}
     *
     * @since 0.3.0
     */
    AsyncTransactionCreatorManager& prepareWriteCounterCeiling(
        const int counterNumber, const int ceilingValue) override;

    /**
     * {@inheritDoc}
     *
     * @since 0.3.0
     */
    AsyncTransactionCreatorManager& prepareWriteCounterConfiguration(
        const int counterNumber,
        const int ceilingValue,
        const CounterIncrementAccess counterIncrementAccess) override;

    /**
     * {@inheritDoc}
     *
     * @since 0.3.0
     */
    std::string exportCommands() const override;

    /**
     * {@inheritDoc}
     *
     * <p>This method is part of the implemented interface, but it cannot be
     * executed by this type of transaction manager, which is not designed to
     * handle target SAM commands. As a result, when called, this method always
     * throws an exception.
     *
     * @throw UnsupportedOperationException Always.
     * @since 0.3.0
     * @deprecated Use processCommands(ChannelControl) instead.
     */
    AsyncTransactionCreatorManager& processCommands() override;

    /**
     * {@inheritDoc}
     *
     * <p>This method is part of the implemented interface, but it cannot be
     * executed by this type of transaction manager, which is not designed to
     * handle target SAM commands. As a result, when called, this method always
     * throws an exception.
     *
     * @throw UnsupportedOperationException Always.
     * @since 1.0.0
     */
    AsyncTransactionCreatorManager&
    processCommands(ChannelControl channelControl) override;

private:
    /**
     *
     */
    std::shared_ptr<TargetSamContextDto> mTargetSamContext;
};

} /* namespace legacysam */
} /* namespace crypto */
} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
