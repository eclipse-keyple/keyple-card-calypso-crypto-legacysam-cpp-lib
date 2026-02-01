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
#include "keyple/card/calypso/crypto/legacysam/LegacySamAdapter.hpp"
#include "keypop/calypso/crypto/legacysam/transaction/AsyncTransactionExecutorManager.hpp"
#include "keypop/card/ProxyReaderApi.hpp"

namespace keyple {
namespace card {
namespace calypso {
namespace crypto {
namespace legacysam {

using keypop::calypso::crypto::legacysam::transaction::
    AsyncTransactionExecutorManager;
using keypop::card::ProxyReaderApi;

/**
 * Adapter of AsyncTransactionExecutorManager.
 *
 * @since 0.3.0
 */
class AsyncTransactionExecutorManagerAdapter final
: public CommonTransactionManagerAdapter,
  public AsyncTransactionExecutorManager {
public:
    /**
     * Constructs a new instance with the specified target SAM reader, target
     * SAM and commands to be executed.
     *
     * @param targetSamReader The reader through which the target SAM
     * communicates.
     * @param targetSam The target legacy SAM.
     * @param samCommandsJson The commands to be executed as a JSON String.
     * @since 0.3.0
     */
    AsyncTransactionExecutorManagerAdapter(
        std::shared_ptr<ProxyReaderApi> targetSamReader,
        std::shared_ptr<LegacySamAdapter> targetSam,
        const std::string& samCommandsJson);

    /**
     * {@inheritDoc}
     *
     * @since 0.3.0
     */
    AsyncTransactionExecutorManager& processCommands() override;
};

} /* namespace legacysam */
} /* namespace crypto */
} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
