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

#include "keyple/card/calypso/crypto/legacysam/LegacySamAdapter.hpp"
#include "keypop/calypso/crypto/legacysam/sam/LegacySam.hpp"
#include "keypop/calypso/crypto/legacysam/transaction/SecuritySetting.hpp"
#include "keypop/card/ProxyReaderApi.hpp"
#include "keypop/reader/CardReader.hpp"

namespace keyple {
namespace card {
namespace calypso {
namespace crypto {
namespace legacysam {

using keypop::calypso::crypto::legacysam::sam::LegacySam;
using keypop::calypso::crypto::legacysam::transaction::SecuritySetting;
using keypop::card::ProxyReaderApi;
using keypop::reader::CardReader;

/**
 * Implementation of SecuritySetting.
 *
 * @since 0.3.0
 */
class SecuritySettingAdapter final
: public SecuritySetting,
  public std::enable_shared_from_this<SecuritySettingAdapter> {
public:
    /**
     * {@inheritDoc}
     *
     * @since 0.3.0
     */
    SecuritySetting& setControlSamResource(
        std::shared_ptr<CardReader> samReader,
        std::shared_ptr<LegacySam> controlSam) override;

    /**
     * Gets the associated control SAM reader to use for secured operations.
     *
     * @return Null if no control SAM reader is set.
     * @since 0.3.0
     */
    std::shared_ptr<ProxyReaderApi> getControlSamReader() const;

    /**
     * Gets the control SAM used for secured operations.
     *
     * @return Null if no control SAM is set.
     * @since 0.3.0
     */
    std::shared_ptr<LegacySamAdapter> getControlSam() const;

private:
    /**
     *
     */
    std::shared_ptr<ProxyReaderApi> mControlSamReader;

    /**
     *
     */
    std::shared_ptr<LegacySamAdapter> mControlSam;
};

} /* namespace legacysam */
} /* namespace crypto */
} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
