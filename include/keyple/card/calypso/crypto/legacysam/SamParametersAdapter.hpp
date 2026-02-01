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
#include <vector>

#include "keypop/calypso/crypto/legacysam/sam/SamParameters.hpp"

namespace keyple {
namespace card {
namespace calypso {
namespace crypto {
namespace legacysam {

using keypop::calypso::crypto::legacysam::sam::SamParameters;

/**
 * Implementation of SamParameters.
 *
 * @since 0.9.0
 */
class SamParametersAdapter final : public SamParameters {
public:
    /**
     * @brief Constructs a SamParametersAdapter from a byte array.
     * @param samParameters The byte array containing the sam parameters.
     * @since 0.9.0
     */
    explicit SamParametersAdapter(std::vector<uint8_t> samParameters);

    /**
     * {@inheritDoc}
     *
     * @since 0.9.0
     */
    const std::vector<uint8_t> getRawData() const override;

private:
    /**
     *
     */
    std::vector<uint8_t> mSamParameters;
};

} /* namespace legacysam */
} /* namespace crypto */
} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
