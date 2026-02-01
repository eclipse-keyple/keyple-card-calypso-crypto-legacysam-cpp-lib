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

#include "keypop/calypso/crypto/legacysam/sam/KeyParameter.hpp"

namespace keyple {
namespace card {
namespace calypso {
namespace crypto {
namespace legacysam {

using keypop::calypso::crypto::legacysam::sam::KeyParameter;

/**
 * Implementation of KeyParameter.
 *
 * @since 0.3.0
 */
class KeyParameterAdapter final : public KeyParameter {
public:
    /**
     * @brief Constructs a KeyParameterAdapter from a byte array.
     * @param keyParameters The byte array containing the key parameters.
     * @since 0.3.0
     */
    explicit KeyParameterAdapter(std::vector<uint8_t> keyParameters);

    /**
     * {@inheritDoc}
     *
     * @since 0.3.0
     */
    const std::vector<uint8_t>& getRawData() const override;

    /**
     * {@inheritDoc}
     *
     * @since 0.3.0
     */
    uint8_t getKif() const override;

    /**
     * {@inheritDoc}
     *
     * @since 0.3.0
     */
    uint8_t getKvc() const override;

    /**
     * {@inheritDoc}
     *
     * @since 0.3.0
     */
    uint8_t getAlgorithm() const override;

    /**
     * {@inheritDoc}
     *
     * @since 0.3.0
     */
    uint8_t getParameterValue(const int parameterNumber) const override;

private:
    /**
     *
     */
    std::vector<uint8_t> mKeyParameters;
};

} /* namespace legacysam */
} /* namespace crypto */
} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
