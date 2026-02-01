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

#include "keyple/card/calypso/crypto/legacysam/KeyParameterAdapter.hpp"

#include <utility>
#include <vector>

#include "keyple/core/util/KeypleAssert.hpp"

namespace keyple {
namespace card {
namespace calypso {
namespace crypto {
namespace legacysam {

using keyple::core::util::Assert;

KeyParameterAdapter::KeyParameterAdapter(std::vector<uint8_t> keyParameters)
: mKeyParameters(std::move(keyParameters))
{
}

const std::vector<uint8_t>&
KeyParameterAdapter::getRawData() const
{
    return mKeyParameters;
}

uint8_t
KeyParameterAdapter::getKif() const
{
    return mKeyParameters[0];
}

uint8_t
KeyParameterAdapter::getKvc() const
{
    return mKeyParameters[1];
}

uint8_t
KeyParameterAdapter::getAlgorithm() const
{
    return mKeyParameters[2];
}

uint8_t
KeyParameterAdapter::getParameterValue(const int parameterNumber) const
{
    Assert::getInstance().isInRange(parameterNumber, 1, 10, "parameterNumber");

    return mKeyParameters[2 + parameterNumber];
}

} /* namespace legacysam */
} /* namespace crypto */
} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
