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

#include "keyple/card/calypso/crypto/legacysam/SamParametersAdapter.hpp"

#include <utility>
#include <vector>

namespace keyple {
namespace card {
namespace calypso {
namespace crypto {
namespace legacysam {

SamParametersAdapter::SamParametersAdapter(std::vector<uint8_t> samParameters)
: mSamParameters(std::move(samParameters))
{
}

const std::vector<uint8_t>
SamParametersAdapter::getRawData() const
{
    return mSamParameters;
}

} /* namespace legacysam */
} /* namespace crypto */
} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
