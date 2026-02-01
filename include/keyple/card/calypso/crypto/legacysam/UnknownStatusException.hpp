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

#include <string>

#include "keyple/card/calypso/crypto/legacysam/CommandException.hpp"

namespace keyple {
namespace card {
namespace calypso {
namespace crypto {
namespace legacysam {

/**
 * Indicates that the status word of the card response is unknown.
 *
 * @since 2.0.0
 */
class KEYPLECARDCALYPSOCRYPTOLEGACYSAM_API UnknownStatusException
: public CommandException {
public:
    /**
     * @param message the detail message.
     * @since 2.0.0
     */
    explicit UnknownStatusException(const std::string& message)
    : CommandException(message)
    {
    }
};

} /* namespace legacysam */
} /* namespace crypto */
} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
