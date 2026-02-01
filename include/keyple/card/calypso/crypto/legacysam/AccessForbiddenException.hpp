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
 * Indicates that preconditions are not satisfied (e.g. session not active...).
 *
 * @since 0.1.0
 */
class KEYPLECARDCALYPSOCRYPTOLEGACYSAM_API AccessForbiddenException
: public CommandException {
public:
    /**
     * @param message the message to identify the exception context.
     * @since 0.1.0
     */
    explicit AccessForbiddenException(const std::string& message)
    : CommandException(message)
    {
    }
};

} /* namespace legacysam */
} /* namespace crypto */
} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
