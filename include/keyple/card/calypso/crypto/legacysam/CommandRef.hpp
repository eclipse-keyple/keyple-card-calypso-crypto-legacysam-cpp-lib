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
#include <string>

namespace keyple {
namespace card {
namespace calypso {
namespace crypto {
namespace legacysam {

/**
 * The reference of a command.
 *
 * @since 2.0.0
 */
class CommandRef {
public:
    static const CommandRef SELECT_DIVERSIFIER;
    static const CommandRef GET_CHALLENGE;
    static const CommandRef DIGEST_INIT;
    static const CommandRef DIGEST_UPDATE;
    static const CommandRef DIGEST_UPDATE_MULTIPLE;
    static const CommandRef DIGEST_CLOSE;
    static const CommandRef DIGEST_AUTHENTICATE;
    static const CommandRef DIGEST_INTERNAL_AUTHENTICATE;
    static const CommandRef GIVE_RANDOM;
    static const CommandRef CARD_GENERATE_KEY;
    static const CommandRef CARD_CIPHER_PIN;
    static const CommandRef UNLOCK;
    static const CommandRef WRITE_KEY;
    static const CommandRef READ_KEY_PARAMETERS;
    static const CommandRef READ_EVENT_COUNTER;
    static const CommandRef READ_CEILINGS;
    static const CommandRef READ_PARAMETERS;
    static const CommandRef SV_CHECK;
    static const CommandRef SV_PREPARE_DEBIT;
    static const CommandRef SV_PREPARE_LOAD;
    static const CommandRef SV_PREPARE_UNDEBIT;
    static const CommandRef DATA_CIPHER;
    static const CommandRef PSO_COMPUTE_SIGNATURE;
    static const CommandRef PSO_VERIFY_SIGNATURE;
    static const CommandRef SAM_DATA_CIPHER;
    static const CommandRef SAM_GENERATE_KEY;
    static const CommandRef WRITE_CEILINGS;
    static const CommandRef WRITE_PARAMETERS;
    static const CommandRef GET_DATA;
    static const CommandRef PSO_COMPUTE_CERTIFICATE;
    static const CommandRef CARD_GENERATE_ASYMMETRIC_KEY_PAIR;

    /**
     * Gets the name.
     *
     * @return A String
     * @since 0.1.0
     */
    const std::string& getName() const;

    /**
     * Gets the instruction byte (INS).
     *
     * @return A byte
     * @since 0.1.0
     */
    std::uint8_t getInstructionByte() const;

    /**
     *
     */
    bool operator==(const CommandRef& other) const;

    /**
     *
     */
    bool operator!=(const CommandRef& other) const;

private:
    /**
     *
     */
    const std::string mName;

    /**
     *
     */
    const std::uint8_t mInstructionByte;

    /**
     * The generic constructor of CalypsoCommands.
     *
     * @param name the name.
     * @param instructionByte the instruction byte.
     * @since 0.1.0
     */
    CommandRef(const std::string& name, std::uint8_t instructionByte);
};

} /* namespace legacysam */
} /* namespace crypto */
} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
