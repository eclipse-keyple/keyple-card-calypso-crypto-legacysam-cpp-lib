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

#include "keyple/card/calypso/crypto/legacysam/CommandRef.hpp"

#include <string>
namespace keyple {
namespace card {
namespace calypso {
namespace crypto {
namespace legacysam {

const CommandRef CommandRef::SELECT_DIVERSIFIER("Select Diversifier", 0x14);
const CommandRef CommandRef::GET_CHALLENGE("Get Challenge", 0x84);
const CommandRef CommandRef::DIGEST_INIT("Digest Init", 0x8A);
const CommandRef CommandRef::DIGEST_UPDATE("Digest Update", 0x8C);
const CommandRef
    CommandRef::DIGEST_UPDATE_MULTIPLE("Digest Update Multiple", 0x8C);
const CommandRef CommandRef::DIGEST_CLOSE("Digest Close", 0x8E);
const CommandRef CommandRef::DIGEST_AUTHENTICATE("Digest Authenticate", 0x82);
const CommandRef CommandRef::DIGEST_INTERNAL_AUTHENTICATE(
    "Digest Internal Authenticate", 0x88);
const CommandRef CommandRef::GIVE_RANDOM("Give Random", 0x86);
const CommandRef CommandRef::CARD_GENERATE_KEY("Card Generate Key", 0x12);
const CommandRef CommandRef::CARD_CIPHER_PIN("Card Cipher PIN", 0x12);
const CommandRef CommandRef::UNLOCK("Unlock", 0x20);
const CommandRef CommandRef::WRITE_KEY("Write Key", 0x1A);
const CommandRef CommandRef::READ_KEY_PARAMETERS("Read Key Parameters", 0xBC);
const CommandRef CommandRef::READ_EVENT_COUNTER("Read Event Counter", 0xBE);
const CommandRef CommandRef::READ_CEILINGS("Read Ceilings", 0xBE);
const CommandRef CommandRef::READ_PARAMETERS("Read Parameters", 0xBE);
const CommandRef CommandRef::SV_CHECK("SV Check", 0x58);
const CommandRef CommandRef::SV_PREPARE_DEBIT("SV Prepare Debit", 0x54);
const CommandRef CommandRef::SV_PREPARE_LOAD("SV Prepare Load", 0x56);
const CommandRef CommandRef::SV_PREPARE_UNDEBIT("SV Prepare Undebit", 0x5C);
const CommandRef CommandRef::DATA_CIPHER("Data Cipher", 0x1C);
const CommandRef
    CommandRef::PSO_COMPUTE_SIGNATURE("PSO Compute Signature", 0x2A);
const CommandRef CommandRef::PSO_VERIFY_SIGNATURE("PSO Verify Signature", 0x2A);
const CommandRef CommandRef::SAM_DATA_CIPHER("SAM Data Cipher", 0x16);
const CommandRef CommandRef::SAM_GENERATE_KEY("SAM Generate Key", 0x16);
const CommandRef CommandRef::WRITE_CEILINGS("Write Ceilings", 0xD8);
const CommandRef CommandRef::WRITE_PARAMETERS("Write Parameters", 0xD8);
const CommandRef CommandRef::GET_DATA("Get Data", 0xCA);
const CommandRef
    CommandRef::PSO_COMPUTE_CERTIFICATE("PSO Compute Certificate", 0x2A);
const CommandRef CommandRef::CARD_GENERATE_ASYMMETRIC_KEY_PAIR(
    "Card Generate Asymmetric Key Pair", 0x46);

CommandRef::CommandRef(const std::string& name, std::uint8_t instructionByte)
: mName(name)
, mInstructionByte(instructionByte)
{
}

const std::string&
CommandRef::getName() const
{
    return mName;
}

std::uint8_t
CommandRef::getInstructionByte() const
{
    return mInstructionByte;
}

bool
CommandRef::operator==(const CommandRef& other) const
{
    return mName == other.mName && mInstructionByte == other.mInstructionByte;
}

bool
CommandRef::operator!=(const CommandRef& other) const
{
    return !(*this == other);
}

} /* namespace legacysam */
} /* namespace crypto */
} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
