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

#include "keyple/card/calypso/crypto/legacysam/LegacySamConstants.hpp"

#include <map>
#include <string>
#include <vector>

#include "keyple/core/util/HexUtil.hpp"
#include "keyple/core/util/cpp/exception/IllegalArgumentException.hpp"

namespace keyple {
namespace card {
namespace calypso {
namespace crypto {
namespace legacysam {

using keyple::core::util::HexUtil;
using keyple::core::util::cpp::exception::IllegalArgumentException;

using TagInfo = LegacySamConstants::TagInfo;

const int LegacySamConstants::MIN_KEY_RECORD_NUMBER = 1;
const int LegacySamConstants::MAX_KEY_RECORD_NUMBER = 126;
const int LegacySamConstants::MIN_COUNTER_NUMBER = 0;
const int LegacySamConstants::MAX_COUNTER_NUMBER = 26;
const int LegacySamConstants::MIN_COUNTER_CEILING_NUMBER = 0;
const int LegacySamConstants::MAX_COUNTER_CEILING_NUMBER = 26;
const int LegacySamConstants::MIN_COUNTER_CEILING_VALUE = 0;
const int LegacySamConstants::MAX_COUNTER_CEILING_VALUE = 0xFFFFFA;
const std::vector<int> LegacySamConstants::COUNTER_TO_RECORD_LOOKUP
    = {0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1,
       1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2};
const uint8_t LegacySamConstants::AID_SIZE_MAX = 16;
const int LegacySamConstants::CA_CERTIFICATE_SIZE = 384;
const int LegacySamConstants::ECC_PUBLIC_KEY_SIZE = 64;
const int LegacySamConstants::PLAIN_CEILING_DATA_BLOCK_SIZE = 30;
const int LegacySamConstants::KEY_DATA_BLOCK_SIZE = 48;
const int LegacySamConstants::LOCK_FILE_SIZE = 29;
const int LegacySamConstants::SAM_PARAMETERS_LENGTH = 29;
const int LegacySamConstants::KEY_PARAMETERS_LENGTH = 10;
const int LegacySamConstants::LOCK_VALUE_LENGTH = 16;

const uint8_t LegacySamConstants::TARGET_IS_SYSTEM_KEY_FILE = 0xC0;
const uint8_t LegacySamConstants::TARGET_IS_LOCK_FILE = 0xE0;
const uint8_t LegacySamConstants::RECORD_CHOSEN_BY_THE_SAM = 0xF0;

const uint8_t LegacySamConstants::FIRST_EVENT_CEILING_RECORD_REFERENCE = 0xB1;
const uint8_t LegacySamConstants::SINGLE_CEILING_REFERENCE = 0xB8;

const uint8_t LegacySamConstants::LOCK_KIF = 0xEF;

const uint8_t LegacySamConstants::DYNAMIC_MODE_CIPHERING = 0x00;
const uint8_t LegacySamConstants::STATIC_MODE_CIPHERING = 0x08;

const std::map<SystemKeyType, uint8_t>
    LegacySamConstants::SYSTEM_KEY_TYPE_KIF_MAP;

const TagInfo LegacySamConstants::TagInfo::CA_CERTIFICATE(
    0xDF43, CA_CERTIFICATE_SIZE, HexUtil::toByteArray("DF43820180"));
const TagInfo LegacySamConstants::TagInfo::CARD_PUBLIC_KEY_DATA(
    0xDF25, 60, HexUtil::toByteArray("DF253F"));
const TagInfo LegacySamConstants::TagInfo::GENERATED_CARD_ECC_KEY_PAIR(
    0xDF3C, 96, HexUtil::toByteArray("DF3C60"));
const TagInfo LegacySamConstants::TagInfo::GENERATED_CARD_CERTIFICATE(
    0xDF45, 316, HexUtil::toByteArray("DF4582013C"));

LegacySamConstants::TagInfo::TagInfo(
    int value, int length, const std::vector<uint8_t>& header)
: mValue(value)
, mLength(length)
, mTotalLength(length + header.size())
, mHeader(header)
, mLsb((uint8_t)(value & 0xFF))
, mMsb((uint8_t)((value & 0xFF00) >> 8))
{
}

int
LegacySamConstants::TagInfo::getValue() const
{
    return mValue;
}

int
LegacySamConstants::TagInfo::getLength() const
{
    return mLength;
}

int
LegacySamConstants::TagInfo::getTotalLength() const
{
    return mTotalLength;
}

const std::vector<uint8_t>&
LegacySamConstants::TagInfo::getHeader() const
{
    return mHeader;
}

uint8_t
LegacySamConstants::TagInfo::getLsb() const
{
    return mLsb;
}

uint8_t
LegacySamConstants::TagInfo::getMsb() const
{
    return mMsb;
}

TagInfo
LegacySamConstants::TagInfo::valueOf(const std::string& name)
{
    if (name == "CA_CERTIFICATE") {
        return CA_CERTIFICATE;
    } else if (name == "CARD_PUBLIC_KEY_DATA") {
        return CARD_PUBLIC_KEY_DATA;
    } else if (name == "GENERATED_CARD_ECC_KEY_PAIR") {
        return GENERATED_CARD_ECC_KEY_PAIR;
    } else {
        throw IllegalArgumentException("Unknown tag name");
    }
}

} /* namespace legacysam */
} /* namespace crypto */
} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
