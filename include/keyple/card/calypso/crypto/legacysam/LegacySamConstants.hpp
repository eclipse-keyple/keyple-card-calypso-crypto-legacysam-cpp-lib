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
#include <map>
#include <string>
#include <vector>

#include "keypop/calypso/crypto/legacysam/SystemKeyType.hpp"

namespace keyple {
namespace card {
namespace calypso {
namespace crypto {
namespace legacysam {

using keypop::calypso::crypto::legacysam::SystemKeyType;

/**
 * Constants for the Legacy SAM API.
 *
 * @since 2.0.0
 */
class LegacySamConstants {
public:
    static const int MIN_KEY_RECORD_NUMBER;
    static const int MAX_KEY_RECORD_NUMBER;
    static const int MIN_COUNTER_NUMBER;
    static const int MAX_COUNTER_NUMBER;
    static const int MIN_COUNTER_CEILING_NUMBER;
    static const int MAX_COUNTER_CEILING_NUMBER;
    static const int MIN_COUNTER_CEILING_VALUE;
    static const int MAX_COUNTER_CEILING_VALUE;
    static const std::vector<int> COUNTER_TO_RECORD_LOOKUP;
    static const std::uint8_t AID_SIZE_MAX;
    static const int CA_CERTIFICATE_SIZE;
    static const int ECC_PUBLIC_KEY_SIZE;
    static const int PLAIN_CEILING_DATA_BLOCK_SIZE;
    static const int KEY_DATA_BLOCK_SIZE;
    static const int LOCK_FILE_SIZE;
    static const int SAM_PARAMETERS_LENGTH;
    static const int KEY_PARAMETERS_LENGTH;
    static const int LOCK_VALUE_LENGTH;

    static const std::uint8_t TARGET_IS_SYSTEM_KEY_FILE;
    static const std::uint8_t TARGET_IS_LOCK_FILE;
    static const std::uint8_t RECORD_CHOSEN_BY_THE_SAM;

    static const std::uint8_t FIRST_EVENT_CEILING_RECORD_REFERENCE;
    static const std::uint8_t SINGLE_CEILING_REFERENCE;

    static const std::uint8_t LOCK_KIF;

    static const std::uint8_t DYNAMIC_MODE_CIPHERING;
    static const std::uint8_t STATIC_MODE_CIPHERING;

    static const std::map<SystemKeyType, uint8_t> SYSTEM_KEY_TYPE_KIF_MAP;

    /**
     * Enum representing the different tags used in Get Data APDU command and
     * providing precomputed
     * values.
     *
     * @since 0.6.0
     */
    class TagInfo {
    public:
        static const TagInfo CA_CERTIFICATE;
        static const TagInfo CARD_PUBLIC_KEY_DATA;
        static const TagInfo GENERATED_CARD_ECC_KEY_PAIR;
        static const TagInfo GENERATED_CARD_CERTIFICATE;

        /**
         *
         */
        const std::vector<uint8_t>& getHeader() const;

        /**
         *
         */
        int getTotalLength() const;

        /**
         *
         */
        uint8_t getLsb() const;

        /**
         *
         */
        uint8_t getMsb() const;

        /**
         *
         */
        int getLength() const;

        /**
         * C++
         */
        static TagInfo valueOf(const std::string& name);

    private:
        /**
         *
         */
        const int mValue;
        const int mLength;
        const int mTotalLength;
        const std::vector<uint8_t> mHeader;
        const std::uint8_t mLsb;
        const std::uint8_t mMsb;

        /**
         * Constructor
         */
        TagInfo(int value, int length, const std::vector<uint8_t>& header);

        /**
         *
         */
        int getValue() const;
    };

private:
    /**
     *
     */
    LegacySamConstants();
};

} /* namespace legacysam */
} /* namespace crypto */
} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
