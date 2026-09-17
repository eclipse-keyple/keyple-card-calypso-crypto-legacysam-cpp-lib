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
#include <memory>
#include <string>
#include <vector>

#include "keypop/card/ApduResponseApi.hpp"
#include "keypop/card/CardResponseApi.hpp"
#include "keypop/card/CardSelectionResponseApi.hpp"

namespace keyple {
namespace card {
namespace calypso {
namespace crypto {
namespace legacysam {

using keypop::card::ApduResponseApi;
using keypop::card::CardResponseApi;
using keypop::card::CardSelectionResponseApi;

/**
 * Test fakes for keypop::card DTOs.
 */
class TestDtoAdapters final {
public:
    /**
     * Adapter of ApduResponseApi.
     */
    class ApduResponseAdapter final : public ApduResponseApi {
    public:
        /**
         * Constructor
         */
        explicit ApduResponseAdapter(const std::vector<uint8_t>& apdu)
        : mApdu(apdu)
        , mStatusWord(
              ((apdu[apdu.size() - 2] & 0x000000FF) << 8)
              + (apdu[apdu.size() - 1] & 0x000000FF))
        {
        }

        /**
         * {@inheritDoc}
         */
        const std::vector<uint8_t>&
        getApdu() const override
        {
            return mApdu;
        }

        /**
         * {@inheritDoc}
         */
        void
        setApdu(const std::vector<uint8_t>& apdu) override
        {
            mApdu = apdu;
        }

        /**
         * {@inheritDoc}
         */
        std::vector<uint8_t>
        getDataOut() const override
        {
            return std::vector<uint8_t>(
                mApdu.begin(), mApdu.begin() + (mApdu.size() - 2));
        }

        /**
         * {@inheritDoc}
         */
        int
        getStatusWord() const override
        {
            return mStatusWord;
        }

    private:
        /**
         *
         */
        std::vector<uint8_t> mApdu;

        /**
         *
         */
        int mStatusWord;
    };

    /**
     * This POJO contains an ordered list of the responses received following a
     * card request and indicators related to the status of the channel and the
     * completion of the card request.
     *
     * @since 2.0.0
     */
    class CardResponseAdapter final : public CardResponseApi {
    public:
        /**
         * Builds a card response from all ApduResponseApi received from the
         * card and booleans indicating if the logical channel is still open.
         *
         * @since 2.0.0
         */
        CardResponseAdapter(
            const std::vector<std::shared_ptr<ApduResponseApi>>& apduResponses,
            const bool isLogicalChannelOpen)
        : mApduResponses(apduResponses)
        , mIsLogicalChannelOpen(isLogicalChannelOpen)
        {
        }

        /**
         * {@inheritDoc}
         *
         * @since 2.0.0
         */
        const std::vector<std::shared_ptr<ApduResponseApi>>&
        getApduResponses() const override
        {
            return mApduResponses;
        }

        /**
         * {@inheritDoc}
         *
         * @since 2.0.0
         */
        bool
        isLogicalChannelOpen() const override
        {
            return mIsLogicalChannelOpen;
        }

    private:
        /**
         *
         */
        std::vector<std::shared_ptr<ApduResponseApi>> mApduResponses;

        /**
         *
         */
        bool mIsLogicalChannelOpen;
    };

    /**
     *
     */
    class CardSelectionResponseAdapter final : public CardSelectionResponseApi {
    public:
        /**
         *
         */
        explicit CardSelectionResponseAdapter(const std::string& powerOnData)
        : mPowerOnData(powerOnData)
        {
        }

        /**
         *
         */
        explicit CardSelectionResponseAdapter(
            std::shared_ptr<ApduResponseApi> selectApplicationResponse)
        : mSelectApplicationResponse(selectApplicationResponse)
        {
        }

        /**
         * {@inheritDoc}
         */
        const std::string&
        getPowerOnData() const override
        {
            return mPowerOnData;
        }

        /**
         * {@inheritDoc}
         */
        const std::shared_ptr<ApduResponseApi>
        getSelectApplicationResponse() const override
        {
            return mSelectApplicationResponse;
        }

        /**
         * {@inheritDoc}
         */
        bool
        hasMatched() const override
        {
            throw std::logic_error("hasMatched");
        }

        /**
         * {@inheritDoc}
         */
        const std::shared_ptr<CardResponseApi>
        getCardResponse() const override
        {
            throw std::logic_error("getCardResponse");
        }

    private:
        /**
         *
         */
        std::string mPowerOnData;

        /**
         *
         */
        std::shared_ptr<ApduResponseApi> mSelectApplicationResponse;
    };

private:
    /**
     *
     */
    TestDtoAdapters() = default;
};

} /* namespace legacysam */
} /* namespace crypto */
} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
