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

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"

#include "keypop/card/ProxyReaderApi.hpp"
#include "keypop/reader/CardReader.hpp"

using keypop::card::CardResponseApi;
using keypop::card::ProxyReaderApi;
using keypop::card::spi::CardRequestSpi;
using keypop::reader::CardReader;

/**
 * Combines CardReader and ProxyReaderApi, mirroring the Java test's
 * "interface ReaderMock extends CardReader, ProxyReaderApi {}".
 */
class ReaderMock : public CardReader, public ProxyReaderApi {
public:
    MOCK_METHOD(const std::string&, getName, (), (const, override));
    MOCK_METHOD(bool, isContactless, (), (override));
    MOCK_METHOD(bool, isCardPresent, (), (override));
    MOCK_METHOD(
        (const std::shared_ptr<CardResponseApi>),
        transmitCardRequest,
        (const std::shared_ptr<CardRequestSpi> cardRequest,
         const keypop::card::ChannelControl channelControl),
        (override));
    MOCK_METHOD(void, releaseChannel, (), (override));
};
