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

#include "keyple/card/calypso/crypto/legacysam/LegacySamAdapter.hpp"

#include <map>
#include <memory>
#include <regex>
#include <string>
#include <utility>
#include <vector>

#include "keyple/core/util/HexUtil.hpp"
#include "keyple/core/util/cpp/exception/Exception.hpp"

namespace keyple {
namespace card {
namespace calypso {
namespace crypto {
namespace legacysam {

using keyple::core::util::HexUtil;
using keyple::core::util::cpp::exception::Exception;

LegacySamAdapter::LegacySamAdapter(ProductType productType)
: mSamProductType(productType)
, mClassByte(computeClassByte(productType))
{
}

LegacySamAdapter::LegacySamAdapter(
    std::shared_ptr<CardSelectionResponseApi> cardSelectionResponse)
{
    parseSelectionResponse(cardSelectionResponse);
}

void
LegacySamAdapter::parseSelectionResponse(
    std::shared_ptr<CardSelectionResponseApi> cardSelectionResponse)
{
    mPowerOnData = cardSelectionResponse->getPowerOnData();
    if (mPowerOnData.empty()) {
        throw std::invalid_argument("ATR should not be empty");
    }

    mSerialNumber.resize(4);

    std::regex extractRegex("3B(.{6}|.{10})805A(.{20})829000");
    std::smatch matcher;

    if (std::regex_search(mPowerOnData, matcher, extractRegex)) {
        std::vector<uint8_t> atrSubElements = HexUtil::toByteArray(matcher[2]);
        mPlatform = atrSubElements[0];
        mApplicationType = atrSubElements[1];
        mApplicationSubType = atrSubElements[2];
        mSoftwareIssuer = atrSubElements[3];
        mSoftwareVersion = atrSubElements[4];
        mSoftwareRevision = atrSubElements[5];

        switch (mApplicationSubType) {
        case 0xC1:
            mSamProductType = mSoftwareIssuer == 0x08 ? ProductType::HSM_C1
                                                      : ProductType::SAM_C1;
            break;
        case 0xD0:
        case 0xD1:
        case 0xD2:
        case 0xD3:
        case 0xD4:
        case 0xD5:
        case 0xD6:
        case 0xD7:
            mSamProductType = ProductType::SAM_S1DX;
            break;
        case 0xE1:
            mSamProductType = ProductType::SAM_S1E1;
            break;
        default:
            mSamProductType = ProductType::UNKNOWN;
            break;
        }

        std::copy(
            atrSubElements.begin() + 6,
            atrSubElements.begin() + 10,
            mSerialNumber.begin());

    } else {
        mSamProductType = ProductType::UNKNOWN;
        mPlatform = 0;
        mApplicationType = 0;
        mApplicationSubType = 0;
        mSoftwareIssuer = 0;
        mSoftwareVersion = 0;
        mSoftwareRevision = 0;
    }

    mClassByte = computeClassByte(mSamProductType);
}

uint8_t
LegacySamAdapter::getClassByte() const
{
    return mClassByte;
}

int
LegacySamAdapter::getMaxDigestDataLength() const
{
    switch (mSamProductType) {
    case ProductType::SAM_C1:
    case ProductType::HSM_C1:
        return 255;
    case ProductType::SAM_S1DX:
        return 70;
    case ProductType::SAM_S1E1:
        return 240;
    default:
        return 0;
    }
}

const std::string&
LegacySamAdapter::getPowerOnData() const
{
    return mPowerOnData;
}

ProductType
LegacySamAdapter::getProductType() const
{
    return mSamProductType;
}

std::string
LegacySamAdapter::getProductInfo() const
{
    return "Type: " + std::to_string(static_cast<int>(mSamProductType))
           + ", S/N: " + HexUtil::toHex(getSerialNumber());
}

const std::vector<uint8_t>&
LegacySamAdapter::getSerialNumber() const
{
    return mSerialNumber;
}

uint8_t
LegacySamAdapter::getPlatform() const
{
    return mPlatform;
}

uint8_t
LegacySamAdapter::getApplicationType() const
{
    return mApplicationType;
}

uint8_t
LegacySamAdapter::getApplicationSubType() const
{
    return mApplicationSubType;
}

uint8_t
LegacySamAdapter::getSoftwareIssuer() const
{
    return mSoftwareIssuer;
}

uint8_t
LegacySamAdapter::getSoftwareVersion() const
{
    return mSoftwareVersion;
}

uint8_t
LegacySamAdapter::getSoftwareRevision() const
{
    return mSoftwareRevision;
}

void
LegacySamAdapter::putCounterValue(int counterNumber, int value)
{
    mCounters[counterNumber] = value;
}

void
LegacySamAdapter::putCounterCeilingValue(int counterNumber, int value)
{
    mCounterCeilings[counterNumber] = value;
}

void
LegacySamAdapter::putCounterIncrementConfiguration(
    int counterNumber, CounterIncrementAccess counterIncrementAccess)
{
    mCountersIncrementConfig[counterNumber] = counterIncrementAccess;
}

std::shared_ptr<int>
LegacySamAdapter::getCounter(const int counterNumber) const
{
    auto it = mCounters.find(counterNumber);
    if (it != mCounters.end()) {
        return std::make_shared<int>(it->second);
    }

    return nullptr;
}

const std::map<const int, int>&
LegacySamAdapter::getCounters() const
{
    return mCounters;
}

CounterIncrementAccess
LegacySamAdapter::getCounterIncrementAccess(const int counterNumber) const
{
    auto it = mCountersIncrementConfig.find(counterNumber);
    if (it != mCountersIncrementConfig.end()) {
        return it->second;
    }

    throw Exception("counterNumber not found");
}

std::shared_ptr<int>
LegacySamAdapter::getCounterCeiling(int counterNumber) const
{
    auto it = mCounterCeilings.find(counterNumber);
    if (it != mCounterCeilings.end()) {
        return std::make_shared<int>(it->second);
    }
    return nullptr;
}

const std::map<const int, int>&
LegacySamAdapter::getCounterCeilings() const
{
    return mCounterCeilings;
}

const std::vector<uint8_t>&
LegacySamAdapter::getCaCertificate() const
{
    return mCaCertificate;
}

std::shared_ptr<SamParameters>
LegacySamAdapter::getSamParameters() const
{
    return mSamParameters;
}

void
LegacySamAdapter::setSamParameters(
    std::shared_ptr<SamParametersAdapter> samParameters)
{
    mSamParameters = samParameters;
}

void
LegacySamAdapter::setSystemKeyParameter(
    SystemKeyType systemKeyType,
    std::shared_ptr<KeyParameterAdapter> keyParameter)
{
    mSystemKeyParameterMap[systemKeyType] = keyParameter;
}

std::shared_ptr<KeyParameter>
LegacySamAdapter::getSystemKeyParameter(SystemKeyType systemKeyType) const
{
    auto it = mSystemKeyParameterMap.find(systemKeyType);
    if (it != mSystemKeyParameterMap.end()) {
        return it->second;
    }
    return nullptr;
}

void
LegacySamAdapter::setWorkKeyParameter(
    int recordNumber, std::shared_ptr<KeyParameterAdapter> keyParameter)
{
    mWorkKeyParameterByRecordNumberMap[recordNumber] = keyParameter;
}

void
LegacySamAdapter::setWorkKeyParameter(
    uint16_t kifKvc, std::shared_ptr<KeyParameterAdapter> keyParameter)
{
    mWorkKeyParameterByKifKvcMap[kifKvc] = keyParameter;
}

std::shared_ptr<KeyParameter>
LegacySamAdapter::getWorkKeyParameter(int recordNumber) const
{
    auto it = mWorkKeyParameterByRecordNumberMap.find(recordNumber);
    if (it != mWorkKeyParameterByRecordNumberMap.end()) {
        return it->second;
    }
    return nullptr;
}

std::shared_ptr<KeyParameter>
LegacySamAdapter::getWorkKeyParameter(uint8_t kif, uint8_t kvc) const
{
    uint16_t kifKvc = (static_cast<uint16_t>(kif) << 8) | kvc;
    auto it = mWorkKeyParameterByKifKvcMap.find(kifKvc);
    if (it != mWorkKeyParameterByKifKvcMap.end()) {
        return it->second;
    }
    return nullptr;
}

std::string
LegacySamAdapter::toString() const
{
    // This is a placeholder implementation.
    // A proper implementation would require a JSON library.
    return "{}";
}

void
LegacySamAdapter::setChallenge(std::vector<uint8_t> challenge)
{
    mChallenge = std::move(challenge);
}

std::vector<uint8_t>
LegacySamAdapter::popChallenge()
{
    std::vector<uint8_t> res = mChallenge;
    mChallenge.clear();
    return res;
}

void
LegacySamAdapter::setCaCertificate(std::vector<uint8_t> caCertificate)
{
    mCaCertificate = std::move(caCertificate);
}

uint8_t
LegacySamAdapter::computeClassByte(ProductType productType)
{
    return productType == ProductType::SAM_S1DX ? 0x94 : 0x80;
}

} /* namespace legacysam */
} /* namespace crypto */
} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
