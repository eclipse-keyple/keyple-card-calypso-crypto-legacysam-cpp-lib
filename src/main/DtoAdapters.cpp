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

#include "keyple/card/calypso/crypto/legacysam/DtoAdapters.hpp"

#include <map>
#include <memory>
#include <string>
#include <vector>

#include "keyple/card/calypso/crypto/legacysam/LegacySamUtil.hpp"
#include "keyple/core/util/KeypleAssert.hpp"
#include "keyple/core/util/cpp/exception/IllegalStateException.hpp"

namespace keyple {
namespace card {
namespace calypso {
namespace crypto {
namespace legacysam {

using keyple::core::util::Assert;
using keyple::core::util::cpp::exception::IllegalStateException;

const std::string DtoAdapters::MSG_THE_COMMAND_HAS_NOT_YET_BEEN_PROCESSED
    = "The command has not yet been processed";

DtoAdapters::DtoAdapters()
{
}

template <typename T>
DtoAdapters::SignatureComputationDataAdapter<
    T>::SignatureComputationDataAdapter()
: SignatureComputationData<T>()
, mKif(0)
, mKvc(0)
, mSignatureSize(8)
, mKeyDiversifier({})
, mSignature({})
{
}

template <typename T>
T&
DtoAdapters::SignatureComputationDataAdapter<T>::setData(
    const std::vector<uint8_t>& data, uint8_t kif, uint8_t kvc)
{
    mData = data;
    mKif = kif;
    mKvc = kvc;

    return dynamic_cast<T&>(*this);
}

template <typename T>
T&
DtoAdapters::SignatureComputationDataAdapter<T>::setSignatureSize(
    const int size)
{
    mSignatureSize = size;

    return dynamic_cast<T&>(*this);
}

template <typename T>
T&
DtoAdapters::SignatureComputationDataAdapter<T>::setKeyDiversifier(
    const std::vector<uint8_t>& diversifier)
{
    mKeyDiversifier = diversifier;

    return dynamic_cast<T&>(*this);
}

template <typename T>
const std::vector<uint8_t>&
DtoAdapters::SignatureComputationDataAdapter<T>::getSignature() const
{
    if (mSignature.empty()) {
        throw IllegalStateException(MSG_THE_COMMAND_HAS_NOT_YET_BEEN_PROCESSED);
    }

    return mSignature;
}

template <typename T>
const std::vector<uint8_t>&
DtoAdapters::SignatureComputationDataAdapter<T>::getData() const
{
    return mData;
}

template <typename T>
uint8_t
DtoAdapters::SignatureComputationDataAdapter<T>::getKif() const
{
    return mKif;
}

template <typename T>
uint8_t
DtoAdapters::SignatureComputationDataAdapter<T>::getKvc() const
{
    return mKvc;
}

template <typename T>
int
DtoAdapters::SignatureComputationDataAdapter<T>::getSignatureSize() const
{
    return mSignatureSize;
}

template <typename T>
const std::vector<uint8_t>
DtoAdapters::SignatureComputationDataAdapter<T>::getKeyDiversifier() const
{
    return mKeyDiversifier;
}

template <typename T>
void
DtoAdapters::SignatureComputationDataAdapter<T>::setSignature(
    const std::vector<uint8_t>& signature)
{
    mSignature = signature;
}

template <typename T>
DtoAdapters::SignatureVerificationDataAdapter<
    T>::SignatureVerificationDataAdapter()
: mKif(0)
, mKvc(0)
, mIsSignatureValid(false)
, mHasIsSignatureValid(false)
{
}

template <typename T>
T&
DtoAdapters::SignatureVerificationDataAdapter<T>::setData(
    const std::vector<uint8_t>& data,
    const std::vector<uint8_t>& signature,
    uint8_t kif,
    uint8_t kvc)
{
    mData = data;
    mSignature = signature;
    mKif = kif;
    mKvc = kvc;

    return dynamic_cast<T&>(*this);
}

template <typename T>
T&
DtoAdapters::SignatureVerificationDataAdapter<T>::setKeyDiversifier(
    const std::vector<uint8_t>& diversifier)
{
    mKeyDiversifier = diversifier;

    return dynamic_cast<T&>(*this);
}

template <typename T>
bool
DtoAdapters::SignatureVerificationDataAdapter<T>::isSignatureValid() const
{
    if (!mHasIsSignatureValid) {
        throw std::logic_error(MSG_THE_COMMAND_HAS_NOT_YET_BEEN_PROCESSED);
    }
    return mIsSignatureValid;
}

template <typename T>
const std::vector<uint8_t>&
DtoAdapters::SignatureVerificationDataAdapter<T>::getData() const
{
    return mData;
}

template <typename T>
const std::vector<uint8_t>&
DtoAdapters::SignatureVerificationDataAdapter<T>::getSignature() const
{
    return mSignature;
}

template <typename T>
uint8_t
DtoAdapters::SignatureVerificationDataAdapter<T>::getKif() const
{
    return mKif;
}

template <typename T>
uint8_t
DtoAdapters::SignatureVerificationDataAdapter<T>::getKvc() const
{
    return mKvc;
}

template <typename T>
const std::vector<uint8_t>
DtoAdapters::SignatureVerificationDataAdapter<T>::getKeyDiversifier() const
{
    return mKeyDiversifier;
}

template <typename T>
void
DtoAdapters::SignatureVerificationDataAdapter<T>::setSignatureValid(
    bool isSignatureValid)
{
    mIsSignatureValid = isSignatureValid;
    mHasIsSignatureValid = true;
}

// Explicit template instantiations
template class DtoAdapters::SignatureComputationDataAdapter<
    BasicSignatureComputationData>;
template class DtoAdapters::SignatureComputationDataAdapter<
    TraceableSignatureComputationData>;
template class DtoAdapters::SignatureVerificationDataAdapter<
    BasicSignatureVerificationData>;
template class DtoAdapters::SignatureVerificationDataAdapter<
    TraceableSignatureVerificationData>;

DtoAdapters::TraceableSignatureComputationDataAdapter ::
    TraceableSignatureComputationDataAdapter()
: mIsSamTraceabilityMode(false)
, mTraceabilityOffset(0)
, mIsBusyMode(true)
{
}

TraceableSignatureComputationData&
DtoAdapters::TraceableSignatureComputationDataAdapter::withSamTraceabilityMode(
    const int offset, const SamTraceabilityMode samTraceabilityMode)
{
    mIsSamTraceabilityMode = true;
    mTraceabilityOffset = offset;
    mSamTraceabilityMode = samTraceabilityMode;

    return *this;
}

TraceableSignatureComputationData&
DtoAdapters::TraceableSignatureComputationDataAdapter::withoutBusyMode()
{
    mIsBusyMode = false;

    return *this;
}

const std::vector<uint8_t>&
DtoAdapters::TraceableSignatureComputationDataAdapter::getSignedData() const
{
    if (mSignedData.empty()) {
        throw IllegalStateException(MSG_THE_COMMAND_HAS_NOT_YET_BEEN_PROCESSED);
    }

    return mSignedData;
}

bool
DtoAdapters::TraceableSignatureComputationDataAdapter::isSamTraceabilityMode()
    const
{
    return mIsSamTraceabilityMode;
}

int
DtoAdapters::TraceableSignatureComputationDataAdapter::getTraceabilityOffset()
    const
{
    return mTraceabilityOffset;
}

SamTraceabilityMode
DtoAdapters::TraceableSignatureComputationDataAdapter::getSamTraceabilityMode()
    const
{
    return mSamTraceabilityMode;
}

bool
DtoAdapters::TraceableSignatureComputationDataAdapter::isBusyMode() const
{
    return mIsBusyMode;
}

void
DtoAdapters::TraceableSignatureComputationDataAdapter::setSignedData(
    const std::vector<uint8_t>& signedData)
{
    mSignedData = signedData;
}

DtoAdapters::TraceableSignatureVerificationDataAdapter ::
    TraceableSignatureVerificationDataAdapter()
: mIsSamTraceabilityMode(false)
, mTraceabilityOffset(0)
, mIsBusyMode(true)
{
}

TraceableSignatureVerificationData&
DtoAdapters::TraceableSignatureVerificationDataAdapter::withSamTraceabilityMode(
    const int offset,
    const SamTraceabilityMode samTraceabilityMode,
    std::shared_ptr<LegacySamRevocationServiceSpi> samRevocationService)
{
    mIsSamTraceabilityMode = true;
    mTraceabilityOffset = offset;
    mSamTraceabilityMode = samTraceabilityMode;
    mSamRevocationService = samRevocationService;

    return *this;
}

TraceableSignatureVerificationData&
DtoAdapters::TraceableSignatureVerificationDataAdapter::withoutBusyMode()
{
    mIsBusyMode = false;

    return *this;
}

bool
DtoAdapters::TraceableSignatureVerificationDataAdapter::isSamTraceabilityMode()
    const
{
    return mIsSamTraceabilityMode;
}

int
DtoAdapters::TraceableSignatureVerificationDataAdapter::getTraceabilityOffset()
    const
{
    return mTraceabilityOffset;
}

SamTraceabilityMode
DtoAdapters::TraceableSignatureVerificationDataAdapter::getSamTraceabilityMode()
    const
{
    return mSamTraceabilityMode;
}

std::shared_ptr<LegacySamRevocationServiceSpi>
DtoAdapters::TraceableSignatureVerificationDataAdapter ::
    getSamRevocationService() const
{
    return mSamRevocationService;
}

bool
DtoAdapters::TraceableSignatureVerificationDataAdapter::isBusyMode() const
{
    return mIsBusyMode;
}

DtoAdapters::ApduRequestAdapter::ApduRequestAdapter(
    const std::vector<uint8_t>& apdu)
: mApdu(apdu)
{
    mSuccessfulStatusWords.push_back(0x9000);
}

DtoAdapters::ApduRequestAdapter&
DtoAdapters::ApduRequestAdapter::addSuccessfulStatusWord(
    int successfulStatusWord)
{
    mSuccessfulStatusWords.push_back(successfulStatusWord);

    return *this;
}

const std::vector<int>&
DtoAdapters::ApduRequestAdapter::getSuccessfulStatusWords() const
{
    return mSuccessfulStatusWords;
}

DtoAdapters::ApduRequestAdapter&
DtoAdapters::ApduRequestAdapter::setInfo(const std::string& info)
{
    mInfo = info;

    return *this;
}

const std::string&
DtoAdapters::ApduRequestAdapter::getInfo() const
{
    return mInfo;
}

const std::vector<uint8_t>&
DtoAdapters::ApduRequestAdapter::getApdu() const
{
    return mApdu;
}

void
DtoAdapters::ApduRequestAdapter::setApdu(const std::vector<std::uint8_t>& apdu)
{
    mApdu = apdu;
}

DtoAdapters::CardRequestAdapter::CardRequestAdapter(
    const std::vector<std::shared_ptr<ApduRequestSpi>>& apduRequests,
    bool stopOnUnsuccessfulStatusWord)
: mApduRequests(apduRequests)
, mStopOnUnsuccessfulStatusWord(stopOnUnsuccessfulStatusWord)
{
}

const std::vector<std::shared_ptr<ApduRequestSpi>>&
DtoAdapters::CardRequestAdapter::getApduRequests() const
{
    return mApduRequests;
}

bool
DtoAdapters::CardRequestAdapter::stopOnUnsuccessfulStatusWord() const
{
    return mStopOnUnsuccessfulStatusWord;
}

const int DtoAdapters::CardSelectionRequestAdapter::DEFAULT_SUCCESSFUL_CODE
    = 0x9000;

DtoAdapters::CardSelectionRequestAdapter::CardSelectionRequestAdapter(
    std::shared_ptr<CardRequestSpi> cardRequest)
: mCardRequest(cardRequest)
{
    mSuccessfulSelectionStatusWords.push_back(DEFAULT_SUCCESSFUL_CODE);
}

const std::vector<int>&
DtoAdapters::CardSelectionRequestAdapter::getSuccessfulSelectionStatusWords()
    const
{
    return mSuccessfulSelectionStatusWords;
}

const std::shared_ptr<CardRequestSpi>
DtoAdapters::CardSelectionRequestAdapter::getCardRequest() const
{
    return mCardRequest;
}

DtoAdapters::TargetSamContextDto::TargetSamContextDto(
    const std::vector<uint8_t>& serialNumber, bool isDynamicMode)
: mSerialNumber(serialNumber)
, mIsDynamicMode(isDynamicMode)
{
}

const std::vector<uint8_t>&
DtoAdapters::TargetSamContextDto::getSerialNumber() const
{
    return mSerialNumber;
}

bool
DtoAdapters::TargetSamContextDto::isDynamicMode() const
{
    return mIsDynamicMode;
}

std::map<SystemKeyType, int>&
DtoAdapters::TargetSamContextDto::getSystemKeyTypeToCounterNumberMap()
{
    return mSystemKeyTypeToCounterNumberMap;
}

std::map<SystemKeyType, uint8_t>&
DtoAdapters::TargetSamContextDto::getSystemKeyTypeToKvcMap()
{
    return mSystemKeyTypeToKvcMap;
}

std::map<int, int>&
DtoAdapters::TargetSamContextDto::getCounterNumberToCounterValueMap()
{
    return mCounterNumberToCounterValueMap;
}

DtoAdapters::CommandContextDto::CommandContextDto(
    std::shared_ptr<LegacySamAdapter> targetSam,
    std::shared_ptr<ProxyReaderApi> controlSamReader,
    std::shared_ptr<LegacySamAdapter> controlSam)
: mTargetSam(targetSam)
, mControlSamReader(controlSamReader)
, mControlSam(controlSam)
{
}

std::shared_ptr<LegacySamAdapter>
DtoAdapters::CommandContextDto::getTargetSam() const
{
    return mTargetSam;
}

std::shared_ptr<ProxyReaderApi>
DtoAdapters::CommandContextDto::getControlSamReader() const
{
    return mControlSamReader;
}

std::shared_ptr<LegacySamAdapter>
DtoAdapters::CommandContextDto::getControlSam() const
{
    return mControlSam;
}

const std::vector<uint8_t>&
DtoAdapters::KeyPairContainerAdapter::getKeyPair() const
{
    return mKeyPair;
}

void
DtoAdapters::KeyPairContainerAdapter::setKeyPair(
    const std::vector<uint8_t>& keyPair)
{
    mKeyPair = keyPair;
}

DtoAdapters::LegacyCardCertificateComputationDataAdapter ::
    LegacyCardCertificateComputationDataAdapter()
: mStartDateBcd(0)
, mEndDateBcd(0)
{
}

LegacyCardCertificateComputationData&
DtoAdapters::LegacyCardCertificateComputationDataAdapter::setCardPublicKey(
    const std::vector<uint8_t>& cardPublicKey)
{
    Assert::getInstance().isEqual(cardPublicKey.size(), 64, "cardPublicKey");

    mCardPublicKey = cardPublicKey;

    return *this;
}

LegacyCardCertificateComputationData&
DtoAdapters::LegacyCardCertificateComputationDataAdapter::setStartDate(
    const tm& startDate)
{
    mStartDateBcd = LegacySamUtil::convertDateToBcdLong(
        startDate.tm_year, startDate.tm_mon, startDate.tm_mday);

    return *this;
}

LegacyCardCertificateComputationData&
DtoAdapters::LegacyCardCertificateComputationDataAdapter::setEndDate(
    const tm& endDate)
{
    mEndDateBcd = LegacySamUtil::convertDateToBcdLong(
        endDate.tm_year, endDate.tm_mon, endDate.tm_mday);

    return *this;
}

LegacyCardCertificateComputationData&
DtoAdapters::LegacyCardCertificateComputationDataAdapter::setCardAid(
    const std::vector<uint8_t>& aid)
{
    Assert::getInstance().isInRange(aid.size(), 5, 16, "aid length");

    mAid = aid;

    return *this;
}

LegacyCardCertificateComputationData&
DtoAdapters::LegacyCardCertificateComputationDataAdapter::setCardSerialNumber(
    const std::vector<uint8_t>& serialNumber)
{
    Assert::getInstance().isEqual(
        serialNumber.size(), 8, "serialNumber length");

    mSerialNumber = serialNumber;

    return *this;
}

LegacyCardCertificateComputationData&
DtoAdapters::LegacyCardCertificateComputationDataAdapter::setCardStartupInfo(
    const std::vector<uint8_t>& startupInfo)
{
    Assert::getInstance().isEqual(startupInfo.size(), 7, "startupInfo length");

    mStartupInfo = startupInfo;

    return *this;
}

const std::vector<uint8_t>&
DtoAdapters::LegacyCardCertificateComputationDataAdapter::getCertificate() const
{
    return mCertificate;
}

void
DtoAdapters::LegacyCardCertificateComputationDataAdapter::setCertificate(
    const std::vector<uint8_t>& cardCertificate)
{
    mCertificate = cardCertificate;
}

const std::vector<uint8_t>&
DtoAdapters::LegacyCardCertificateComputationDataAdapter::getCardPublicKey()
    const
{
    return mCardPublicKey;
}

uint32_t
DtoAdapters::LegacyCardCertificateComputationDataAdapter::getStartDateBcd()
    const
{
    return mStartDateBcd;
}

uint32_t
DtoAdapters::LegacyCardCertificateComputationDataAdapter::getEndDateBcd() const
{
    return mEndDateBcd;
}

const std::vector<uint8_t>&
DtoAdapters::LegacyCardCertificateComputationDataAdapter::getAid() const
{
    return mAid;
}

const std::vector<uint8_t>&
DtoAdapters::LegacyCardCertificateComputationDataAdapter::getSerialNumber()
    const
{
    return mSerialNumber;
}

const std::vector<uint8_t>&
DtoAdapters::LegacyCardCertificateComputationDataAdapter::getStartupInfo() const
{
    return mStartupInfo;
}

} /* namespace legacysam */
} /* namespace crypto */
} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
