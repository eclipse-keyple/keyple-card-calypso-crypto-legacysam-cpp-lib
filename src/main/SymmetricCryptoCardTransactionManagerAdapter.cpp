/******************************************************************************
 * Copyright (c) 2019 Calypso Networks Association https://calypsonet.org/    *
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

#include "keyple/card/calypso/crypto/legacysam/SymmetricCryptoCardTransactionManagerAdapter.hpp"

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "keyple/card/calypso/crypto/legacysam/CardTransactionUtil.hpp"
#include "keyple/card/calypso/crypto/legacysam/CommandCardCipherPin.hpp"
#include "keyple/card/calypso/crypto/legacysam/CommandCardGenerateKey.hpp"
#include "keyple/card/calypso/crypto/legacysam/CommandDataCipher.hpp"
#include "keyple/card/calypso/crypto/legacysam/CommandDigestAuthenticate.hpp"
#include "keyple/card/calypso/crypto/legacysam/CommandDigestClose.hpp"
#include "keyple/card/calypso/crypto/legacysam/CommandDigestInit.hpp"
#include "keyple/card/calypso/crypto/legacysam/CommandDigestInternalAuthenticate.hpp"
#include "keyple/card/calypso/crypto/legacysam/CommandDigestUpdateMultiple.hpp"
#include "keyple/card/calypso/crypto/legacysam/CommandGetChallenge.hpp"
#include "keyple/card/calypso/crypto/legacysam/CommandGiveRandom.hpp"
#include "keyple/card/calypso/crypto/legacysam/CommandPsoComputeSignature.hpp"
#include "keyple/card/calypso/crypto/legacysam/CommandPsoVerifySignature.hpp"
#include "keyple/card/calypso/crypto/legacysam/CommandSelectDiversifier.hpp"
#include "keyple/card/calypso/crypto/legacysam/CommandSvCheck.hpp"
#include "keyple/card/calypso/crypto/legacysam/CommandSvPrepareDebitOrUndebit.hpp"
#include "keyple/card/calypso/crypto/legacysam/CommandSvPrepareLoad.hpp"
#include "keyple/card/calypso/crypto/legacysam/DtoAdapters.hpp"
#include "keyple/card/calypso/crypto/legacysam/SecurityDataException.hpp"
#include "keyple/core/util/ApduUtil.hpp"
#include "keyple/core/util/ByteArrayUtil.hpp"
#include "keyple/core/util/HexUtil.hpp"
#include "keyple/core/util/KeypleAssert.hpp"
#include "keyple/core/util/cpp/Arrays.hpp"
#include "keyple/core/util/cpp/System.hpp"
#include "keyple/core/util/cpp/exception/IllegalStateException.hpp"
#include "keypop/calypso/card/transaction/InconsistentDataException.hpp"
#include "keypop/calypso/crypto/legacysam/transaction/InvalidSignatureException.hpp"
#include "keypop/calypso/crypto/legacysam/transaction/SamRevokedException.hpp"
#include "keypop/calypso/crypto/legacysam/transaction/SignatureComputationDataBase.hpp"
#include "keypop/calypso/crypto/legacysam/transaction/UnexpectedCommandStatusException.hpp"
#include "keypop/calypso/crypto/symmetric/SymmetricCryptoException.hpp"

namespace keyple {
namespace card {
namespace calypso {
namespace crypto {
namespace legacysam {

using keyple::core::util::ApduUtil;
using keyple::core::util::Assert;
using keyple::core::util::ByteArrayUtil;
using keyple::core::util::HexUtil;
using keyple::core::util::cpp::Arrays;
using keyple::core::util::cpp::System;
using keyple::core::util::cpp::exception::IllegalStateException;
using keypop::calypso::card::transaction::InconsistentDataException;
using keypop::calypso::crypto::legacysam::transaction::
    InvalidSignatureException;
using keypop::calypso::crypto::legacysam::transaction::SamRevokedException;
using keypop::calypso::crypto::legacysam::transaction::
    SignatureComputationDataBase;
using keypop::calypso::crypto::legacysam::transaction::
    UnexpectedCommandStatusException;
using keypop::calypso::crypto::symmetric::SymmetricCryptoException;

using InvalidCardMacException
    = SymmetricCryptoCardTransactionManagerAdapter::InvalidCardMacException;

const std::string
    SymmetricCryptoCardTransactionManagerAdapter::MSG_SAM_INCONSISTENT_DATA
    = "The number of SAM commands/responses does not match: nb commands = ";
const std::string
    SymmetricCryptoCardTransactionManagerAdapter::MSG_SAM_NB_RESPONSES
    = ", nb responses = ";
const std::string
    SymmetricCryptoCardTransactionManagerAdapter::MSG_INPUT_OUTPUT_DATA
    = "input/output data";
const std::string
    SymmetricCryptoCardTransactionManagerAdapter::MSG_SIGNATURE_SIZE
    = "signature size";
const std::string SymmetricCryptoCardTransactionManagerAdapter ::
    MSG_KEY_DIVERSIFIER_SIZE_IS_IN_RANGE_1_8
    = "key diversifier size is in range [1..8]";

SymmetricCryptoCardTransactionManagerAdapter::
    SymmetricCryptoCardTransactionManagerAdapter(
        std::shared_ptr<ProxyReaderApi> samReader,
        std::shared_ptr<LegacySamAdapter> sam,
        const std::vector<uint8_t>& cardKeyDiversifier,
        bool useExtendedMode,
        int maxCardApduLengthSupported,
        const std::vector<std::vector<uint8_t>>& transactionAuditData)
: mSamReader(samReader)
, mSam(sam)
, mCardKeyDiversifier(cardKeyDiversifier)
, mIsExtendedModeRequired(useExtendedMode)
, mMaxCardApduLengthSupported(maxCardApduLengthSupported)
, mTransactionAuditData(transactionAuditData)
{
}

std::shared_ptr<DtoAdapters::CommandContextDto>
SymmetricCryptoCardTransactionManagerAdapter::getContext()
{
    return std::make_shared<DtoAdapters::CommandContextDto>(
        mSam, nullptr, nullptr);
}

std::vector<uint8_t>
SymmetricCryptoCardTransactionManagerAdapter::initTerminalSecureSessionContext()
{
    if (isSelectDiversifierNeeded(mCardKeyDiversifier)) {
        mIsSelectDiversifierNeededOnDigestInit = true;
    }

    std::vector<uint8_t> challenge = mSam->popChallenge();
    if (challenge.empty()) {
        auto cmd = std::make_shared<CommandGetChallenge>(
            getContext(), mIsExtendedModeRequired ? 8 : 4);
        mSamCommands.push_back(cmd);
        processCommands();
        return mSam->popChallenge();

    } else {
        return mIsExtendedModeRequired ? challenge
                                       : Arrays::copyOf(challenge, 4);
    }
}

void
SymmetricCryptoCardTransactionManagerAdapter::initTerminalSessionMac(
    const std::vector<uint8_t>& openSecureSessionDataOut,
    uint8_t kif,
    uint8_t kvc)
{
    mDigestManager = std::make_shared<DigestManager>(
        this, openSecureSessionDataOut, kif, kvc);
}

std::vector<uint8_t>
SymmetricCryptoCardTransactionManagerAdapter::updateTerminalSessionMac(
    const std::vector<uint8_t>& cardApdu)
{
    if (mIsEncryptionActive) {
        /*
         * Encrypted mode.
         * We first prepare any pending plain-text commands in order to optimize
         * the possible groupings.
         */
        mDigestManager->prepareCommands();

        /* We then prepare the command for encryption. */
        auto samCommand = mDigestManager->prepareCommandForEncryption(cardApdu);

        /*  Process commands. */
        processCommands();

        /* Return the encrypted/decrypted value. */
        return samCommand->getProcessedData();

    } else {
        /* Plain mode. */
        mDigestManager->updateSession(cardApdu);
        return {};
    }
}

std::vector<uint8_t>
SymmetricCryptoCardTransactionManagerAdapter::finalizeTerminalSessionMac()
{
    mDigestManager->prepareAllCommands();
    mDigestManager.reset();

    auto cmdSamDigestClose = std::dynamic_pointer_cast<CommandDigestClose>(
        mSamCommands[mSamCommands.size() - 1]);

    processCommands();

    return cmdSamDigestClose->getMac();
}

std::vector<uint8_t>
SymmetricCryptoCardTransactionManagerAdapter::generateTerminalSessionMac()
{
    /*
     * We first prepare any pending commands in order to optimize the possible
     * groupings.
     */
    mDigestManager->prepareCommands();

    /* Then we prepare the "Digest Internal Authenticate" command. */
    auto cmdSamDigestInternalAuthenticate
        = std::make_shared<CommandDigestInternalAuthenticate>(getContext());
    mSamCommands.push_back(cmdSamDigestInternalAuthenticate);

    /* Process commands. */
    processCommands();

    /* Return the terminal session MAC. */
    return cmdSamDigestInternalAuthenticate->getTerminalSignature();
}

void
SymmetricCryptoCardTransactionManagerAdapter::activateEncryption()
{
    mIsEncryptionActive = true;
}

void
SymmetricCryptoCardTransactionManagerAdapter::deactivateEncryption()
{
    mIsEncryptionActive = false;
}

bool
SymmetricCryptoCardTransactionManagerAdapter::isCardSessionMacValid(
    const std::vector<uint8_t>& cardSessionMac)
{
    mSamCommands.push_back(
        std::make_shared<CommandDigestAuthenticate>(
            getContext(), cardSessionMac));
    try {
        processCommands();
        return true;

    } catch (const InvalidCardMacException&) {
        return false;
    }
}

void
SymmetricCryptoCardTransactionManagerAdapter::computeSvCommandSecurityData(
    std::shared_ptr<SvCommandSecurityDataApi> svCommandSecurityData)
{
    prepareSelectDiversifierIfNeeded();
    if ((svCommandSecurityData->getSvCommandPartialRequest())[0] == 0xB8) {
        mSamCommands.push_back(
            std::make_shared<CommandSvPrepareLoad>(
                getContext(), svCommandSecurityData));
    } else {
        mSamCommands.push_back(
            std::make_shared<CommandSvPrepareDebitOrUndebit>(
                getContext(), svCommandSecurityData));
    }
    processCommands();
}

bool
SymmetricCryptoCardTransactionManagerAdapter::isCardSvMacValid(
    const std::vector<uint8_t>& cardSvMac)
{
    mSamCommands.push_back(
        std::make_shared<CommandSvCheck>(getContext(), cardSvMac));
    try {
        processCommands();
        return true;

    } catch (const InvalidCardMacException&) {
        return false;
    }
}

std::vector<uint8_t>
SymmetricCryptoCardTransactionManagerAdapter::cipherPinForPresentation(
    const std::vector<uint8_t>& cardChallenge,
    const std::vector<uint8_t>& pin,
    const std::shared_ptr<uint8_t> kif,
    const std::shared_ptr<uint8_t> kvc)
{
    return cipherPin(cardChallenge, pin, {}, kif, kvc);
}

std::vector<uint8_t>
SymmetricCryptoCardTransactionManagerAdapter::cipherPinForModification(
    const std::vector<uint8_t>& cardChallenge,
    const std::vector<uint8_t>& currentPin,
    const std::vector<uint8_t>& newPin,
    const std::shared_ptr<uint8_t> kif,
    const std::shared_ptr<uint8_t> kvc)
{
    return cipherPin(cardChallenge, currentPin, newPin, kif, kvc);
}

std::vector<uint8_t>
SymmetricCryptoCardTransactionManagerAdapter::generateCipheredCardKey(
    const std::vector<uint8_t>& cardChallenge,
    uint8_t issuerKeyKif,
    uint8_t issuerKeyKvc,
    uint8_t targetKeyKif,
    uint8_t targetKeyKvc)
{
    prepareGiveRandom(cardChallenge);
    auto cmd = std::make_shared<CommandCardGenerateKey>(
        getContext(), issuerKeyKif, issuerKeyKvc, targetKeyKif, targetKeyKvc);
    mSamCommands.push_back(cmd);
    processCommands();
    return cmd->getCipheredData();
}

void
SymmetricCryptoCardTransactionManagerAdapter::synchronize()
{
    processCommands();
}

CardTransactionLegacySamExtension&
SymmetricCryptoCardTransactionManagerAdapter::prepareComputeSignature(
    std::shared_ptr<SignatureComputationDataBase> data)
{
    std::shared_ptr<DtoAdapters::BasicSignatureComputationDataAdapter>
        basicDataAdapter = std::dynamic_pointer_cast<
            DtoAdapters::BasicSignatureComputationDataAdapter>(data);
    if (basicDataAdapter) {
        /* Basic signature */
        Assert::getInstance()
            .notNull(basicDataAdapter, MSG_INPUT_OUTPUT_DATA)
            .isInRange(
                basicDataAdapter->getData().size(),
                1,
                208,
                "length of data to sign")
            .isTrue(
                basicDataAdapter->getData().size() % 8 == 0,
                "length of data to sign is a multiple of 8")
            .isInRange(
                basicDataAdapter->getSignatureSize(), 1, 8, MSG_SIGNATURE_SIZE)
            .isTrue(
                basicDataAdapter->getKeyDiversifier().empty()
                    || (basicDataAdapter->getKeyDiversifier().size() >= 1
                        && basicDataAdapter->getKeyDiversifier().size() <= 8),
                MSG_KEY_DIVERSIFIER_SIZE_IS_IN_RANGE_1_8);

        prepareSelectDiversifierIfNeeded(basicDataAdapter->getKeyDiversifier());
        mSamCommands.push_back(
            std::make_shared<CommandDataCipher>(
                getContext(), basicDataAdapter, nullptr));

    } else {
        std::shared_ptr<DtoAdapters::TraceableSignatureComputationDataAdapter>
            traceableDataAdapter = std::dynamic_pointer_cast<
                DtoAdapters::TraceableSignatureComputationDataAdapter>(data);
        if (traceableDataAdapter) {
            /* Traceable signature */
            const bool isTracebilityOffsetInRage
                = !traceableDataAdapter->isSamTraceabilityMode()
                  || (traceableDataAdapter->getTraceabilityOffset() >= 0
                      && traceableDataAdapter->getTraceabilityOffset()
                             <= static_cast<int>(
                                 ((traceableDataAdapter->getData().size() * 8)
                                  - (traceableDataAdapter
                                                 ->getSamTraceabilityMode()
                                             == SamTraceabilityMode::
                                                 TRUNCATED_SERIAL_NUMBER
                                         ? 7 * 8
                                         : 8 * 8))));
            core::util::Assert::getInstance()
                .notNull(traceableDataAdapter, MSG_INPUT_OUTPUT_DATA)
                .isInRange(
                    traceableDataAdapter->getData().size(),
                    1,
                    traceableDataAdapter->isSamTraceabilityMode() ? 206 : 208,
                    "length of data to sign")
                .isInRange(
                    traceableDataAdapter->getSignatureSize(),
                    1,
                    8,
                    MSG_SIGNATURE_SIZE)
                .isTrue(
                    isTracebilityOffsetInRage,
                    "traceability offset is in range")
                .isTrue(
                    traceableDataAdapter->getKeyDiversifier().empty()
                        || (traceableDataAdapter->getKeyDiversifier().size()
                                >= 1
                            && traceableDataAdapter->getKeyDiversifier().size()
                                   <= 8),
                    MSG_KEY_DIVERSIFIER_SIZE_IS_IN_RANGE_1_8);

            prepareSelectDiversifierIfNeeded(
                traceableDataAdapter->getKeyDiversifier());
            mSamCommands.push_back(
                std::make_shared<CommandPsoComputeSignature>(
                    getContext(), traceableDataAdapter));

        } else {
            throw std::invalid_argument(
                "The provided data must be an instance of "
                "'BasicSignatureComputationDataAdapter'"
                " or 'TraceableSignatureComputationDataAdapter'");
        }
    }

    return *this;
}

CardTransactionLegacySamExtension&
SymmetricCryptoCardTransactionManagerAdapter::prepareVerifySignature(
    std::shared_ptr<SignatureVerificationDataBase> data)
{
    std::shared_ptr<DtoAdapters::BasicSignatureVerificationDataAdapter>
        basicDataAdapter = std::dynamic_pointer_cast<
            DtoAdapters::BasicSignatureVerificationDataAdapter>(data);
    if (basicDataAdapter) {
        /* Basic signature */
        core::util::Assert::getInstance()
            .notNull(basicDataAdapter, MSG_INPUT_OUTPUT_DATA)
            .isInRange(
                basicDataAdapter->getData().size(),
                1,
                208,
                "length of signed data to verify")
            .isTrue(
                basicDataAdapter->getData().size() % 8 == 0,
                "length of data to verify is a multiple of 8")
            .isInRange(
                basicDataAdapter->getSignature().size(),
                1,
                8,
                MSG_SIGNATURE_SIZE)
            .isTrue(
                basicDataAdapter->getKeyDiversifier().empty()
                    || (basicDataAdapter->getKeyDiversifier().size() >= 1
                        && basicDataAdapter->getKeyDiversifier().size() <= 8),
                MSG_KEY_DIVERSIFIER_SIZE_IS_IN_RANGE_1_8);

        prepareSelectDiversifierIfNeeded(basicDataAdapter->getKeyDiversifier());
        mSamCommands.push_back(
            std::make_shared<CommandDataCipher>(
                getContext(), nullptr, basicDataAdapter));

    } else {
        std::shared_ptr<DtoAdapters::TraceableSignatureVerificationDataAdapter>
            traceableDataAdapter = std::dynamic_pointer_cast<
                DtoAdapters::TraceableSignatureVerificationDataAdapter>(data);
        if (traceableDataAdapter) {
            /* Traceable signature */
            const bool isTracebilityOffsetInRange
                = !traceableDataAdapter->isSamTraceabilityMode()
                  || (traceableDataAdapter->getTraceabilityOffset() >= 0
                      && traceableDataAdapter->getTraceabilityOffset()
                             <= static_cast<int>(
                                 ((traceableDataAdapter->getData().size() * 8)
                                  - (traceableDataAdapter
                                                 ->getSamTraceabilityMode()
                                             == SamTraceabilityMode::
                                                 TRUNCATED_SERIAL_NUMBER
                                         ? 7 * 8
                                         : 8 * 8))));
            core::util::Assert::getInstance()
                .notNull(traceableDataAdapter, MSG_INPUT_OUTPUT_DATA)
                .isInRange(
                    traceableDataAdapter->getData().size(),
                    1,
                    traceableDataAdapter->isSamTraceabilityMode() ? 206 : 208,
                    "length of signed data to verify")
                .isInRange(
                    traceableDataAdapter->getSignature().size(),
                    1,
                    8,
                    MSG_SIGNATURE_SIZE)
                .isTrue(
                    isTracebilityOffsetInRange,
                    "traceability offset is in range")
                .isTrue(
                    traceableDataAdapter->getKeyDiversifier().empty()
                        || (traceableDataAdapter->getKeyDiversifier().size()
                                >= 1
                            && traceableDataAdapter->getKeyDiversifier().size()
                                   <= 8),
                    MSG_KEY_DIVERSIFIER_SIZE_IS_IN_RANGE_1_8);

            /* Check SAM revocation status if requested. */
            if (traceableDataAdapter->getSamRevocationService()) {
                /*
                 * Extract the SAM serial number and the counter value from the
                 * data.
                 */
                std::vector<uint8_t> samSerialNumber
                    = ByteArrayUtil::extractBytes(
                        traceableDataAdapter->getData(),
                        traceableDataAdapter->getTraceabilityOffset(),
                        traceableDataAdapter->getSamTraceabilityMode()
                                == SamTraceabilityMode::TRUNCATED_SERIAL_NUMBER
                            ? 3
                            : 4);

                int samCounterValue = ByteArrayUtil::extractInt(
                    ByteArrayUtil::extractBytes(
                        traceableDataAdapter->getData(),
                        traceableDataAdapter->getTraceabilityOffset()
                            + (traceableDataAdapter->getSamTraceabilityMode()
                                       == SamTraceabilityMode::
                                           TRUNCATED_SERIAL_NUMBER
                                   ? 3 * 8
                                   : 4 * 8),
                        3),
                    0,
                    3,
                    false);

                // Is SAM revoked ?
                if (traceableDataAdapter->getSamRevocationService()
                        ->isSamRevoked(samSerialNumber, samCounterValue)) {
                    throw SamRevokedException(
                        "SAM with serial number ["
                        + HexUtil::toHex(samSerialNumber)
                        + "] and counter value ["
                        + std::to_string(samCounterValue) + "] is revoked");
                }
            }

            prepareSelectDiversifierIfNeeded(
                traceableDataAdapter->getKeyDiversifier());
            mSamCommands.push_back(
                std::make_shared<CommandPsoVerifySignature>(
                    getContext(), traceableDataAdapter));

        } else {
            throw std::invalid_argument(
                "The provided data must be an instance of "
                "'SignatureVerificationDataAdapter'");
        }
    }
    return *this;
}

bool
SymmetricCryptoCardTransactionManagerAdapter::isSelectDiversifierNeeded(
    const std::vector<uint8_t>& keyDiversifier)
{
    if (!Arrays::equals(mCurrentKeyDiversifier, keyDiversifier)) {
        mCurrentKeyDiversifier = keyDiversifier;
        return true;
    }

    return false;
}

void
SymmetricCryptoCardTransactionManagerAdapter::processCommands()
{
    /*
     * If there are pending SAM commands and the secure session is open and the
     * "Digest Init" command is not already executed, then we need to flush the
     * session pending commands by executing the pending "digest" commands
     * "BEFORE" the other SAM commands to make sure that between the session
     * "Get Challenge" and the "Digest Init", there is no other command
     * inserted.
     */
    if (!mSamCommands.empty() && mDigestManager
        && !mDigestManager->mIsDigestInitDone) {
        mDigestManager->prepareDigestInit();
    }

    if (mSamCommands.empty()) {
        return;
    }

    try {
        /* Get the list of C-APDU to transmit */
        auto apduRequests = CardTransactionUtil::getApduRequests(mSamCommands);

        /* Wrap the list of C-APDUs into a card request */
        auto cardRequest = std::make_shared<DtoAdapters::CardRequestAdapter>(
            apduRequests, true);

        /* Transmit the commands to the SAM */
        auto cardResponse = CardTransactionUtil::transmitCardRequest(
            cardRequest, mSamReader, mSam, mTransactionAuditData);

        /* Retrieve the list of R-APDUs */
        auto apduResponses = cardResponse->getApduResponses();

        /*
         * If there are more responses than requests, then we are unable to fill
         * the card image. In this case we stop processing immediately because
         * it may be a case of fraud, and we throw an exception.
         */
        if (apduResponses.size() > apduRequests.size()) {
            throw SymmetricCryptoException(
                "The number of SAM commands/responses does not match: nb "
                "commands = "
                    + std::to_string(apduRequests.size()) + ", nb responses = "
                    + std::to_string(apduResponses.size()),
                InconsistentDataException(
                    "The number of SAM commands/responses does not match: nb "
                    "commands = "
                    + std::to_string(apduRequests.size())
                    + ", nb responses = " + std::to_string(apduResponses.size())
                    + CardTransactionUtil::getTransactionAuditDataAsString(
                        mTransactionAuditData, mSam)));
        }

        for (size_t i = 0; i < apduResponses.size(); i++) {
            try {
                mSamCommands[i]->parseResponse(apduResponses[i]);
            } catch (const CommandException& e) {
                auto commandRef = mSamCommands[i]->getCommandRef();
                if (commandRef == CommandRef::DIGEST_AUTHENTICATE
                    && dynamic_cast<const SecurityDataException*>(&e)) {
                    throw InvalidCardMacException("Invalid card signature");
                } else if (
                    (commandRef == CommandRef::PSO_VERIFY_SIGNATURE
                     || commandRef == CommandRef::DATA_CIPHER)
                    && dynamic_cast<const SecurityDataException*>(&e)) {
                    throw InvalidSignatureException(
                        "Invalid signature",
                        std::make_shared<CommandException>(e));
                } else if (
                    commandRef == CommandRef::SV_CHECK
                    && dynamic_cast<const SecurityDataException*>(&e)) {
                    throw InvalidCardMacException("Invalid SV card signature");
                }

                const std::string sw = mSamCommands[i]->getApduResponse()
                                           ? HexUtil::toHex(
                                                 static_cast<std::uint16_t>(
                                                     mSamCommands[i]
                                                         ->getApduResponse()
                                                         ->getStatusWord()))
                                           : "null";

                throw SymmetricCryptoException(
                    "A SAM command error occurred while processing responses "
                    "to SAM commands: "
                        + commandRef.getName() + " [" + sw + "]",
                    UnexpectedCommandStatusException(
                        "A SAM command error occurred while processing "
                        "responses to SAM commands: "
                            + commandRef.getName() + " [" + sw + "]"
                            + CardTransactionUtil::
                                getTransactionAuditDataAsString(
                                    mTransactionAuditData, mSam),
                        e));
            }
        }

        if (apduResponses.size() < apduRequests.size()) {
            throw SymmetricCryptoException(
                "The number of SAM commands/responses does not match: nb "
                "commands = "
                    + std::to_string(apduRequests.size()) + ", nb responses = "
                    + std::to_string(apduResponses.size()),
                InconsistentDataException(
                    "The number of SAM commands/responses does not match: nb "
                    "commands = "
                    + std::to_string(apduRequests.size())
                    + ", nb responses = " + std::to_string(apduResponses.size())
                    + CardTransactionUtil::getTransactionAuditDataAsString(
                        mTransactionAuditData, mSam)));
        }
    } catch (...) {
        mSamCommands.clear();
        throw;
    }
    mSamCommands.clear();
}

void
SymmetricCryptoCardTransactionManagerAdapter::prepareGiveRandom(
    const std::vector<uint8_t>& cardChallenge)
{
    prepareSelectDiversifierIfNeeded();
    mSamCommands.push_back(
        std::make_shared<CommandGiveRandom>(getContext(), cardChallenge));
}

std::vector<uint8_t>
SymmetricCryptoCardTransactionManagerAdapter::cipherPin(
    const std::vector<uint8_t>& cardChallenge,
    const std::vector<uint8_t>& currentPin,
    const std::vector<uint8_t>& newPin,
    const std::shared_ptr<uint8_t> kif,
    const std::shared_ptr<uint8_t> kvc)
{
    uint8_t pinCipheringKif;
    uint8_t pinCipheringKvc;

    if (mDigestManager && mDigestManager->mSessionKif != 0) {
        /* The current work key has been set (a secure session is open) */
        pinCipheringKif = mDigestManager->mSessionKif;
        pinCipheringKvc = mDigestManager->mSessionKvc;

    } else {
        /* No current work key is available (outside secure session) */
        if (kif == nullptr || kvc == nullptr) {
            std::string msg = newPin.empty() ? "verification" : "modification";
            throw IllegalStateException(
                "No KIF or KVC defined for the PIN " + msg + " ciphering key");
        }
        pinCipheringKif = *kif;
        pinCipheringKvc = *kvc;
    }

    prepareGiveRandom(cardChallenge);

    /* An empty new PIN means a verification, which has its own constructor
     * setting P1 to 80h; the modification one sets 40h and rejects it. */
    std::shared_ptr<CommandCardCipherPin> cmd;
    if (newPin.empty()) {
        cmd = std::make_shared<CommandCardCipherPin>(
            getContext(), pinCipheringKif, pinCipheringKvc, currentPin);

    } else {
        cmd = std::make_shared<CommandCardCipherPin>(
            getContext(), pinCipheringKif, pinCipheringKvc, currentPin, newPin);
    }
    mSamCommands.push_back(cmd);

    processCommands();

    return cmd->getCipheredData();
}

void
SymmetricCryptoCardTransactionManagerAdapter::prepareSelectDiversifier()
{
    mSamCommands.push_back(
        std::make_shared<CommandSelectDiversifier>(
            getContext(), mCurrentKeyDiversifier));
}

void
SymmetricCryptoCardTransactionManagerAdapter::prepareSelectDiversifierIfNeeded(
    const std::vector<uint8_t>& specificKeyDiversifier)
{
    if (!specificKeyDiversifier.empty()) {
        if (isSelectDiversifierNeeded(specificKeyDiversifier)) {
            prepareSelectDiversifier();
        }

    } else {
        prepareSelectDiversifierIfNeeded();
    }
}

void
SymmetricCryptoCardTransactionManagerAdapter::prepareSelectDiversifierIfNeeded()
{
    if (isSelectDiversifierNeeded(mCardKeyDiversifier)) {
        prepareSelectDiversifier();
    }
}

SymmetricCryptoCardTransactionManagerAdapter ::InvalidCardMacException::
    InvalidCardMacException(const std::string& message)
: RuntimeException(message)
{
}

SymmetricCryptoCardTransactionManagerAdapter::DigestManager::DigestManager(
    SymmetricCryptoCardTransactionManagerAdapter* parent,
    const std::vector<std::uint8_t>& openSecureSessionDataOut,
    std::uint8_t kif,
    std::uint8_t kvc)
: mSessionKif(kif)
, mSessionKvc(kvc)
, mParent(parent)
, mOpenSecureSessionDataOut(openSecureSessionDataOut)
{
}

void
SymmetricCryptoCardTransactionManagerAdapter::DigestManager::updateSession(
    const std::vector<std::uint8_t>& cardApdu)
{
    /*
     * If the request is of case4 type, LE must be excluded from the digest
     * computation. In this case, we remove here the last byte of the command
     * buffer.
     */

    /* CL-C4-MAC.1 */
    if (mIsRequest) {
        mCardApdus.push_back(
            ApduUtil::isCase4(cardApdu)
                ? Arrays::copyOfRange(cardApdu, 0, cardApdu.size() - 1)
                : cardApdu);
    } else {
        mCardApdus.push_back(cardApdu);
    }

    mIsRequest = !mIsRequest;
}

std::shared_ptr<CommandDigestUpdate>
SymmetricCryptoCardTransactionManagerAdapter ::DigestManager::
    prepareCommandForEncryption(const std::vector<std::uint8_t>& cardApdu)
{
    updateSession(cardApdu);

    /* Prepare the "Digest Update" commands and flush the buffer. */
    const std::vector<std::uint8_t> apdu = mCardApdus.front();
    mCardApdus.erase(mCardApdus.begin());

    auto command = std::make_shared<CommandDigestUpdate>(
        mParent->getContext(), true, apdu);

    mParent->mSamCommands.push_back(command);

    return command;
}

void
SymmetricCryptoCardTransactionManagerAdapter ::DigestManager::prepareCommands()
{
    /* Prepare the "Digest Init" command if not already done. */
    if (!mIsDigestInitDone) {
        prepareDigestInit();
    }

    /*
     * Prepare the "Digest Update" commands and flush the buffer.
     */
    prepareDigestUpdate();
    mCardApdus.clear();
}

void
SymmetricCryptoCardTransactionManagerAdapter ::DigestManager::
    prepareAllCommands()
{
    prepareCommands();

    /* Prepare the "Digest Close" command. */
    prepareDigestClose();
}

void
SymmetricCryptoCardTransactionManagerAdapter ::DigestManager::
    prepareDigestInit()
{
    if (mParent->mIsSelectDiversifierNeededOnDigestInit) {
        mParent->mSamCommands.insert(
            mParent->mSamCommands.begin(),
            std::make_shared<CommandSelectDiversifier>(
                mParent->getContext(), mParent->mCardKeyDiversifier));
    }

    /* CL-SAM-DINIT.1 */
    mParent->mSamCommands.insert(
        mParent->mSamCommands.begin() + 1,
        std::make_shared<CommandDigestInit>(
            mParent->getContext(),
            false,
            mParent->mIsExtendedModeRequired,
            mSessionKif,
            mSessionKvc,
            mOpenSecureSessionDataOut));
    mIsDigestInitDone = true;
}

void
SymmetricCryptoCardTransactionManagerAdapter ::DigestManager::
    prepareDigestUpdate()
{
    if (mCardApdus.empty()) {
        return;
    }

    /* CL-SAM-DUPDATE.1 */
    if (mParent->mSam->getProductType() == LegacySam::ProductType::SAM_C1) {
        /* Digest Update Multiple */
        std::vector<std::uint8_t> buffer(255);
        int i = 0;
        for (const auto& cardApdu : mCardApdus) {
            if (static_cast<int>(i + cardApdu.size() + 1)
                > mParent->mMaxCardApduLengthSupported) {
                /* Add command and reset buffer */
                if (i != 0) {
                    mParent->mSamCommands.push_back(
                        std::make_shared<CommandDigestUpdateMultiple>(
                            mParent->getContext(), Arrays::copyOf(buffer, i)));
                }
                i = 0;
            }

            if (static_cast<int>(cardApdu.size())
                != mParent->mMaxCardApduLengthSupported) {
                /* Add [length][apdu] to current buffer */
                buffer[i++] = cardApdu.size();
                System::arraycopy(cardApdu, 0, buffer, i, cardApdu.size());
                i += cardApdu.size();

            } else {
                /*
                 * Create a Digest Update (simple) when the command fills
                 * entirely the SAM buffer.
                 */
                mParent->mSamCommands.push_back(
                    std::make_shared<CommandDigestUpdate>(
                        mParent->getContext(), false, cardApdu));
            }
        }

        if (i != 0) {
            /* Add command */
            mParent->mSamCommands.push_back(
                std::make_shared<CommandDigestUpdateMultiple>(
                    mParent->getContext(), Arrays::copyOf(buffer, i)));
        }
    } else {
        /* Digest Update (simple) */
        for (const auto& cardApdu : mCardApdus) {
            mParent->mSamCommands.push_back(
                std::make_shared<CommandDigestUpdate>(
                    mParent->getContext(), false, cardApdu));
        }
    }
}

void
SymmetricCryptoCardTransactionManagerAdapter ::DigestManager::
    prepareDigestClose()
{
    /* CL-SAM-DCLOSE.1 */
    mParent->mSamCommands.push_back(
        std::make_shared<CommandDigestClose>(
            mParent->getContext(), mParent->mIsExtendedModeRequired ? 8 : 4));
}

} /* namespace legacysam */
} /* namespace crypto */
} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
