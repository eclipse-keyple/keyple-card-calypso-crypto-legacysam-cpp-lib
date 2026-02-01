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

#include "keyple/card/calypso/crypto/legacysam/CommandDigestUpdate.hpp"
#include "keyple/card/calypso/crypto/legacysam/LegacySamAdapter.hpp"
#include "keyple/core/util/cpp/exception/RuntimeException.hpp"
#include "keypop/calypso/crypto/legacysam/transaction/CardTransactionLegacySamExtension.hpp"
#include "keypop/calypso/crypto/legacysam/transaction/SignatureComputationDataBase.hpp"
#include "keypop/calypso/crypto/legacysam/transaction/SignatureVerificationDataBase.hpp"
#include "keypop/calypso/crypto/symmetric/SvCommandSecurityDataApi.hpp"
#include "keypop/calypso/crypto/symmetric/spi/SymmetricCryptoCardTransactionManagerSpi.hpp"

namespace keyple {
namespace card {
namespace calypso {
namespace crypto {
namespace legacysam {

using keyple::core::util::cpp::exception::RuntimeException;
using keypop::calypso::crypto::legacysam::transaction::
    CardTransactionLegacySamExtension;
using keypop::calypso::crypto::legacysam::transaction::
    SignatureComputationDataBase;
using keypop::calypso::crypto::legacysam::transaction::
    SignatureVerificationDataBase;
using keypop::calypso::crypto::symmetric::SvCommandSecurityDataApi;
using keypop::calypso::crypto::symmetric::spi::
    SymmetricCryptoCardTransactionManagerSpi;

/**
 * Adapter of SymmetricCryptoCardTransactionManagerSpi and
 * CardTransactionLegacySamExtension.
 *
 * @since 2.3.1
 */
class SymmetricCryptoCardTransactionManagerAdapter final
: public SymmetricCryptoCardTransactionManagerSpi,
  public CardTransactionLegacySamExtension {
public:
    /**
     * Creates an instance of CardTransactionLegacySamExtension.
     *
     * @param samReader The reader through which the SAM communicates.
     * @param sam The initial SAM data provided by the selection process.
     * @param cardKeyDiversifier The diversifier to use for card related
     * computations.
     * @param useExtendedMode True if the extended mode should be used.
     * @param maxCardApduLengthSupported The maximum length, in bytes, that a
     * single APDU command sent to the SAM can contain.
     * @since 2.0.0
     */
    SymmetricCryptoCardTransactionManagerAdapter(
        std::shared_ptr<ProxyReaderApi> samReader,
        std::shared_ptr<LegacySamAdapter> sam,
        const std::vector<uint8_t>& cardKeyDiversifier,
        bool useExtendedMode,
        int maxCardApduLengthSupported,
        const std::vector<std::vector<uint8_t>>& transactionAuditData);

    /**
     * {@inheritDoc}
     *
     * @since 2.3.1
     */
    std::vector<uint8_t> initTerminalSecureSessionContext() override;

    /**
     * {@inheritDoc}
     *
     * @since 2.3.1
     */
    void initTerminalSessionMac(
        const std::vector<uint8_t>& openSecureSessionDataOut,
        uint8_t kif,
        uint8_t kvc) override;

    /**
     * {@inheritDoc}
     *
     * @since 2.3.1
     */
    std::vector<uint8_t>
    updateTerminalSessionMac(const std::vector<uint8_t>& cardApdu) override;

    /**
     * {@inheritDoc}
     *
     * @since 2.3.1
     */
    std::vector<uint8_t> finalizeTerminalSessionMac() override;

    /**
     * {@inheritDoc}
     *
     * @since 2.3.1
     */
    std::vector<uint8_t> generateTerminalSessionMac() override;

    /**
     * {@inheritDoc}
     *
     * @since 2.3.1
     */
    void activateEncryption() override;

    /**
     * {@inheritDoc}
     *
     * @since 2.3.1
     */
    void deactivateEncryption() override;

    /**
     * {@inheritDoc}
     *
     * @since 2.3.1
     */
    bool
    isCardSessionMacValid(const std::vector<uint8_t>& cardSessionMac) override;

    /**
     * {@inheritDoc}
     *
     * @since 2.3.1
     */
    void computeSvCommandSecurityData(
        std::shared_ptr<SvCommandSecurityDataApi> svCommandSecurityData)
        override;

    /**
     * {@inheritDoc}
     *
     * @since 2.3.1
     */
    bool isCardSvMacValid(const std::vector<uint8_t>& cardSvMac) override;

    /**
     * {@inheritDoc}
     *
     * @since 2.3.1
     */
    std::vector<uint8_t> cipherPinForPresentation(
        const std::vector<uint8_t>& cardChallenge,
        const std::vector<uint8_t>& pin,
        const std::shared_ptr<uint8_t> kif,
        const std::shared_ptr<uint8_t> kvc) override;

    /**
     * {@inheritDoc}
     *
     * @since 2.3.1
     */
    std::vector<uint8_t> cipherPinForModification(
        const std::vector<uint8_t>& cardChallenge,
        const std::vector<uint8_t>& currentPin,
        const std::vector<uint8_t>& newPin,
        const std::shared_ptr<uint8_t> kif,
        const std::shared_ptr<uint8_t> kvc) override;

    /**
     * {@inheritDoc}
     *
     * @since 2.3.1
     */
    std::vector<uint8_t> generateCipheredCardKey(
        const std::vector<uint8_t>& cardChallenge,
        uint8_t issuerKeyKif,
        uint8_t issuerKeyKvc,
        uint8_t targetKeyKif,
        uint8_t targetKeyKvc) override;

    /**
     * {@inheritDoc}
     *
     * @since 2.3.1
     */
    void synchronize() override;

    /**
     * {@inheritDoc}
     *
     * @since 0.4.0
     */
    CardTransactionLegacySamExtension& prepareComputeSignature(
        std::shared_ptr<SignatureComputationDataBase> data) override;

    /**
     * {@inheritDoc}
     *
     * @since 0.4.0
     */
    CardTransactionLegacySamExtension& prepareVerifySignature(
        std::shared_ptr<SignatureVerificationDataBase> data) override;

    /**
     *
     */
    class InvalidCardMacException final : public RuntimeException {
    public:
        /**
         *
         */
        explicit InvalidCardMacException(const std::string& message);
    };

private:
    /**
     * The manager of the digest session.
     */
    class DigestManager {
    public:
        /**
         *
         */
        bool mIsRequest = true;

        /**
         *
         */
        bool mIsDigestInitDone;

        /**
         *
         */
        const std::uint8_t mSessionKif;

        /**
         *
         */
        const std::uint8_t mSessionKvc;

        /**
         * Creates a new digest manager.
         *
         * @param parent The outer class.
         * @param openSecureSessionDataOut The data out of the "Open Secure
         * Session" card command.
         * @param kif The KIF to use.
         * @param kvc The KVC to use.
         */
        DigestManager(
            SymmetricCryptoCardTransactionManagerAdapter* parent,
            const std::vector<std::uint8_t>& openSecureSessionDataOut,
            std::uint8_t kif,
            std::uint8_t kvc);

        /**
         * Prepares all intermediate digest commands.
         */
        void prepareCommands();

        /**
         * Prepares a digest update command for encryption mode.
         *
         * @param cardApdu The card APDU.
         */
        std::shared_ptr<CommandDigestUpdate>
        prepareCommandForEncryption(const std::vector<std::uint8_t>& cardApdu);

        /**
         * Add one or more exchanged card APDUs to the buffer.
         *
         * @param cardApdu The APDU.
         */
        void updateSession(const std::vector<std::uint8_t>& cardApdu);

        /**
         * Prepares all pending digest commands.
         */
        void prepareAllCommands();

        /**
         * Prepares the "Digest Init" SAM command.
         */
        void prepareDigestInit();

    private:
        /**
         *
         */
        SymmetricCryptoCardTransactionManagerAdapter* mParent;

        /**
         *
         */
        const std::vector<std::uint8_t> mOpenSecureSessionDataOut;

        /**
         *
         */
        std::vector<std::vector<std::uint8_t>> mCardApdus;

        /**
         * Prepares the "Digest Update" SAM command.
         */
        void prepareDigestUpdate();

        /**
         * Prepares the "Digest Close" SAM command.
         */
        void prepareDigestClose();
    };

    /**
     *
     */
    static const std::string MSG_SAM_INCONSISTENT_DATA;
    static const std::string MSG_SAM_NB_RESPONSES;
    static const std::string MSG_INPUT_OUTPUT_DATA;
    static const std::string MSG_SIGNATURE_SIZE;
    static const std::string MSG_KEY_DIVERSIFIER_SIZE_IS_IN_RANGE_1_8;

    /**
     *
     */
    std::shared_ptr<ProxyReaderApi> mSamReader;

    /**
     *
     */
    std::shared_ptr<LegacySamAdapter> mSam;

    /**
     *
     */
    std::vector<uint8_t> mCardKeyDiversifier;

    /**
     *
     */
    bool mIsExtendedModeRequired;

    /**
     *
     */
    int mMaxCardApduLengthSupported;

    /**
     *
     */
    std::vector<std::vector<uint8_t>> mTransactionAuditData;

    /**
     *
     */
    std::vector<std::shared_ptr<Command>> mSamCommands;

    /**
     *
     */
    std::vector<uint8_t> mCurrentKeyDiversifier;

    /**
     *
     */
    std::shared_ptr<DigestManager> mDigestManager;

    /**
     *
     */
    bool mIsEncryptionActive;

    /**
     *
     */
    bool mIsSelectDiversifierNeededOnDigestInit;

    /**
     * Gets the command context.
     *
     * @return An instance of {@link DtoAdapters.CommandContextDto}.
     * @since 0.3.0
     */
    std::shared_ptr<DtoAdapters::CommandContextDto> getContext();

    /**
     * @param keyDiversifier The key diversifier to use.
     * @return true if the current key diversifier has changed and therefore a
     * "Select Diversifier" command is needed.
     */
    bool isSelectDiversifierNeeded(const std::vector<uint8_t>& keyDiversifier);

    /**
     *
     */
    void processCommands();

    /**
     *
     */
    void prepareGiveRandom(const std::vector<uint8_t>& cardChallenge);

    /**
     *
     */
    std::vector<uint8_t> cipherPin(
        const std::vector<uint8_t>& cardChallenge,
        const std::vector<uint8_t>& currentPin,
        const std::vector<uint8_t>& newPin,
        const std::shared_ptr<uint8_t> kif,
        const std::shared_ptr<uint8_t> kvc);

    /**
     *
     */
    void prepareSelectDiversifier();

    /**
     *
     */
    void prepareSelectDiversifierIfNeeded(
        const std::vector<uint8_t>& specificKeyDiversifier);

    /**
     *
     */
    void prepareSelectDiversifierIfNeeded();
};

} /* namespace legacysam */
} /* namespace crypto */
} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
