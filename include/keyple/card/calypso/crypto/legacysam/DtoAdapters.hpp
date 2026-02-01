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
#include <memory>
#include <set>
#include <string>
#include <vector>

#include "keyple/card/calypso/crypto/legacysam/LegacySamAdapter.hpp"
#include "keypop/calypso/crypto/legacysam/SystemKeyType.hpp"
#include "keypop/calypso/crypto/legacysam/spi/LegacySamRevocationServiceSpi.hpp"
#include "keypop/calypso/crypto/legacysam/transaction/BasicSignatureComputationData.hpp"
#include "keypop/calypso/crypto/legacysam/transaction/BasicSignatureVerificationData.hpp"
#include "keypop/calypso/crypto/legacysam/transaction/KeyPairContainer.hpp"
#include "keypop/calypso/crypto/legacysam/transaction/LegacyCardCertificateComputationData.hpp"
#include "keypop/calypso/crypto/legacysam/transaction/SamTraceabilityMode.hpp"
#include "keypop/calypso/crypto/legacysam/transaction/SignatureComputationData.hpp"
#include "keypop/calypso/crypto/legacysam/transaction/SignatureVerificationData.hpp"
#include "keypop/calypso/crypto/legacysam/transaction/TraceableSignatureComputationData.hpp"
#include "keypop/calypso/crypto/legacysam/transaction/TraceableSignatureVerificationData.hpp"
#include "keypop/card/ProxyReaderApi.hpp"
#include "keypop/card/spi/ApduRequestSpi.hpp"
#include "keypop/card/spi/CardRequestSpi.hpp"
#include "keypop/card/spi/CardSelectionRequestSpi.hpp"

namespace keyple {
namespace card {
namespace calypso {
namespace crypto {
namespace legacysam {

using keypop::calypso::crypto::legacysam::SystemKeyType;
using keypop::calypso::crypto::legacysam::spi::LegacySamRevocationServiceSpi;
using keypop::calypso::crypto::legacysam::transaction::
    BasicSignatureComputationData;
using keypop::calypso::crypto::legacysam::transaction::
    BasicSignatureVerificationData;
using keypop::calypso::crypto::legacysam::transaction::KeyPairContainer;
using keypop::calypso::crypto::legacysam::transaction::
    LegacyCardCertificateComputationData;
using keypop::calypso::crypto::legacysam::transaction::SamTraceabilityMode;
using keypop::calypso::crypto::legacysam::transaction::SignatureComputationData;
using keypop::calypso::crypto::legacysam::transaction::
    SignatureVerificationData;
using keypop::calypso::crypto::legacysam::transaction::
    TraceableSignatureComputationData;
using keypop::calypso::crypto::legacysam::transaction::
    TraceableSignatureVerificationData;
using keypop::card::ProxyReaderApi;
using keypop::card::spi::ApduRequestSpi;
using keypop::card::spi::CardRequestSpi;
using keypop::card::spi::CardSelectionRequestSpi;

/**
 * Contains all DTO adapters.
 *
 * @since 0.1.0
 */
class DtoAdapters final {
public:
    /**
     * Adapter of SignatureComputationData.
     *
     * @param <T> The type of the lowest level child object.
     * @since 0.1.0
     */
    template <typename T>
    class SignatureComputationDataAdapter
    : public virtual SignatureComputationData<T> {
    public:
        /**
         *
         */
        SignatureComputationDataAdapter();

        /**
         * {@inheritDoc}
         *
         * @since 0.1.0
         */
        T& setData(
            const std::vector<uint8_t>& data,
            const uint8_t kif,
            const uint8_t kvc) override;

        /**
         * {@inheritDoc}
         *
         * @since 0.1.0
         */
        T& setSignatureSize(const int size) override;

        /**
         * {@inheritDoc}
         *
         * @since 0.1.0
         */
        T& setKeyDiversifier(const std::vector<uint8_t>& diversifier) override;

        /**
         * {@inheritDoc}
         *
         * @since 0.1.0
         */
        const std::vector<uint8_t>& getSignature() const override;

        /**
         * @return A not empty array of data. It is required to check inpu data
         * first.
         * @since 0.1.0
         */
        const std::vector<uint8_t>& getData() const;

        /**
         * @return The KIF. It is required to check input data first.
         * @since 0.1.0
         */
        uint8_t getKif() const;

        /**
         * @return The KVC. It is required to check input data first.
         * @since 0.1.0
         */
        uint8_t getKvc() const;

        /**
         * @return The signature size.
         * @since 0.1.0
         */
        int getSignatureSize() const;

        /**
         * @return Empty if the key diversifier is not set.
         * @since 0.1.0
         */
        const std::vector<uint8_t> getKeyDiversifier() const;

        /**
         * Sets the computed signature.
         *
         * @param signature The computed signature.
         * @since 0.1.0
         */
        void setSignature(const std::vector<uint8_t>& signature);

    private:
        /**
         *
         */
        std::vector<uint8_t> mData;

        /**
         *
         */
        uint8_t mKif;

        /**
         *
         */
        uint8_t mKvc;

        /**
         *
         */
        int mSignatureSize;

        /**
         *
         */
        std::vector<uint8_t> mKeyDiversifier;

        /**
         *
         */
        std::vector<uint8_t> mSignature;
    };

    /**
     * Adapter of SignatureVerificationData.
     *
     * @param <T> The type of the lowest level child object.
     * @since 0.1.0
     */
    template <typename T>
    class SignatureVerificationDataAdapter
    : public virtual SignatureVerificationData<T> {
    public:
        /**
         *
         */
        SignatureVerificationDataAdapter();

        /**
         * {@inheritDoc}
         *
         * @since 0.1.0
         */
        T& setData(
            const std::vector<uint8_t>& data,
            const std::vector<uint8_t>& signature,
            uint8_t kif,
            uint8_t kvc) override;

        /**
         * {@inheritDoc}
         *
         * @since 0.1.0
         */
        T& setKeyDiversifier(const std::vector<uint8_t>& diversifier) override;

        /**
         * {@inheritDoc}
         *
         * @since 0.1.0
         */
        bool isSignatureValid() const override;

        /**
         * @return A not empty array of data. It is required to check input data
         * first.
         * @since 0.1.0
         */
        const std::vector<uint8_t>& getData() const;

        /**
         * @return A not empty array of the signature to check. It is required
         * to check input data first.
         * @since 0.1.0
         */
        const std::vector<uint8_t>& getSignature() const;

        /**
         * @return The KIF. It is required to check input data first.
         * @since 0.1.0
         */
        uint8_t getKif() const;

        /**
         * @return The KVC. It is required to check input data first.
         * @since 0.1.0
         */
        uint8_t getKvc() const;

        /**
         * @return Null if the key diversifier is not set.
         * @since 0.1.0
         */
        const std::vector<uint8_t> getKeyDiversifier() const;

        /**
         * Sets the signature verification status.
         *
         * @param isSignatureValid True if the signature is valid.
         * @since 0.1.0
         */
        void setSignatureValid(bool isSignatureValid);

    protected:
        /**
         *
         */
        SamTraceabilityMode mSamTraceabilityMode;

    private:
        /**
         *
         */
        std::vector<uint8_t> mData;

        /**
         *
         */
        std::vector<uint8_t> mSignature;

        /**
         *
         */
        uint8_t mKif;

        /**
         *
         */
        uint8_t mKvc;

        /**
         *
         */
        std::vector<uint8_t> mKeyDiversifier;

        /**
         *
         */
        bool mIsSignatureValid;

        /**
         *
         */
        bool mHasIsSignatureValid;
    };

    /**
     * Adapter of BasicSignatureComputationData.
     *
     * @since 0.1.0
     */
    class BasicSignatureComputationDataAdapter
    : public virtual SignatureComputationDataAdapter<
          BasicSignatureComputationData>,
      public virtual BasicSignatureComputationData { };

    /**
     * Adapter of BasicSignatureVerificationData.
     *
     * @since 0.1.0
     */
    class BasicSignatureVerificationDataAdapter
    : public virtual SignatureVerificationDataAdapter<
          BasicSignatureVerificationData>,
      public virtual BasicSignatureVerificationData { };

    /**
     * Adapter of TraceableSignatureComputationData.
     *
     * @since 0.1.0
     */
    class TraceableSignatureComputationDataAdapter final
    : public SignatureComputationDataAdapter<TraceableSignatureComputationData>,
      public TraceableSignatureComputationData {
    public:
        /**
         *
         */
        TraceableSignatureComputationDataAdapter();

        /**
         * {@inheritDoc}
         *
         * @since 0.1.0
         */
        TraceableSignatureComputationData& withSamTraceabilityMode(
            const int offset,
            const SamTraceabilityMode samTraceabilityMode) override;

        /**
         * {@inheritDoc}
         *
         * @since 0.1.0
         */
        TraceableSignatureComputationData& withoutBusyMode() override;

        /**
         * {@inheritDoc}
         *
         * @since 0.1.0
         */
        const std::vector<uint8_t>& getSignedData() const override;

        /**
         * @return True if the "SAM traceability" mode is enabled.
         * @since 0.1.0
         */
        bool isSamTraceabilityMode() const;

        /**
         * @return The offset associated to the "SAM traceability" mode. It is
         * required to check if the "SAM traceability" mode is enabled first.
         * @since 0.1.0
         */

        int getTraceabilityOffset() const;

        /**
         * @return the "SAM traceability" mode. It is required to check if the
         * "SAM traceability" mode is enabled first.
         * @since 0.1.0
         */
        SamTraceabilityMode getSamTraceabilityMode() const;

        /**
         * @return True if the "Busy" mode is enabled.
         * @since 0.1.0
         */
        bool isBusyMode() const;

        /**
         * Sets the data used for signature computation.
         *
         * @param signedData The signed data.
         * @since 0.1.0
         */
        void setSignedData(const std::vector<uint8_t>& signedData);

    private:
        /**
         *
         */
        bool mIsSamTraceabilityMode;

        /**
         *
         */
        int mTraceabilityOffset;

        /**
         *
         */
        bool mIsBusyMode;

        /**
         *
         */
        std::vector<uint8_t> mSignedData;

        /**
         *
         */
        SamTraceabilityMode mSamTraceabilityMode;
    };

    /**
     * Adapter of TraceableSignatureVerificationData.
     *
     * @since 0.1.0
     */
    class TraceableSignatureVerificationDataAdapter final
    : public SignatureVerificationDataAdapter<
          TraceableSignatureVerificationData>,
      public TraceableSignatureVerificationData {
    public:
        /**
         *
         */
        TraceableSignatureVerificationDataAdapter();

        /**
         * {@inheritDoc}
         *
         * @since 0.1.0
         */
        TraceableSignatureVerificationData& withSamTraceabilityMode(
            int offset,
            SamTraceabilityMode samTraceabilityMode,
            std::shared_ptr<LegacySamRevocationServiceSpi> samRevocationService)
            override;

        /**
         * {@inheritDoc}
         *
         * @since 0.1.0
         */
        TraceableSignatureVerificationData& withoutBusyMode() override;

        /**
         * @return True if the "SAM traceability" mode is enabled.
         * @since 0.1.0
         */
        bool isSamTraceabilityMode() const;

        /**
         * @return The offset associated to the "SAM traceability" mode. It is
         * required to check if the "SAM traceability" mode is enabled first.
         * @since 0.1.0
         */
        int getTraceabilityOffset() const;

        /**
         * @return the "SAM traceability" mode. It is required to check if the
         * "SAM traceability" mode is enabled first.
         * @since 0.1.0
         */
        SamTraceabilityMode getSamTraceabilityMode() const;

        /**
         * @return The SAM revocation service or null if the verification of the
         * SAM revocation status is not requested. It is required to check if
         * the "SAM traceability" mode is enabled first.
         * @since 0.1.0
         */
        std::shared_ptr<LegacySamRevocationServiceSpi>
        getSamRevocationService() const;

        /**
         * @return True if the "Busy" mode is enabled.
         * @since 0.1.0
         */
        bool isBusyMode() const;

    private:
        /**
         *
         */
        bool mIsSamTraceabilityMode;

        /**
         *
         */
        int mTraceabilityOffset;

        /**
         *
         */
        std::shared_ptr<LegacySamRevocationServiceSpi> mSamRevocationService;

        /**
         *
         */
        bool mIsBusyMode;
    };

    /**
     * This POJO contains a set of data related to an ISO-7816 APDU command.
     *
     * @since 0.1.0
     */
    class ApduRequestAdapter final : public ApduRequestSpi {
    public:
        /**
         * Builds an APDU request from a raw byte buffer.
         *
         * <p>The default status words list is initialized with the standard
         * successful code 9000h.
         *
         * @param apdu The bytes of the APDU's body.
         * @since 0.1.0
         */
        explicit ApduRequestAdapter(const std::vector<uint8_t>& apdu);

        /**
         * Adds a status word to the list of those that should be considered
         * successful for the APDU.
         *
         * <p>Note: initially, the list contains the standard successful status
         * word {@code 9000h}.
         *
         * @param successfulStatusWord A positive int &le; {@code FFFFh}.
         * @return The object instance.
         * @since 0.1.0
         */
        ApduRequestAdapter& addSuccessfulStatusWord(int successfulStatusWord);

        /**
         * {@inheritDoc}
         *
         * @since 0.1.0
         */
        const std::vector<int>& getSuccessfulStatusWords() const override;

        /**
         * Names the APDU request.
         *
         * <p>This string is dedicated to improve the readability of logs and
         * should therefore only be invoked conditionally (e.g. when log level
         * &gt;= debug).
         *
         * @param info The request name (free text).
         * @return The object instance.
         * @since 0.1.0
         */
        ApduRequestAdapter& setInfo(const std::string& info);

        /**
         * {@inheritDoc}
         *
         * @since 0.1.0
         */
        const std::string& getInfo() const override;

        /**
         * {@inheritDoc}
         *
         * @since 0.1.0
         */
        const std::vector<uint8_t>& getApdu() const override;

        /**
         * {@inheritDoc}
         *
         * @since 0.1.0
         */
        void setApdu(const std::vector<std::uint8_t>& apdu) override;

        /**
         *
         */
        friend std::ostream&
        operator<<(
            std::ostream& os, const std::shared_ptr<ApduRequestAdapter> ara)
        {
            os << "APDU_REQUEST: "
               << std::dynamic_pointer_cast<ApduRequestSpi>(ara);

            return os;
        }

    private:
        /**
         *
         */
        std::vector<uint8_t> mApdu;

        /**
         *
         */
        std::vector<int> mSuccessfulStatusWords;

        /**
         *
         */
        std::string mInfo;
    };

    /**
     * This POJO contains an ordered list of ApduRequestSpiand the associated
     * status code check policy.
     *
     * @since 0.1.0
     */
    class CardRequestAdapter final : public CardRequestSpi {
    public:
        /**
         * Builds a card request with a list of ApduRequestSpi and the flag
         * indicating the expected response checking behavior.
         *
         * <p>When the status code verification is enabled, the transmission of
         * the APDUs must be interrupted as soon as the status code of a
         * response is unexpected.
         *
         * @param apduRequests A not empty list.
         * @param stopOnUnsuccessfulStatusWord true or false.
         * @since 0.1.0
         */
        CardRequestAdapter(
            const std::vector<std::shared_ptr<ApduRequestSpi>>& apduRequests,
            bool stopOnUnsuccessfulStatusWord);

        /**
         * {@inheritDoc}
         *
         * @since 0.1.0
         */
        const std::vector<std::shared_ptr<ApduRequestSpi>>&
        getApduRequests() const override;

        /**
         * {@inheritDoc}
         *
         * @since 0.1.0
         */
        bool stopOnUnsuccessfulStatusWord() const override;

        /**
         *
         */
        friend std::ostream&
        operator<<(
            std::ostream& os, const std::shared_ptr<CardRequestAdapter> cra)
        {
            os << "CARD_REQUEST: "
               << std::dynamic_pointer_cast<CardRequestSpi>(cra);

            return os;
        }

    private:
        /**
         *
         */
        std::vector<std::shared_ptr<ApduRequestSpi>> mApduRequests;

        /**
         *
         */
        bool mStopOnUnsuccessfulStatusWord;
    };

    /**
     * This POJO contains the data used to define a selection extension
     * containing additional APDU commands to be sent to the card when the
     * selection is successful.
     *
     * @since 0.1.0
     */
    class CardSelectionRequestAdapter final : public CardSelectionRequestSpi {
    public:
        /**
         * Builds a card selection request to open a logical channel with
         * additional APDUs to be sent after the selection step.
         *
         * @param cardRequest The card request.
         * @since 0.1.0
         */
        explicit CardSelectionRequestAdapter(
            std::shared_ptr<CardRequestSpi> cardRequest);

        /**
         * {@inheritDoc}
         *
         * @since 0.1.0
         */
        const std::vector<int>&
        getSuccessfulSelectionStatusWords() const override;

        /**
         * {@inheritDoc}
         *
         * @since 0.1.0
         */
        const std::shared_ptr<CardRequestSpi> getCardRequest() const override;

        /**
         *
         */
        friend std::ostream&
        operator<<(
            std::ostream& os,
            const std::shared_ptr<CardSelectionRequestAdapter> csra)
        {
            os << "CARD_SELECTION_REQUEST: "
               << std::dynamic_pointer_cast<CardRequestSpi>(csra);

            return os;
        }

    private:
        /**
         *
         */
        static const int DEFAULT_SUCCESSFUL_CODE;
        /**
         *
         */
        std::shared_ptr<CardRequestSpi> mCardRequest;

        /**
         *
         */
        std::vector<int> mSuccessfulSelectionStatusWords;
    };

    /**
     * This POJO contains the target SAM context data used when doing
     * asynchronous transactions.
     *
     * @since 0.3.0
     */
    class TargetSamContextDto final {
    public:
        /**
         * Constructs a new instance with the specified serial number and
         * dynamic mode flag.
         *
         * @param serialNumber The serial number of the target SAM.
         * @param isDynamicMode A boolean indicating whether the target SAM is
         * operating in dynamic mode.
         * @since 0.3.0
         */
        TargetSamContextDto(
            const std::vector<uint8_t>& serialNumber, bool isDynamicMode);

        /**
         * Returns the serial number of the target SAM.
         *
         * @return a byte array containing the serial number of the target SAM.
         * @since 0.3.0
         */
        const std::vector<uint8_t>& getSerialNumber() const;

        /**
         * Returns a boolean indicating whether the target SAM is operating in
         * dynamic mode.
         *
         * @return True if the target SAM is operating in dynamic mode,
         * otherwise false.
         * @since 0.3.0
         */
        bool isDynamicMode() const;

        /**
         * Returns a map containing the system key types and their corresponding
         * counter numbers
         *
         * @return A map.
         * @since 0.3.0
         */
        std::map<SystemKeyType, int>& getSystemKeyTypeToCounterNumberMap();

        /**
         * Returns a map containing the system key types and their corresponding
         * KVCs.
         *
         * @return A map.
         * @since 0.3.0
         */
        std::map<SystemKeyType, uint8_t>& getSystemKeyTypeToKvcMap();

        /**
         * Returns a map containing the counter numbers and their corresponding
         * counter values.
         *
         * @return A map.
         * @since 0.3.0
         */
        std::map<int, int>& getCounterNumberToCounterValueMap();

    private:
        /**
         *
         */
        std::vector<uint8_t> mSerialNumber;

        /**
         *
         */
        bool mIsDynamicMode;

        /**
         *
         */
        std::map<SystemKeyType, int> mSystemKeyTypeToCounterNumberMap;

        /**
         *
         */
        std::map<SystemKeyType, uint8_t> mSystemKeyTypeToKvcMap;

        /**
         *
         */
        std::map<int, int> mCounterNumberToCounterValueMap;
    };

    /**
     * This POJO contains the command context for a SAM transaction and its
     * related SAM commands.
     *
     * @since 0.3.0
     */
    class CommandContextDto final {
    public:
        /**
         * Constructs a new instance with the specified target SAM, control SAM
         * reader and control SAM.
         *
         * @param targetSam The target legacy SAM.
         * @param controlSamReader The reader through which the control SAM
         * communicates.
         * @param controlSam The control legacy SAM.
         * @since 0.3.0

         */
        CommandContextDto(
            std::shared_ptr<LegacySamAdapter> targetSam,
            std::shared_ptr<ProxyReaderApi> controlSamReader,
            std::shared_ptr<LegacySamAdapter> controlSam);

        /**
         * @return The target SAM.
         * @since 0.3.0
         */
        std::shared_ptr<LegacySamAdapter> getTargetSam() const;

        /**
         * @return The control SAM reader.
         * @since 0.3.0
         */
        std::shared_ptr<ProxyReaderApi> getControlSamReader() const;

        /**
         * @return The control SAM.
         * @since 0.3.0
         */
        std::shared_ptr<LegacySamAdapter> getControlSam() const;

    private:
        /**
         *
         */
        std::shared_ptr<LegacySamAdapter> mTargetSam;

        /**
         *
         */
        std::shared_ptr<ProxyReaderApi> mControlSamReader;

        /**
         *
         */
        std::shared_ptr<LegacySamAdapter> mControlSam;
    };

    /**
     * This POJO contains an ECC key pair generated by the SAM.
     *
     * @since 0.6.0
     */
    class KeyPairContainerAdapter final : public KeyPairContainer {
    public:
        /**
         * {@inheritDoc}
         *
         * @since 0.6.0
         */
        const std::vector<uint8_t>& getKeyPair() const override;

        /**
         * Sets the key pair value.
         *
         * @param keyPair A 96-byte byte array.
         * @since 0.6.0
         */
        void setKeyPair(const std::vector<uint8_t>& keyPair);

    private:
        /**
         *
         */
        std::vector<uint8_t> mKeyPair;
    };

    /**
     * This POJO contains all data expected by the SAM to compute a card
     * certificate.
     *
     * @since 0.6.0
     */
    class LegacyCardCertificateComputationDataAdapter final
    : public LegacyCardCertificateComputationData {
    public:
        /**
         *
         */
        LegacyCardCertificateComputationDataAdapter();

        /**
         * {@inheritDoc}
         *
         * @since 0.6.0
         */
        LegacyCardCertificateComputationData&
        setCardPublicKey(const std::vector<uint8_t>& cardPublicKey) override;

        /**
         * {@inheritDoc}
         *
         * @since 0.6.0
         */
        LegacyCardCertificateComputationData&
        setStartDate(const tm& startDate) override;

        /**
         * {@inheritDoc}
         *
         * @since 0.6.0
         */
        LegacyCardCertificateComputationData&
        setEndDate(const tm& endDate) override;

        /**
         * {@inheritDoc}
         *
         * @since 0.6.0
         */
        LegacyCardCertificateComputationData&
        setCardAid(const std::vector<uint8_t>& aid) override;

        /**
         * {@inheritDoc}
         *
         * @since 0.6.0
         */
        LegacyCardCertificateComputationData&
        setCardSerialNumber(const std::vector<uint8_t>& serialNumber) override;

        /**
         * {@inheritDoc}
         *
         * @since 0.6.0
         */
        LegacyCardCertificateComputationData&
        setCardStartupInfo(const std::vector<uint8_t>& startupInfo) override;

        /**
         * @return The computed certificate.
         * @since 0.6.0
         */

        const std::vector<uint8_t>& getCertificate() const override;

        /**
         * Sets the computed certificate.
         *
         * @param cardCertificate A 316-byte byte array.
         * @since 0.6.0
         */
        void setCertificate(const std::vector<uint8_t>& cardCertificate);

        /**
         * @return The card's public key or null if the key is not set.
         * @since 0.6.0
         */
        const std::vector<uint8_t>& getCardPublicKey() const;

        /**
         * @return The start date in BCD format.
         * @since 0.6.0
         */
        uint32_t getStartDateBcd() const;

        /**
         * @return The end date in BCD format.
         * @since 0.6.0
         */
        uint32_t getEndDateBcd() const;

        /**
         * @return The card AID.
         * @since 0.6.0
         */
        const std::vector<uint8_t>& getAid() const;

        /**
         * @return The card serial number.
         * @since 0.6.0
         */
        const std::vector<uint8_t>& getSerialNumber() const;

        /**
         * @return The card startup information.
         * @since 0.6.0
         */
        const std::vector<uint8_t>& getStartupInfo() const;

    private:
        /**
         *
         */
        std::vector<uint8_t> mCardPublicKey;

        /**
         *
         */
        uint32_t mStartDateBcd;

        /**
         *
         */
        uint32_t mEndDateBcd;

        /**
         *
         */
        std::vector<uint8_t> mAid;

        /**
         *
         */
        std::vector<uint8_t> mSerialNumber;

        /**
         *
         */
        std::vector<uint8_t> mStartupInfo;

        /**
         *
         */
        std::vector<uint8_t> mCertificate;
    };

private:
    /**
     *
     */
    static const std::string MSG_THE_COMMAND_HAS_NOT_YET_BEEN_PROCESSED;

    /**
     *
     */
    DtoAdapters();
};

} /* namespace legacysam */
} /* namespace crypto */
} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
