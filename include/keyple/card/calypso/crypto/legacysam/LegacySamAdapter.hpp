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
#include <optional>
#include <string>
#include <vector>

#include "keyple/card/calypso/crypto/legacysam/KeyParameterAdapter.hpp"
#include "keyple/card/calypso/crypto/legacysam/SamParametersAdapter.hpp"
#include "keypop/calypso/crypto/legacysam/CounterIncrementAccess.hpp"
#include "keypop/calypso/crypto/legacysam/SystemKeyType.hpp"
#include "keypop/calypso/crypto/legacysam/sam/LegacySam.hpp"
#include "keypop/calypso/crypto/legacysam/sam/SamParameters.hpp"
#include "keypop/card/CardSelectionResponseApi.hpp"
#include "keypop/card/spi/SmartCardSpi.hpp"

namespace keyple {
namespace card {
namespace calypso {
namespace crypto {
namespace legacysam {

using keypop::calypso::crypto::legacysam::CounterIncrementAccess;
using keypop::calypso::crypto::legacysam::SystemKeyType;
using keypop::calypso::crypto::legacysam::sam::LegacySam;
using keypop::calypso::crypto::legacysam::sam::SamParameters;
using keypop::card::CardSelectionResponseApi;
using keypop::card::spi::SmartCardSpi;

using ProductType = LegacySam::ProductType;

/**
 * Adapter of LegacySam.
 *
 * @since 0.1.0
 */
class LegacySamAdapter final : public LegacySam, public SmartCardSpi {
public:
    /**
     * @brief Constructs a LegacySamAdapter from a product type.
     * @param productType The SAM product type.
     * @since 0.4.0
     */
    explicit LegacySamAdapter(ProductType productType);

    /**
     * @brief Constructs a LegacySamAdapter from a card selection response.
     * @param cardSelectionResponse The response to the selection command.
     * @since 0.1.0
     */
    explicit LegacySamAdapter(
        std::shared_ptr<CardSelectionResponseApi> cardSelectionResponse);

    /**
     * Parses the selection response in order to determine all the SAM
     * attributes from the power-on data.
     *
     * @param cardSelectionResponse the response to the selection command.
     * @since 0.4.0
     */
    void parseSelectionResponse(
        std::shared_ptr<CardSelectionResponseApi> cardSelectionResponse);

    /**
     * Gets the class byte to use for the current product type.
     *
     * @return A byte.
     * @since 0.1.0
     */
    uint8_t getClassByte() const;

    /**
     * Gets the maximum length allowed for digest commands.
     *
     * @return An positive int.
     * @since 0.1.0
     */
    int getMaxDigestDataLength() const;

    /**
     * {@inheritDoc}
     *
     * @since 0.1.0
     */
    const std::string& getPowerOnData() const override;

    /**
     * {@inheritDoc}
     *
     * @since 0.1.0
     */
    ProductType getProductType() const override;

    /**
     * {@inheritDoc}
     *
     * @since 0.1.0
     */
    std::string getProductInfo() const override;

    /**
     * {@inheritDoc}
     *
     * @since 0.1.0
     */
    const std::vector<uint8_t>& getSerialNumber() const override;

    /**
     * {@inheritDoc}
     *
     * @since 0.1.0
     */
    uint8_t getPlatform() const override;

    /**
     * {@inheritDoc}
     *
     * @since 0.1.0
     */
    uint8_t getApplicationType() const override;

    /**
     * {@inheritDoc}
     *
     * @since 0.1.0
     */
    uint8_t getApplicationSubType() const override;

    /**
     * {@inheritDoc}
     *
     * @since 0.1.0
     */
    uint8_t getSoftwareIssuer() const override;

    /**
     * {@inheritDoc}
     *
     * @since 0.1.0
     */
    uint8_t getSoftwareVersion() const override;

    /**
     * {@inheritDoc}
     *
     * @since 0.1.0
     */
    uint8_t getSoftwareRevision() const override;

    /**
     * Adds or replace a counter value.
     *
     * @param counterNumber The number of the counter.
     * @param value The counter value.
     * @since 0.1.0
     */
    void putCounterValue(int counterNumber, int value);

    /**
     * Adds or replace a counter ceiling value.
     *
     * @param counterNumber The number of the counter.
     * @param value The counter ceiling value.
     * @since 0.1.0
     */
    void putCounterCeilingValue(int counterNumber, int value);

    /**
     * Adds or replace a counter increment configuration.
     *
     * @param counterNumber The number of the counter.
     * @param counterIncrementAccess The counter incrementing access.
     * @since 0.3.0
     */
    void putCounterIncrementConfiguration(
        int counterNumber, CounterIncrementAccess counterIncrementAccess);

    /**
     * {@inheritDoc}
     *
     * @since 0.1.0
     */
    std::shared_ptr<int> getCounter(int counterNumber) const override;

    /**
     * {@inheritDoc}
     *
     * @since 0.1.0
     */
    const std::map<const int, int>& getCounters() const override;

    /**
     * {@inheritDoc}
     *
     * @since 0.3.0
     */
    CounterIncrementAccess
    getCounterIncrementAccess(int counterNumber) const override;

    /**
     * {@inheritDoc}
     *
     * @since 0.1.0
     */
    std::shared_ptr<int> getCounterCeiling(int counterNumber) const override;

    /**
     * {@inheritDoc}
     *
     * @since 0.1.0
     */
    const std::map<const int, int>& getCounterCeilings() const override;

    /**
     * {@inheritDoc}
     *
     * @since 0.6.0
     */
    const std::vector<uint8_t>& getCaCertificate() const override;

    /**
     * {@inheritDoc}
     *
     * @since 0.9.0
     */
    std::shared_ptr<SamParameters> getSamParameters() const override;

    /**
     * Set the SAM parameters.
     *
     * @param samParameters The SamParametersAdapter.
     * @since 0.9.0
     */
    void setSamParameters(std::shared_ptr<SamParametersAdapter> samParameters);

    /**
     * Set the KeyParameter for specified SystemKeyType.
     *
     * @param systemKeyType The system key type.
     * @param keyParameter The KeyParameterAdapter.
     * @since 0.3.0
     */
    void setSystemKeyParameter(
        SystemKeyType systemKeyType,
        std::shared_ptr<KeyParameterAdapter> keyParameter);

    /**
     * {@inheritDoc}
     *
     * @since 0.3.0
     */
    std::shared_ptr<KeyParameter>
    getSystemKeyParameter(SystemKeyType systemKeyType) const override;

    /**
     * Set the KeyParameter for a work key identified by its record number.
     *
     * @param recordNumber The key record number.
     * @param keyParameter The KeyParameterAdapter.
     * @since 0.9.0
     */
    void setWorkKeyParameter(
        const int recordNumber,
        std::shared_ptr<KeyParameterAdapter> keyParameter);

    /**
     * Set the KeyParameter for a work key identified by its KIF/KVC.
     *
     * @param kifKvc The combined KIF/KVC of the key.
     * @param keyParameter The KeyParameterAdapter.
     * @since 0.9.0
     */
    void setWorkKeyParameter(
        const uint16_t kifKvc,
        const std::shared_ptr<KeyParameterAdapter> keyParameter);

    /**
     * {@inheritDoc}
     *
     * @since 0.9.0
     */
    std::shared_ptr<KeyParameter>
    getWorkKeyParameter(const int recordNumber) const override;

    /**
     * {@inheritDoc}
     *
     * @since 0.9.0
     */
    std::shared_ptr<KeyParameter>
    getWorkKeyParameter(const uint8_t kif, const uint8_t kvc) const override;

    /**
     * Gets the object content as a Json string.
     *
     * @return A not empty string.
     * @since 0.1.0
     */
    std::string toString() const;

    /**
     * Sets the challenge.
     *
     * @since 0.3.0
     */
    void setChallenge(std::vector<uint8_t> challenge);

    /**
     * Gets and resets the current challenge.
     *
     * @return Null if no challenge is available.
     * @since 0.4.0
     */
    std::vector<uint8_t> popChallenge();

    /**
     * Sets the CA certificate retrieved from the SAM.
     *
     * @param caCertificate The 384 bytes of the CA certificate.
     * @since 0.6.0
     */
    void setCaCertificate(std::vector<uint8_t> caCertificate);

private:
    /**
     *
     */
    static uint8_t computeClassByte(ProductType productType);

    /**
     *
     */
    std::string mPowerOnData;

    /**
     *
     */
    ProductType mSamProductType;

    /**
     *
     */
    std::vector<uint8_t> mSerialNumber;

    /**
     *
     */
    uint8_t mPlatform;

    /**
     *
     */
    uint8_t mApplicationType;

    /**
     *
     */
    uint8_t mApplicationSubType;

    /**
     *
     */
    uint8_t mSoftwareIssuer;

    /**
     *
     */
    uint8_t mSoftwareVersion;

    /**
     *
     */
    uint8_t mSoftwareRevision;

    /**
     *
     */
    uint8_t mClassByte;

    /**
     *
     */
    std::map<const int, int> mCounters;

    /**
     *
     */
    std::map<int, CounterIncrementAccess> mCountersIncrementConfig;

    /**
     *
     */
    std::map<const int, int> mCounterCeilings;

    /**
     *
     */
    std::map<SystemKeyType, std::shared_ptr<KeyParameterAdapter>>
        mSystemKeyParameterMap;

    /**
     *
     */
    std::map<int, std::shared_ptr<KeyParameterAdapter>>
        mWorkKeyParameterByRecordNumberMap;

    /**
     *
     */
    std::map<uint16_t, std::shared_ptr<KeyParameterAdapter>>
        mWorkKeyParameterByKifKvcMap;

    /**
     *
     */
    std::vector<uint8_t> mChallenge;

    /**
     *
     */
    std::vector<uint8_t> mCaCertificate;

    /**
     *
     */
    std::shared_ptr<SamParametersAdapter> mSamParameters;
};

} /* namespace legacysam */
} /* namespace crypto */
} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
