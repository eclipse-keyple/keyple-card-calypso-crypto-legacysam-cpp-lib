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
#include <vector>

#include "keyple/card/calypso/crypto/legacysam/Command.hpp"

namespace keyple {
namespace card {
namespace calypso {
namespace crypto {
namespace legacysam {

using StatusProperties = Command::StatusProperties;

/**
 * Builds the Card Cipher PIN APDU command.
 *
 * @since 2.0.1
 */
class KEYPLECARDCALYPSOCRYPTOLEGACYSAM_API CommandCardCipherPin
: public virtual Command {
public:
    /**
     * Constructor
     *
     * <p>In the case of a PIN verification, only the current PIN must be
     * provided (newPin must be set to null).
     *
     * <p>In the case of a PIN update, the current and new PINs must be
     * provided.
     *
     * @param context The command context.
     * @param cipheringKif the KIF of the key used to encipher the PIN data.
     * @param cipheringKvc the KVC of the key used to encipher the PIN data.
     * @param currentPin the current PIN (a 4-byte byte array).
     * @since 2.0.1
     */
    CommandCardCipherPin(
        std::shared_ptr<DtoAdapters::CommandContextDto> context,
        std::uint8_t cipheringKif,
        std::uint8_t cipheringKvc,
        const std::vector<std::uint8_t>& currentPin);

    /**
     * Constructor
     *
     * <p>In the case of a PIN verification, only the current PIN must be
     * provided (newPin must be set to null).
     *
     * <p>In the case of a PIN update, the current and new PINs must be
     * provided.
     *
     * @param context The command context.
     * @param cipheringKif the KIF of the key used to encipher the PIN data.
     * @param cipheringKvc the KVC of the key used to encipher the PIN data.
     * @param currentPin the current PIN (a 4-byte byte array).
     * @param newPin the new PIN (a 4-byte byte array)
     * @since 2.0.1
     */
    CommandCardCipherPin(
        std::shared_ptr<DtoAdapters::CommandContextDto> context,
        std::uint8_t cipheringKif,
        std::uint8_t cipheringKvc,
        const std::vector<std::uint8_t>& currentPin,
        const std::vector<std::uint8_t>& newPin);

    /**
     * Gets the 8 bytes of ciphered data.
     *
     * @return The ciphered data byte array
     * @since 2.0.1
     */
    const std::vector<std::uint8_t>& getCipheredData() const;

    /**
     * {@inheritDoc}
     *
     * @since 0.4.0
     */
    void finalizeRequest() override;

    /**
     * {@inheritDoc}
     *
     * @since 0.4.0
     */
    bool isControlSamRequiredToFinalizeRequest() const override;

    /**
     * {@inheritDoc}
     *
     * @since 0.3.0
     */
    void parseResponse(std::shared_ptr<ApduResponseApi> apduResponse) override;

    /**
     * {@inheritDoc}
     *
     * @since 0.1.0
     */
    const std::map<int, const std::shared_ptr<StatusProperties>>&
    getStatusTable() const override;

private:
    /**
     *
     */
    std::vector<std::uint8_t> mCipheredData;

    /**
     *
     */
    static const std::map<int, const std::shared_ptr<StatusProperties>>
        STATUS_TABLE;
};

} /* namespace legacysam */
} /* namespace crypto */
} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
