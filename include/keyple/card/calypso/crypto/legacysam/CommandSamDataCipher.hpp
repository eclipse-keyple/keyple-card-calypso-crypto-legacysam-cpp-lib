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
#include "keyple/card/calypso/crypto/legacysam/CommandRef.hpp"

namespace keyple {
namespace card {
namespace calypso {
namespace crypto {
namespace legacysam {

/**
 * Builds a "SAM Cipher" command ("SAM Cipher CAAD", "SAM Cipher Ceilings",
 * "SAM Cipher Parameters").
 *
 * <p>The purpose is to compute the encrypted block to provide as input to the
 * associated "write" commands.
 *
 * @since 0.3.0
 */
class KEYPLECARDCALYPSOCRYPTOLEGACYSAM_API CommandSamDataCipher final
: public Command {
public:
    /**
     * Enum to represent the different types of data that can be ciphered.
     *
     * @since 0.3.0
     */
    enum class DataType {
        /**
         * The data is a CAAD record.
         *
         * @since 0.3.0
         */
        CAAD_RECORD,

        /**
         * The data is a ceilings file record.
         *
         * @since 0.3.0
         */
        CEILINGS_FILE_RECORD,

        /**
         * The data is a single ceiling value.
         *
         * @since 0.3.0
         */
        ONE_CEILING_VALUE,

        /**
         * The data is a parameters record.
         *
         * @since 0.3.0
         */
        PARAMETERS_RECORD
    };

    /**
     * Constructor
     *
     * @param context The command context.
     * @param recordNumber The targeted record number (in range [1..7], ignored
     * when DataType is DataType::ONE_CEILING_VALUE or
     * DataType::PARAMETERS_RECORD).
     * @param dataType The type of data to be ciphered.
     * @param plainData The data to be ciphered, preceded by a byte containing
     * the encryption key KVC (30 bytes).
     * @since 0.3.0
     */
    CommandSamDataCipher(
        std::shared_ptr<DtoAdapters::CommandContextDto> context,
        int recordNumber,
        DataType dataType,
        const std::vector<uint8_t>& plainData);

    /**
     * {@inheritDoc}
     *
     * @since 0.3.0
     */
    const std::map<int, const std::shared_ptr<StatusProperties>>&
    getStatusTable() const override;

    /**
     * {@inheritDoc}
     *
     * @since 0.3.0
     */
    void finalizeRequest() override;

    /**
     * {@inheritDoc}
     *
     * @since 0.3.0
     */
    bool isControlSamRequiredToFinalizeRequest() const override;

    /**
     * {@inheritDoc}
     *
     * @since 0.3.0
     */
    void parseResponse(std::shared_ptr<ApduResponseApi> apduResponse) override;

    /**
     * Retrieves the ciphered data resulting of the execution of the command.
     *
     * @return A 48-byte byte array.
     */
    const std::vector<uint8_t>& getCipheredData() const;

private:
    /**
     *
     */
    static const std::map<int, const std::shared_ptr<StatusProperties>>
        STATUS_TABLE;

    /**
     *
     */
    std::vector<uint8_t> mCipheredData;
};

} /* namespace legacysam */
} /* namespace crypto */
} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
