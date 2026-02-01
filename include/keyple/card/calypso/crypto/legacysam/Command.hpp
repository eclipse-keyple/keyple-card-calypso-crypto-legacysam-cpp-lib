/******************************************************************************
 * Copyright (c) 2023 Calypso Networks Association https://calypsonet.org/    *
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
#include <string>
#include <typeinfo>
#include <vector>

#include "keyple/card/calypso/crypto/legacysam/CommandException.hpp"
#include "keyple/card/calypso/crypto/legacysam/CommandRef.hpp"
#include "keyple/card/calypso/crypto/legacysam/DtoAdapters.hpp"
#include "keyple/card/calypso/crypto/legacysam/KeypleCardCalypsoCryptoLegacySamExport.hpp"
#include "keyple/card/generic/ApduRequestAdapter.hpp"
#include "keypop/card/ApduResponseApi.hpp"

namespace keyple {
namespace card {
namespace calypso {
namespace crypto {
namespace legacysam {

using keyple::card::generic::ApduRequestAdapter;
using keypop::card::ApduResponseApi;

using CommandContextDto = DtoAdapters::CommandContextDto;

/**
 * Superclass for all SAM commands.
 *
 * <p>It provides the generic getters to retrieve:
 *
 * <ul>
 *   <li>the card command reference,
 *   <li>the name of the command,
 *   <li>the built keypop::card::spi::ApduRequestSpi,
 *   <li>the parsed ApduResponseApi.
 * </ul>
 *
 * @since 0.1.0
 */
class KEYPLECARDCALYPSOCRYPTOLEGACYSAM_API Command {
public:
    /**
     * This internal class provides status word properties
     *
     * @since 0.1.0
     */
    class StatusProperties {
    public:
        /**
         * Creates a successful status.
         *
         * @param information the status information.
         * @since 0.1.0
         */
        explicit StatusProperties(const std::string& information);

        /**
         * Creates an error status.<br>
         * If exceptionClass is null, then a successful status is created.
         *
         * @param information the status information.
         * @param exceptionClass the associated exception class.
         * @since 0.1.0
         */
        StatusProperties(
            const std::string& information,
            const std::type_info& exceptionType);

        /**
         * Gets information
         *
         * @return A reference
         * @since 0.1.0
         */
        const std::string& getInformation() const;

        /**
         * Gets successful indicator
         *
         * @return The successful indicator
         * @since 0.1.0
         */
        bool isSuccessful() const;

        /**
         * Gets Exception Class
         *
         * @return A reference
         * @since 0.1.0
         */
        const std::type_info& getExceptionClass() const;

    private:
        /**
         *
         */
        std::string mInformation;

        /**
         *
         */
        bool mSuccessful;

        /**
         *
         */
        const std::type_info& mExceptionClass;
    };

    /**
     * Constructor.
     *
     * @param commandRef The command reference.
     * @param le The value of the LE field.
     * @param context The command context.
     * @since 0.1.0
     */
    Command(
        CommandRef commandRef,
        int le,
        std::shared_ptr<CommandContextDto> context);

    /**
     * Default destructor.
     *
     * @since 2.0.0
     */
    virtual ~Command() = default;

    /**
     * Appends a string to the current name.
     *
     * <p>The sub name completes the name of the current command. This method
     * must therefore only be invoked conditionally (log level &gt;= debug).
     *
     * @param subName The string to append.
     * @throws NullPointerException If the request is not set.
     * @since 0.1.0
     */
    void addSubName(const std::string& subName);

    /**
     * Gets the command reference.
     *
     * @return the command reference.
     * @since 2.0.0
     */
    virtual CommandRef getCommandRef() const;

    /**
     * Gets the name of this APDU command.
     *
     * @return A not empty string.
     * @since 0.1.0
     */
    const std::string& getName() const;

    /**
     * Sets the command ApduRequestAdapter.
     *
     * @param apduRequest The APDU request.
     * @since 0.1.0
     */
    void setApduRequest(std::shared_ptr<ApduRequestAdapter> apduRequest);

    /**
     * Gets the ApduRequestAdapter.
     *
     * @return Null if the request is not set.
     * @since 0.1.0
     */
    std::shared_ptr<ApduRequestAdapter> getApduRequest() const;

    /**
     * Gets the APDU response.
     *
     * @return The APDU response.
     * @since 0.1.0
     */
    std::shared_ptr<ApduResponseApi> getApduResponse() const;

    /**
     * Returns the command context.
     *
     * @return Null if the SAM selection has not yet been made.
     * @since 0.1.0
     */
    std::shared_ptr<CommandContextDto> getContext() const;

    /**
     * Adds a control SAM command.
     *
     * @param command The command to add.
     * @since 0.1.0
     */
    void addControlSamCommand(std::shared_ptr<Command> command);

    /**
     * Finalize the construction of the APDU request if needed.
     *
     * @since 0.3.0
     */
    virtual void finalizeRequest() = 0;

    /**
     * Indicates the need for a control SAM to compute the data used to finalize
     * the command.
     *
     * @return true if a control SAM is required.
     * @since 0.3.0
     */
    virtual bool isControlSamRequiredToFinalizeRequest() const = 0;

    /**
     * Parses the APDU response, updates the card image and synchronize the
     * crypto service if it is involved in the process.
     *
     * @param apduResponse The APDU response.
     * @throw CommandException if status is not successful or if the length of
     * the response is not equal to the LE field in the request.
     * @since 0.3.0
     */
    virtual void parseResponse(std::shared_ptr<ApduResponseApi> apduResponse)
        = 0;

    /**
     * Sets the response ApduResponseApi and checks the status word.
     *
     * @param apduResponse The APDU response.
     * @throw CommandException if status is not successful or if the length of
     * the response is not equal to the LE field in the request.
     * @since 0.1.0
     */
    void
    setResponseAndCheckStatus(std::shared_ptr<ApduResponseApi> apduResponse);

    /**
     * Gets the status table.
     *
     * @return The status table.
     * @since 0.1.0
     */
    virtual const std::map<int, const std::shared_ptr<StatusProperties>>&
    getStatusTable() const;

    /**
     * Builds a specific APDU command exception.
     *
     * @param exceptionClass the exception class.
     * @param message The message.
     * @return A not null reference.
     * @since 0.1.0
     */
    CommandException buildCommandException(
        const std::type_info& exceptionClass, const std::string& message);

protected:
    /**
     * Executes all previously added commands for the control SAM.
     *
     * @since 0.3.0
     */
    void processControlSamCommand();

    /**
     *
     */
    static const std::map<int, const std::shared_ptr<StatusProperties>>
        STATUS_TABLE;

private:
    /**
     *
     */
    CommandRef mCommandRef;

    /**
     *
     */
    int mLe;

    /**
     *
     */
    std::string mName;

    /**
     *
     */
    std::shared_ptr<DtoAdapters::CommandContextDto> mContext;

    /**
     *
     */
    std::shared_ptr<ApduRequestAdapter> mApduRequest;

    /**
     *
     */
    std::shared_ptr<ApduResponseApi> mApduResponse;

    /**
     *
     */
    std::vector<std::shared_ptr<Command>> mControlSamCommands;

    /**
     * @return The properties of the result.
     * @throw NullPointerException If the response is not set.
     */
    std::shared_ptr<StatusProperties> getStatusWordProperties();

    /**
     * This method check the status word and if the length of the response is
     * equal to the LE field in the request.<br>
     * If status word is not referenced, then status is considered unsuccessful.
     *
     * @throw CommandException if status is not successful or if the length of
     * the response is not equal to the LE field in the request.
     */
    void checkStatus();
};

} /* namespace legacysam */
} /* namespace crypto */
} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
