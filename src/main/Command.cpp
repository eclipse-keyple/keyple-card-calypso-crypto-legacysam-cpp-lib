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

#include "keyple/card/calypso/crypto/legacysam/Command.hpp"

#include <map>
#include <memory>
#include <string>
#include <utility>

#include "keyple/card/calypso/crypto/legacysam/AccessForbiddenException.hpp"
#include "keyple/card/calypso/crypto/legacysam/CommandException.hpp"
#include "keyple/card/calypso/crypto/legacysam/CommandExecutor.hpp"
#include "keyple/card/calypso/crypto/legacysam/CounterOverflowException.hpp"
#include "keyple/card/calypso/crypto/legacysam/IllegalParameterException.hpp"
#include "keyple/card/calypso/crypto/legacysam/IncorrectInputDataException.hpp"
#include "keyple/card/calypso/crypto/legacysam/SecurityContextException.hpp"
#include "keyple/card/calypso/crypto/legacysam/SecurityDataException.hpp"
#include "keyple/card/calypso/crypto/legacysam/UnexpectedResponseLengthException.hpp"
#include "keyple/card/calypso/crypto/legacysam/UnknownStatusException.hpp"
#include "keyple/core/util/HexUtil.hpp"
#include "keyple/core/util/cpp/StringUtils.hpp"

namespace keyple {
namespace card {
namespace calypso {
namespace crypto {
namespace legacysam {

using keyple::core::util::HexUtil;
using keyple::core::util::cpp::StringUtils;

using StatusProperties = Command::StatusProperties;

const std::map<int, const std::shared_ptr<StatusProperties>>
    Command::STATUS_TABLE = [] {
        std::map<int, const std::shared_ptr<StatusProperties>> m;

        m.insert(
            {{0x9000, std::make_shared<StatusProperties>("Success")},
             {0x6200,
              std::make_shared<StatusProperties>(
                  "No information given", typeid(CommandException))},
             {0x6281,
              std::make_shared<StatusProperties>(
                  "Part of returned data may be corrupted",
                  typeid(CommandException))},
             {0x6282,
              std::make_shared<StatusProperties>(
                  "End of file/record reached before reading Ne bytes",
                  typeid(CommandException))},
             {0x6300,
              std::make_shared<StatusProperties>(
                  "Authentication failed", typeid(SecurityDataException))},
             {0x6310,
              std::make_shared<StatusProperties>(
                  "Authentication failed, 10 retries left",
                  typeid(SecurityDataException))},
             {0x6400,
              std::make_shared<StatusProperties>(
                  "State of non-volatile memory unchanged",
                  typeid(CommandException))},
             {0x6581,
              std::make_shared<StatusProperties>(
                  "Memory failure", typeid(CommandException))},
             {0x6600,
              std::make_shared<StatusProperties>(
                  "No information given", typeid(CommandException))},
             {0x6700,
              std::make_shared<StatusProperties>(
                  "Wrong length", typeid(IllegalParameterException))},
             {0x6800,
              std::make_shared<StatusProperties>(
                  "No information given", typeid(CommandException))},
             {0x6881,
              std::make_shared<StatusProperties>(
                  "Logical channel not supported",
                  typeid(IllegalParameterException))},
             {0x6882,
              std::make_shared<StatusProperties>(
                  "Secure messaging not supported",
                  typeid(IllegalParameterException))},
             {0x6900,
              std::make_shared<StatusProperties>(
                  "No information given", typeid(CommandException))},
             {0x6981,
              std::make_shared<StatusProperties>(
                  "Command incompatible with file structure",
                  typeid(IllegalParameterException))},
             {0x6982,
              std::make_shared<StatusProperties>(
                  "Security status not satisfied",
                  typeid(SecurityDataException))},
             {0x6983,
              std::make_shared<StatusProperties>(
                  "Authentication method blocked",
                  typeid(SecurityDataException))},
             {0x6984,
              std::make_shared<StatusProperties>(
                  "Reference data not usable", typeid(SecurityDataException))},
             {0x6985,
              std::make_shared<StatusProperties>(
                  "Conditions of use not satisfied",
                  typeid(AccessForbiddenException))},
             {0x6986,
              std::make_shared<StatusProperties>(
                  "Command not allowed (no current EF)",
                  typeid(AccessForbiddenException))},
             {0x6A00,
              std::make_shared<StatusProperties>(
                  "Wrong P1/P2", typeid(IllegalParameterException))},
             {0x6A80,
              std::make_shared<StatusProperties>(
                  "Incorrect parameters in data field",
                  typeid(IllegalParameterException))},
             {0x6A81,
              std::make_shared<StatusProperties>(
                  "Function not supported", typeid(IllegalParameterException))},
             {0x6A82,
              std::make_shared<StatusProperties>(
                  "File not found", typeid(IllegalParameterException))},
             {0x6A83,
              std::make_shared<StatusProperties>(
                  "Record not found", typeid(IllegalParameterException))},
             {0x6A84,
              std::make_shared<StatusProperties>(
                  "Not enough memory space",
                  typeid(IllegalParameterException))},
             {0x6A86,
              std::make_shared<StatusProperties>(
                  "Incorrect parameters P1-P2",
                  typeid(IllegalParameterException))},
             {0x6B00,
              std::make_shared<StatusProperties>(
                  "Wrong P1/P2", typeid(IllegalParameterException))},
             {0x6C00,
              std::make_shared<StatusProperties>(
                  "Wrong Le field", typeid(IllegalParameterException))},
             {0x6D00,
              std::make_shared<StatusProperties>(
                  "Instruction code not supported or invalid",
                  typeid(UnknownStatusException))},
             {0x6E00,
              std::make_shared<StatusProperties>(
                  "Class not supported", typeid(UnknownStatusException))},
             {0x6F00,
              std::make_shared<StatusProperties>(
                  "No precise diagnosis", typeid(UnknownStatusException))}});

        return m;
    }();

Command::Command(
    CommandRef commandRef,
    int le,
    std::shared_ptr<DtoAdapters::CommandContextDto> context)
: mCommandRef(commandRef)
, mLe(le)
, mContext(std::move(context))
{
}

void
Command::addSubName(const std::string& subName)
{
    mName += " - " + subName;

    mApduRequest->setInfo(mName);
}

CommandRef
Command::getCommandRef() const
{
    return mCommandRef;
}

std::shared_ptr<ApduRequestAdapter>
Command::getApduRequest() const
{
    return mApduRequest;
}

std::shared_ptr<CommandContextDto>
Command::getContext() const
{
    return mContext;
}

void
Command::addControlSamCommand(std::shared_ptr<Command> command)
{
    mControlSamCommands.push_back(std::move(command));
}

void
Command::processControlSamCommand()
{
    try {
        CommandExecutor::processCommands(
            mControlSamCommands, mContext->getControlSamReader(), false);

    } catch (const std::exception& e) {
        throw;
    }

    /* Finally */
    mControlSamCommands.clear();
}

void
Command::setApduRequest(std::shared_ptr<ApduRequestAdapter> apduRequest)
{
    mApduRequest = std::move(apduRequest);
}

std::shared_ptr<StatusProperties>
Command::getStatusWordProperties()
{
    if (mApduResponse == nullptr) {
        throw std::exception();
    }

    const auto it = getStatusTable().find(mApduResponse->getStatusWord());

    return (it != getStatusTable().end()) ? it->second : nullptr;
}

void
Command::setResponseAndCheckStatus(
    std::shared_ptr<ApduResponseApi> apduResponse)
{
    mApduResponse = apduResponse;
    checkStatus();
}

void
Command::checkStatus()
{
    const auto props = getStatusWordProperties();
    if (props != nullptr && props->isSuccessful()) {
        /* SW is successful, then check the response length (CL-CSS-RESPLE.1) */
        if (mLe != 0
            && mLe != static_cast<int>(mApduResponse->getDataOut().size())) {
            throw UnexpectedResponseLengthException(
                StringUtils::format(
                    "Incorrect APDU response length (expected: %d, actual: %d)",
                    mLe,
                    mApduResponse->getDataOut().size()));
        }

        /* SW and response length are correct. */
        return;
    }

    /* Status word is not referenced, or not successful. */

    /* Exception class */
    const std::type_info& exceptionClass
        = props != nullptr ? props->getExceptionClass() : typeid(nullptr);

    /* Message */
    const std::string message
        = props != nullptr ? props->getInformation() : "Unknown status";

    /* Throw the exception */
    throwCommandException(exceptionClass, message);
}

std::shared_ptr<ApduResponseApi>
Command::getApduResponse() const
{
    return mApduResponse;
}

const std::map<int, const std::shared_ptr<StatusProperties>>&
Command::getStatusTable() const
{
    return STATUS_TABLE;
}

void
Command::throwCommandException(
    const std::type_info& exceptionClass, const std::string& message)
{
    if (exceptionClass == typeid(AccessForbiddenException)) {
        throw AccessForbiddenException(message);
    } else if (exceptionClass == typeid(CounterOverflowException)) {
        throw CounterOverflowException(message);
    } else if (exceptionClass == typeid(DataAccessException)) {
        throw DataAccessException(message);
    } else if (exceptionClass == typeid(IllegalParameterException)) {
        throw IllegalParameterException(message);
    } else if (exceptionClass == typeid(IncorrectInputDataException)) {
        throw IncorrectInputDataException(message);
    } else if (exceptionClass == typeid(SecurityDataException)) {
        throw SecurityDataException(message);
    } else if (exceptionClass == typeid(SecurityContextException)) {
        throw SecurityContextException(message);
    } else {
        throw UnknownStatusException(message);
    }
}

Command::StatusProperties::StatusProperties(const std::string& information)
: mInformation(information)
, mSuccessful(true)
, mExceptionClass(typeid(nullptr))
{
}

Command::StatusProperties::StatusProperties(
    const std::string& information, const std::type_info& exceptionClass)
: mInformation(information)
, mSuccessful(exceptionClass == typeid(nullptr))
, mExceptionClass(exceptionClass)
{
}

const std::string&
Command::StatusProperties::getInformation() const
{
    return mInformation;
}

bool
Command::StatusProperties::isSuccessful() const
{
    return mSuccessful;
}

const std::type_info&
Command::StatusProperties::getExceptionClass() const
{
    return mExceptionClass;
}

} /* namespace legacysam */
} /* namespace crypto */
} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
