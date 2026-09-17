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

#include "keyple/card/calypso/crypto/legacysam/AsyncTransactionExecutorManagerAdapter.hpp"

#include <memory>
#include <string>
#include <vector>

#include "keypop/calypso/crypto/legacysam/transaction/ReaderIOException.hpp"
#include "keypop/calypso/crypto/legacysam/transaction/SamIOException.hpp"
#include "keypop/calypso/crypto/legacysam/transaction/UnexpectedCommandStatusException.hpp"
#include "keypop/reader/CardCommunicationException.hpp"
#include "keypop/reader/InvalidCardResponseException.hpp"
#include "keypop/reader/ReaderCommunicationException.hpp"

namespace keyple {
namespace card {
namespace calypso {
namespace crypto {
namespace legacysam {

using keypop::calypso::crypto::legacysam::transaction::ReaderIOException;
using keypop::calypso::crypto::legacysam::transaction::SamIOException;
using keypop::calypso::crypto::legacysam::transaction::
    UnexpectedCommandStatusException;
using keypop::reader::CardCommunicationException;
using keypop::reader::InvalidCardResponseException;
using keypop::reader::ReaderCommunicationException;

AsyncTransactionExecutorManagerAdapter::AsyncTransactionExecutorManagerAdapter(
    std::shared_ptr<ProxyReaderApi> targetSamReader,
    std::shared_ptr<LegacySamAdapter> targetSam,
    const std::string& /*samCommandsJson**/)
: CommonTransactionManagerAdapter(targetSamReader, targetSam, nullptr, nullptr)
{
    // JsonObject jsonObject = JsonUtil.getParser().fromJson(samCommandsJson,
    // JsonObject.class);

    /* Extract the type and command lists. */
    // std::vector<std::string> commandsTypes;
    //     JsonUtil.getParser()
    //         .fromJson(
    //             jsonObject.get(SAM_COMMANDS_TYPES).getAsJsonArray(),
    //             new TypeToken<ArrayList<String>>() {}.getType());
    // JsonArray commands = jsonObject.get(SAM_COMMANDS).getAsJsonArray();

    // for (int i = 0; i < commandsTypes.size(); i++) {
    // check the resulting command class
    // try {
    // Class<?> classOfCommand = Class.forName(commandsTypes.get(i));
    // addTargetSamCommand(
    //     (Command) JsonUtil.getParser().fromJson(commands.get(i),
    //     classOfCommand));

    //     } catch (const ClassNotFoundException& e) {
    //         throw IllegalStateException(
    //             "Class '" + commandsTypes[i] + "' not found. Unable to "
    //             "parse JSON object: " + samCommandsJson,
    //             std::make_shared<ClassNotFoundException>(e));
    //     }
    // }
}

AsyncTransactionExecutorManager&
AsyncTransactionExecutorManagerAdapter::processCommands()
{
    try {
        return processCommands(ChannelControl::KEEP_OPEN);
    } catch (const ReaderCommunicationException& e) {
        throw ReaderIOException(e.what(), e);
    } catch (const CardCommunicationException& e) {
        throw SamIOException(e.what(), e);
    } catch (const InvalidCardResponseException& e) {
        throw UnexpectedCommandStatusException(e.what(), e);
    }
}

AsyncTransactionExecutorManager&
AsyncTransactionExecutorManagerAdapter::processCommands(
    ChannelControl channelControl)
{
    processTargetSamCommandsAlreadyFinalized(channelControl);

    return *this;
}

} /* namespace legacysam */
} /* namespace crypto */
} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
