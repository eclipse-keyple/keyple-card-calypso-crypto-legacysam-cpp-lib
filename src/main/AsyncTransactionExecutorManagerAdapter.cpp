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

namespace keyple {
namespace card {
namespace calypso {
namespace crypto {
namespace legacysam {

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
    //             "Invalid JSON commands object",
    //             std::make_shared<ClassNotFoundException>(e));
    //     }
    // }
}

AsyncTransactionExecutorManager&
AsyncTransactionExecutorManagerAdapter::processCommands()
{
    processTargetSamCommandsAlreadyFinalized(false);

    return *this;
}

} /* namespace legacysam */
} /* namespace crypto */
} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
