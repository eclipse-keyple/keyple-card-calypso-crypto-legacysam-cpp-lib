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

#include "keyple/card/calypso/crypto/legacysam/LegacySamExtensionService.hpp"

#include <memory>
#include <string>

#include "keyple/card/calypso/crypto/legacysam/ContextSettingAdapter.hpp"
#include "keyple/card/calypso/crypto/legacysam/LegacySamApiFactoryAdapter.hpp"
#include "keyple/card/calypso/crypto/legacysam/LegacySamResourceProfileExtensionAdapter.hpp"
#include "keyple/card/calypso/crypto/legacysam/LegacySamSelectionExtensionAdapter.hpp"
#include "keyple/core/common/CommonApiProperties.hpp"
#include "keyple/core/util/KeypleAssert.hpp"
#include "keyple/core/util/cpp/exception/IllegalArgumentException.hpp"
#include "keypop/card/CardApiProperties.hpp"
#include "keypop/reader/ReaderApiProperties.hpp"

namespace keyple {
namespace card {
namespace calypso {
namespace crypto {
namespace legacysam {

using keyple::core::util::Assert;
using keyple::core::util::cpp::exception::IllegalArgumentException;

std::shared_ptr<LegacySamExtensionService> LegacySamExtensionService::mInstance
    = nullptr;

LegacySamExtensionService::LegacySamExtensionService()
: mContextSetting(std::make_shared<ContextSettingAdapter>())
{
}

std::shared_ptr<LegacySamExtensionService>
LegacySamExtensionService::getInstance()
{
    if (mInstance == nullptr) {
        mInstance = std::shared_ptr<LegacySamExtensionService>(
            new LegacySamExtensionService());
    }
    return mInstance;
}

std::shared_ptr<ContextSetting>
LegacySamExtensionService::getContextSetting()
{
    return mContextSetting;
}

std::shared_ptr<LegacySamApiFactory>
LegacySamExtensionService::getLegacySamApiFactory()
{
    return std::make_shared<LegacySamApiFactoryAdapter>(mContextSetting);
}

std::shared_ptr<CardResourceProfileExtension>
LegacySamExtensionService::createLegacySamResourceProfileExtension(
    std::shared_ptr<LegacySamSelectionExtension> legacySamSelectionExtension)
{
    Assert::getInstance().notNull(
        legacySamSelectionExtension, "Legacy SAM selection");
    auto legacySamSelectionExtensionAdapter
        = std::dynamic_pointer_cast<LegacySamSelectionExtensionAdapter>(
            legacySamSelectionExtension);

    if (!legacySamSelectionExtensionAdapter) {
        throw IllegalArgumentException(
            "The provided 'legacySamSelectionExtension' must be an instance of "
            "'LegacySamSelectionExtensionAdapter'");
    }
    return std::make_shared<LegacySamResourceProfileExtensionAdapter>(
        legacySamSelectionExtensionAdapter, "");
}

std::shared_ptr<CardResourceProfileExtension>
LegacySamExtensionService::createLegacySamResourceProfileExtension(
    std::shared_ptr<LegacySamSelectionExtension> legacySamSelectionExtension,
    const std::string& powerOnDataRegex)
{
    core::util::Assert::getInstance().notEmpty(
        powerOnDataRegex, "powerOnDataRegex");
    auto legacySamSelectionExtensionAdapter
        = std::dynamic_pointer_cast<LegacySamSelectionExtensionAdapter>(
            legacySamSelectionExtension);
    if (!legacySamSelectionExtensionAdapter) {
        throw IllegalArgumentException(
            "The provided 'legacySamSelectionExtension' must be an instance of "
            "'LegacySamSelectionExtensionAdapter'");
    }
    return std::make_shared<LegacySamResourceProfileExtensionAdapter>(
        legacySamSelectionExtensionAdapter, powerOnDataRegex);
}

const std::string
LegacySamExtensionService::getCommonApiVersion() const
{
    return keyple::core::common::CommonApiProperties_VERSION;
}

const std::string
LegacySamExtensionService::getReaderApiVersion() const
{
    return keypop::reader::ReaderApiProperties_VERSION;
}

const std::string
LegacySamExtensionService::getCardApiVersion() const
{
    return keypop::card::CardApiProperties_VERSION;
}

} /* namespace legacysam */
} /* namespace crypto */
} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
