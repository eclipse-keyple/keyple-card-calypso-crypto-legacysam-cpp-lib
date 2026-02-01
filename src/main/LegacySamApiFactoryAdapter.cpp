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

#include "keyple/card/calypso/crypto/legacysam/LegacySamApiFactoryAdapter.hpp"

#include <memory>
#include <string>
#include <utility>

#include "keyple/card/calypso/crypto/legacysam/AsyncTransactionCreatorManagerAdapter.hpp"
#include "keyple/card/calypso/crypto/legacysam/AsyncTransactionExecutorManagerAdapter.hpp"
#include "keyple/card/calypso/crypto/legacysam/DtoAdapters.hpp"
#include "keyple/card/calypso/crypto/legacysam/FreeTransactionManagerAdapter.hpp"
#include "keyple/card/calypso/crypto/legacysam/LegacySamAdapter.hpp"
#include "keyple/card/calypso/crypto/legacysam/LegacySamSelectionExtensionAdapter.hpp"
#include "keyple/card/calypso/crypto/legacysam/SecureWriteTransactionManagerAdapter.hpp"
#include "keyple/card/calypso/crypto/legacysam/SecuritySettingAdapter.hpp"
#include "keyple/card/calypso/crypto/legacysam/SymmetricCryptoCardTransactionManagerFactoryAdapter.hpp"
#include "keyple/core/util/KeypleAssert.hpp"
#include "keyple/core/util/cpp/exception/IllegalArgumentException.hpp"

namespace keyple {
namespace card {
namespace calypso {
namespace crypto {
namespace legacysam {

using keyple::core::util::Assert;
using keyple::core::util::cpp::exception::IllegalArgumentException;

const std::string LegacySamApiFactoryAdapter ::
    MSG_THE_PROVIDED_SAM_READER_MUST_IMPLEMENT_PROXY_READER_API
    = "The provided 'samReader' must implement 'ProxyReaderApi'";
const std::string LegacySamApiFactoryAdapter ::
    MSG_THE_PROVIDED_SAM_MUST_BE_AN_INSTANCE_OF_LEGACY_SAM_ADAPTER
    = "The provided 'sam' must be an instance of 'LegacySamAdapter'";

LegacySamApiFactoryAdapter::LegacySamApiFactoryAdapter(
    std::shared_ptr<ContextSettingAdapter> contextSetting)
: mContextSetting(contextSetting)
{
}

std::shared_ptr<LegacySamSelectionExtension>
LegacySamApiFactoryAdapter::createLegacySamSelectionExtension()
{
    return std::make_shared<LegacySamSelectionExtensionAdapter>();
}

std::shared_ptr<SymmetricCryptoCardTransactionManagerFactory>
LegacySamApiFactoryAdapter::createSymmetricCryptoCardTransactionManagerFactory(
    std::shared_ptr<CardReader> samReader, std::shared_ptr<LegacySam> sam)
{
    auto proxyReader = std::dynamic_pointer_cast<ProxyReaderApi>(samReader);
    if (!proxyReader) {
        throw IllegalArgumentException(
            MSG_THE_PROVIDED_SAM_READER_MUST_IMPLEMENT_PROXY_READER_API);
    }
    auto legacySamAdapter = std::dynamic_pointer_cast<LegacySamAdapter>(sam);
    if (!legacySamAdapter) {
        throw IllegalArgumentException(
            MSG_THE_PROVIDED_SAM_MUST_BE_AN_INSTANCE_OF_LEGACY_SAM_ADAPTER);
    }

    return std::make_shared<
        SymmetricCryptoCardTransactionManagerFactoryAdapter>(
        proxyReader, legacySamAdapter, mContextSetting);
}

std::shared_ptr<SecuritySetting>
LegacySamApiFactoryAdapter::createSecuritySetting()
{
    return std::make_shared<SecuritySettingAdapter>();
}

std::shared_ptr<FreeTransactionManager>
LegacySamApiFactoryAdapter::createFreeTransactionManager(
    std::shared_ptr<CardReader> samReader, std::shared_ptr<LegacySam> sam)
{
    auto proxyReader = std::dynamic_pointer_cast<ProxyReaderApi>(samReader);
    if (!proxyReader) {
        throw IllegalArgumentException(
            MSG_THE_PROVIDED_SAM_READER_MUST_IMPLEMENT_PROXY_READER_API);
    }
    auto legacySamAdapter = std::dynamic_pointer_cast<LegacySamAdapter>(sam);
    if (!legacySamAdapter) {
        throw IllegalArgumentException(
            MSG_THE_PROVIDED_SAM_MUST_BE_AN_INSTANCE_OF_LEGACY_SAM_ADAPTER);
    }

    return std::make_shared<FreeTransactionManagerAdapter>(
        proxyReader, legacySamAdapter);
}

std::shared_ptr<SecureWriteTransactionManager>
LegacySamApiFactoryAdapter::createSecureWriteTransactionManager(
    std::shared_ptr<CardReader> samReader,
    std::shared_ptr<LegacySam> sam,
    std::shared_ptr<SecuritySetting> securitySetting)
{
    auto proxyReader = std::dynamic_pointer_cast<ProxyReaderApi>(samReader);
    if (!proxyReader) {
        throw IllegalArgumentException(
            MSG_THE_PROVIDED_SAM_READER_MUST_IMPLEMENT_PROXY_READER_API);
    }
    auto legacySamAdapter = std::dynamic_pointer_cast<LegacySamAdapter>(sam);
    if (!legacySamAdapter) {
        throw IllegalArgumentException(
            MSG_THE_PROVIDED_SAM_MUST_BE_AN_INSTANCE_OF_LEGACY_SAM_ADAPTER);
    }

    Assert::getInstance().notNull(securitySetting, "securitySetting");
    auto securitySettingAdapter
        = std::dynamic_pointer_cast<SecuritySettingAdapter>(securitySetting);

    return std::make_shared<SecureWriteTransactionManagerAdapter>(
        proxyReader,
        legacySamAdapter,
        securitySettingAdapter->getControlSamReader(),
        securitySettingAdapter->getControlSam());
}

std::shared_ptr<AsyncTransactionCreatorManager>
LegacySamApiFactoryAdapter::createAsyncTransactionCreatorManager(
    const std::string& targetSamContext,
    std::shared_ptr<SecuritySetting> securitySetting)
{
    core::util::Assert::getInstance().notNull(
        securitySetting, "securitySetting");

    return std::make_shared<AsyncTransactionCreatorManagerAdapter>(
        targetSamContext, securitySetting);
}

std::shared_ptr<AsyncTransactionExecutorManager>
LegacySamApiFactoryAdapter::createAsyncTransactionExecutorManager(
    std::shared_ptr<CardReader> samReader,
    std::shared_ptr<LegacySam> sam,
    const std::string& samCommands)
{
    auto proxyReader = std::dynamic_pointer_cast<ProxyReaderApi>(samReader);
    if (!proxyReader) {
        throw IllegalArgumentException(
            MSG_THE_PROVIDED_SAM_READER_MUST_IMPLEMENT_PROXY_READER_API);
    }
    auto legacySamAdapter = std::dynamic_pointer_cast<LegacySamAdapter>(sam);
    if (!legacySamAdapter) {
        throw IllegalArgumentException(
            MSG_THE_PROVIDED_SAM_MUST_BE_AN_INSTANCE_OF_LEGACY_SAM_ADAPTER);
    }

    return std::make_shared<AsyncTransactionExecutorManagerAdapter>(
        proxyReader, legacySamAdapter, samCommands);
}

std::shared_ptr<KeyPairContainer>
LegacySamApiFactoryAdapter::createKeyPairContainer()
{
    return std::make_shared<DtoAdapters::KeyPairContainerAdapter>();
}

std::shared_ptr<LegacyCardCertificateComputationData>
LegacySamApiFactoryAdapter::createLegacyCardCertificateComputationData()
{
    return std::make_shared<
        DtoAdapters::LegacyCardCertificateComputationDataAdapter>();
}

std::shared_ptr<BasicSignatureComputationData>
LegacySamApiFactoryAdapter::createBasicSignatureComputationData()
{
    return std::make_shared<
        DtoAdapters::BasicSignatureComputationDataAdapter>();
}

std::shared_ptr<TraceableSignatureComputationData>
LegacySamApiFactoryAdapter::createTraceableSignatureComputationData()
{
    return std::make_shared<
        DtoAdapters::TraceableSignatureComputationDataAdapter>();
}

std::shared_ptr<BasicSignatureVerificationData>
LegacySamApiFactoryAdapter::createBasicSignatureVerificationData()
{
    return std::make_shared<
        DtoAdapters::BasicSignatureVerificationDataAdapter>();
}

std::shared_ptr<TraceableSignatureVerificationData>
LegacySamApiFactoryAdapter::createTraceableSignatureVerificationData()
{
    return std::make_shared<
        DtoAdapters::TraceableSignatureVerificationDataAdapter>();
}

} /* namespace legacysam */
} /* namespace crypto */
} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
