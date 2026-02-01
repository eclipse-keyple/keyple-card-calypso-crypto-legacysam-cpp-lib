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

#include "keyple/card/calypso/crypto/legacysam/SecuritySettingAdapter.hpp"

#include <memory>

#include "keyple/core/util/KeypleAssert.hpp"
#include "keyple/core/util/cpp/exception/IllegalArgumentException.hpp"

namespace keyple {
namespace card {
namespace calypso {
namespace crypto {
namespace legacysam {

using keyple::core::util::Assert;
using keyple::core::util::cpp::exception::IllegalArgumentException;

SecuritySetting&
SecuritySettingAdapter::setControlSamResource(
    std::shared_ptr<CardReader> samReader,
    std::shared_ptr<LegacySam> controlSam)
{
    Assert::getInstance()
        .notNull(samReader, "samReader")
        .notNull(controlSam, "controlSam")
        .isTrue(
            controlSam->getProductType() != ProductType::UNKNOWN,
            "productType");

    auto proxyReader = std::dynamic_pointer_cast<ProxyReaderApi>(samReader);
    if (!proxyReader) {
        throw IllegalArgumentException(
            "The provided 'samReader' must implement 'ProxyReaderApi'");
    }

    auto legacySamAdapter
        = std::dynamic_pointer_cast<LegacySamAdapter>(controlSam);
    if (!legacySamAdapter) {
        throw IllegalArgumentException(
            "The provided 'controlSam' must be an instance of "
            "'LegacySamAdapter'");
    }

    mControlSamReader = proxyReader;
    mControlSam = legacySamAdapter;

    return *this;
}

std::shared_ptr<ProxyReaderApi>
SecuritySettingAdapter::getControlSamReader() const
{
    return mControlSamReader;
}

std::shared_ptr<LegacySamAdapter>
SecuritySettingAdapter::getControlSam() const
{
    return mControlSam;
}

} /* namespace legacysam */
} /* namespace crypto */
} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
