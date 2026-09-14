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

#include "keyple/card/calypso/crypto/legacysam/ContextSettingAdapter.hpp"

#include <memory>

#include "keyple/core/util/KeypleAssert.hpp"

namespace keyple {
namespace card {
namespace calypso {
namespace crypto {
namespace legacysam {

using keyple::core::util::Assert;

ContextSettingAdapter::ContextSettingAdapter()
: mContactReaderPayloadCapacity(nullptr)
{
}

ContextSetting&
ContextSettingAdapter::setContactReaderPayloadCapacity(int payloadCapacity)
{
    Assert::getInstance().isInRange(payloadCapacity, 0, 255, "payloadCapacity");

    mContactReaderPayloadCapacity = std::make_shared<int>(payloadCapacity);

    return *this;
}

std::shared_ptr<int>
ContextSettingAdapter::getContactReaderPayloadCapacity() const
{
    return mContactReaderPayloadCapacity;
}

} /* namespace legacysam */
} /* namespace crypto */
} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
