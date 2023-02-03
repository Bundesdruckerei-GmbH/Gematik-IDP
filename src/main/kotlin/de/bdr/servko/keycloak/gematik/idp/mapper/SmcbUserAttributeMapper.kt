/*
 *  Copyright 2023 Bundesdruckerei GmbH and/or its affiliates
 *  and other contributors.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package de.bdr.servko.keycloak.gematik.idp.mapper

import de.bdr.servko.keycloak.gematik.idp.CardType

class SmcbUserAttributeMapper : AbstractGematikIDPUserAttributeMapper() {

    override val cardType: CardType
        get() = CardType.SMCB

    override fun getId(): String = "gematik-idp-smcb-user-mapper"

    override fun getHelpText(): String =
        "Import the claim of the SMCB card, if it exists, into the specified user attribute."

    override fun getDisplayType(): String = "Gematik SMCB Claim Attribute"

}
