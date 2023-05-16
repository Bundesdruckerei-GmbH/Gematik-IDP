<!--
  ~  Copyright 2023 Bundesdruckerei GmbH and/or its affiliates
  ~  and other contributors.
  ~
  ~  Licensed under the Apache License, Version 2.0 (the "License");
  ~  you may not use this file except in compliance with the License.
  ~  You may obtain a copy of the License at
  ~
  ~  http://www.apache.org/licenses/LICENSE-2.0
  ~
  ~  Unless required by applicable law or agreed to in writing, software
  ~  distributed under the License is distributed on an "AS IS" BASIS,
  ~  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  ~  See the License for the specific language governing permissions and
  ~  limitations under the License.
  -->
<#import "template.ftl" as layout>

<@layout.registrationLayout bodyClass="authenticator-loading-page"; section>
    <#if section = "header">
        <p class="authenticator-loading-title">
            ${msg("authenticator.startingTitle")}
        </p>
    <#elseif section = "form">
        <div class="pf-c-backdrop gematik-idp-modal">
            <div class="pf-l-bullseye">
                <div class="pf-c-modal-box" role="dialog" aria-modal="true" aria-labelledby="modal-login-info-title"
                     aria-describedby="modal-login-info-description">
                    <header class="pf-c-modal-box__header">
                        <h1 class="pf-c-modal-box__title" id="modal-login-info-title">${msg("confirmOpenAuthenticatorModalHint")}</h1>
                    </header>
                    <div class="pf-c-modal-box__body" id="modal-login-info-description">
                        <p>
                            ${kcSanitize(msg("confirmOpenAuthenticatorModalDescription"))?no_esc}
                        </p>
                    </div>
                    <footer class="pf-c-modal-box__footer">
                        <a class="pf-c-button pf-m-primary close" href="${authenticatorUrl}" id="openAuthenticator">
                            ${kcSanitize(msg("confirmOpenAuthenticatorModalButton"))?no_esc}
                        </a>
                    </footer>
                </div>
            </div>
        </div>
        <p class="pf-c-content authenticator-loading-message">
            ${msg("authenticator.startingInfo")}
        </p>

        <#compress>
            <script id="gematikIdpConfiguration" type="application/json">
                {
                    "statusUrl": "${statusUrl!""}",
                    "timeoutUrl": "${timeoutUrl!""}",
                    "timeout": ${timeoutMs?c}
                }
            </script>
        </#compress>
    </#if>
</@layout.registrationLayout>
