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
<#import "macros.ftl" as macros>

<@layout.registrationLayout bodyClass="authenticator-timeout-page"; section>
    <#if section = "header">
        ${msg("authenticator.timeoutTitle")}
    <#elseif section = "form">
        <div class="pf-l-grid pf-m-gutter">
            <div class="pf-l-grid__item pf-m-12-col pf-c-content error-message">
                ${msg("authenticator.timeoutInfo")}
            </div>

            <#if client?? && client.baseUrl?has_content>
                <div class="pf-l-grid__item pf-m-12-col">
                    <@macros.LinkButton 
                        url=client.baseUrl 
                        label=msg("toHomePage") 
                        className=['pf-m-primary'] 
                        linkProperties=['id="backToApplication"'] 
                    />
                </div>
            </#if>
    </#if>
</@layout.registrationLayout>
