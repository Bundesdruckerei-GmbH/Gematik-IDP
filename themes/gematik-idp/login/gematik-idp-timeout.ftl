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
