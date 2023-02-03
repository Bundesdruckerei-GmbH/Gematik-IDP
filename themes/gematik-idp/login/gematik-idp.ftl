<#import "template.ftl" as layout>

<@layout.registrationLayout bodyClass="authenticator-loading-page"; section>
    <#if section = "header">
        <div class="authenticator-loading-title">
            ${msg("authenticator.startingTitle")}
        </div>
    <#elseif section = "form">
        <div class="pf-c-content authenticator-loading-message">
            ${msg("authenticator.startingInfo")}
        </div>
    <#elseif section = "head">
        <script type="text/javascript">
            function timeout() {
                location.assign("${timeoutUrl}")
            }
            setTimeout(timeout, ${timeoutMs?c})
        </script>
        <meta http-equiv="refresh" content="1; URL=${authenticatorUrl}">
    </#if>
</@layout.registrationLayout>
