<#macro IconText text="Click me" icon="" placement="start">
    <#assign label = kcSanitize(text)?no_esc />

    <#if icon == "" && (placement != 'start' || placement != 'end')>
        ${label}

        <#return />
    </#if>

    <#assign iconTag>
        <#compress>
            <span class="pf-c-button__icon pf-m-${placement}"><i class="fas ${icon}" aria-hidden="true"></i></span>
        </#compress>
    </#assign>

    <#if icon != "">
        <#if placement == 'start'>
            ${iconTag}${label}
        </#if>

        <#if placement == 'end'>
            ${label}${iconTag}
        </#if>
    <#else>
        ${label}
    </#if>
</#macro>

<#macro LinkButton url="#" label="" icon="" iconPlacement="start" className=[] linkProperties=[]>
    <#assign classes=['pf-c-button'] + className />
    <#assign properties=['href=${url}'] + linkProperties />

    <#if icon != "">
        <#assign classes= classes + ['pf-m-${iconPlacement}'] />
    </#if>

    <a
        <#if classes?size gt 0>class="${concatProperties(classes)}"</#if>
        <#if properties?size gt 0> ${concatProperties(properties)}</#if>
    >
        <@IconText text=label icon=icon placement=iconPlacement />
    </a>
</#macro>

<#function concatProperties properties=[]>
    <#assign propList>
        <#compress>
            <#list properties><#items as prop>${prop?no_esc}<#sep> </#items></#list>
        </#compress>
    </#assign>
    <#return propList />
</#function>
