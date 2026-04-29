function Set-CIPPSPOSiteAuthContext {
    <#
    .SYNOPSIS
    Set the Conditional Access policy / Authentication Context on a SharePoint site

    .DESCRIPTION
    Wraps the Microsoft.Online.SharePoint.TenantAdministration.Tenant CSOM ProcessQuery
    endpoint to set the ConditionalAccessPolicy and AuthenticationContextName properties
    on a SiteProperties object - the same call Set-SPOSite makes under the hood.

    .PARAMETER TenantFilter
    Tenant to apply the change to.

    .PARAMETER SiteUrl
    Full SharePoint site URL (e.g. https://contoso.sharepoint.com/sites/research).

    .PARAMETER ConditionalAccessPolicy
    One of: AllowFullAccess, AllowLimitedAccess, BlockAccess, AuthenticationContext.
    Use AllowFullAccess to clear any auth context previously applied (reversal).

    .PARAMETER AuthenticationContextName
    Display name of the Entra authentication context (e.g. "c1: ..."). Required when
    ConditionalAccessPolicy is AuthenticationContext, ignored otherwise.

    .EXAMPLE
    Set-CIPPSPOSiteAuthContext -TenantFilter 'contoso.onmicrosoft.com' `
        -SiteUrl 'https://contoso.sharepoint.com/sites/research' `
        -ConditionalAccessPolicy 'AuthenticationContext' `
        -AuthenticationContextName 'Sensitive information - guest terms of use'

    .EXAMPLE
    # Reversal - remove auth context binding
    Set-CIPPSPOSiteAuthContext -TenantFilter 'contoso.onmicrosoft.com' `
        -SiteUrl 'https://contoso.sharepoint.com/sites/research' `
        -ConditionalAccessPolicy 'AllowFullAccess'
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantFilter,
        [Parameter(Mandatory = $true)]
        [string]$SiteUrl,
        [Parameter(Mandatory = $true)]
        [ValidateSet('AllowFullAccess', 'AllowLimitedAccess', 'BlockAccess', 'AuthenticationContext')]
        [string]$ConditionalAccessPolicy,
        [string]$AuthenticationContextName,
        [string]$APIName = 'Set SPO Site Auth Context',
        $Headers
    )

    $PolicyValue = switch ($ConditionalAccessPolicy) {
        'AllowFullAccess'        { 0 }
        'AllowLimitedAccess'     { 1 }
        'BlockAccess'            { 2 }
        'AuthenticationContext'  { 3 }
    }

    if ($ConditionalAccessPolicy -eq 'AuthenticationContext' -and [string]::IsNullOrWhiteSpace($AuthenticationContextName)) {
        throw 'AuthenticationContextName is required when ConditionalAccessPolicy is AuthenticationContext.'
    }

    $SharePointInfo = Get-SharePointAdminLink -Public $false -tenantFilter $TenantFilter
    $AdminUrl = $SharePointInfo.AdminUrl

    # When clearing the binding, also blank the context name to avoid stale display state.
    $ContextNameToSet = if ($ConditionalAccessPolicy -eq 'AuthenticationContext') {
        $AuthenticationContextName
    } else {
        ''
    }

    $XML = @"
<Request xmlns="http://schemas.microsoft.com/sharepoint/clientquery/2009" AddExpandoFieldTypeSuffix="true" SchemaVersion="15.0.0.0" LibraryVersion="16.0.0.0" ApplicationName=".NET Library">
  <Actions>
    <ObjectPath Id="3" ObjectPathId="2" />
    <SetProperty Id="4" ObjectPathId="2" Name="ConditionalAccessPolicy">
      <Parameter Type="Number">$PolicyValue</Parameter>
    </SetProperty>
    <SetProperty Id="5" ObjectPathId="2" Name="AuthenticationContextName">
      <Parameter Type="String">$([System.Security.SecurityElement]::Escape($ContextNameToSet))</Parameter>
    </SetProperty>
    <Method Name="Update" Id="6" ObjectPathId="2" />
  </Actions>
  <ObjectPaths>
    <Constructor Id="1" TypeId="{268004ae-ef6b-4e9b-8425-127220d84719}" />
    <Method Id="2" ParentId="1" Name="GetSitePropertiesByUrl">
      <Parameters>
        <Parameter Type="String">$([System.Security.SecurityElement]::Escape($SiteUrl))</Parameter>
        <Parameter Type="Boolean">true</Parameter>
      </Parameters>
    </Method>
  </ObjectPaths>
</Request>
"@

    $AdditionalHeaders = @{
        'Accept' = 'application/json;odata=verbose'
    }

    $PolicyNameMap = @{
        0 = 'AllowFullAccess'
        1 = 'AllowLimitedAccess'
        2 = 'BlockAccess'
        3 = 'AuthenticationContext'
    }

    # Read current state for audit logging (before/after capture).
    # Failure to read does not block the change - we just log "unknown" prior state.
    $PreviousPolicy = 'unknown'
    $PreviousContextName = ''
    try {
        $ReadXML = @"
<Request xmlns="http://schemas.microsoft.com/sharepoint/clientquery/2009" AddExpandoFieldTypeSuffix="true" SchemaVersion="15.0.0.0" LibraryVersion="16.0.0.0" ApplicationName=".NET Library">
  <Actions>
    <ObjectPath Id="3" ObjectPathId="2" />
    <Query Id="4" ObjectPathId="2">
      <Query SelectAllProperties="false">
        <Properties>
          <Property Name="ConditionalAccessPolicy" ScalarProperty="true" />
          <Property Name="AuthenticationContextName" ScalarProperty="true" />
        </Properties>
      </Query>
    </Query>
  </Actions>
  <ObjectPaths>
    <Constructor Id="1" TypeId="{268004ae-ef6b-4e9b-8425-127220d84719}" />
    <Method Id="2" ParentId="1" Name="GetSitePropertiesByUrl">
      <Parameters>
        <Parameter Type="String">$([System.Security.SecurityElement]::Escape($SiteUrl))</Parameter>
        <Parameter Type="Boolean">true</Parameter>
      </Parameters>
    </Method>
  </ObjectPaths>
</Request>
"@
        $CurrentState = New-GraphPostRequest -scope "$AdminUrl/.default" -tenantid $TenantFilter -Uri "$AdminUrl/_vti_bin/client.svc/ProcessQuery" -Type POST -Body $ReadXML -ContentType 'text/xml' -AddedHeaders $AdditionalHeaders
        $CurrentProps = $CurrentState | Where-Object { $null -ne $_.ConditionalAccessPolicy } | Select-Object -Last 1
        if ($CurrentProps) {
            $CurrentPolicyInt = [int]$CurrentProps.ConditionalAccessPolicy
            if ($PolicyNameMap.ContainsKey($CurrentPolicyInt)) {
                $PreviousPolicy = $PolicyNameMap[$CurrentPolicyInt]
            } else {
                $PreviousPolicy = "unknown($CurrentPolicyInt)"
            }
            $PreviousContextName = [string]$CurrentProps.AuthenticationContextName
        }
    } catch {
        Write-Information "Could not read current SPO site CA state for $($SiteUrl): $($_.Exception.Message)"
    }

    $PreviousDescription = if ($PreviousPolicy -eq 'AuthenticationContext') {
        "ConditionalAccessPolicy=AuthenticationContext, AuthenticationContextName='$PreviousContextName'"
    } else {
        "ConditionalAccessPolicy=$PreviousPolicy"
    }
    $TargetDescription = if ($ConditionalAccessPolicy -eq 'AuthenticationContext') {
        "ConditionalAccessPolicy=AuthenticationContext, AuthenticationContextName='$AuthenticationContextName'"
    } else {
        "ConditionalAccessPolicy=$ConditionalAccessPolicy"
    }

    if (-not $PSCmdlet.ShouldProcess($SiteUrl, "Set $TargetDescription (was $PreviousDescription)")) {
        return "Skipped (WhatIf): $SiteUrl -> $TargetDescription (was $PreviousDescription)"
    }

    try {
        $Result = New-GraphPostRequest -scope "$AdminUrl/.default" -tenantid $TenantFilter -Uri "$AdminUrl/_vti_bin/client.svc/ProcessQuery" -Type POST -Body $XML -ContentType 'text/xml' -AddedHeaders $AdditionalHeaders

        $ErrorInfo = $Result | Where-Object { $_.ErrorInfo -and $_.ErrorInfo.ErrorMessage } | Select-Object -First 1
        if ($ErrorInfo) {
            $Message = "Failed to set auth context on $($SiteUrl) (was $PreviousDescription): $($ErrorInfo.ErrorInfo.ErrorMessage)"
            Write-LogMessage -headers $Headers -API $APIName -message $Message -Sev Error -tenant $TenantFilter
            throw $Message
        }

        $Message = "Set $TargetDescription on $SiteUrl (was $PreviousDescription)"
        Write-LogMessage -headers $Headers -API $APIName -message $Message -Sev Info -tenant $TenantFilter
        return $Message
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        $Message = "Failed to set auth context on $($SiteUrl) (was $PreviousDescription): $($ErrorMessage.NormalizedError)"
        Write-LogMessage -headers $Headers -API $APIName -message $Message -Sev Error -tenant $TenantFilter -LogData $ErrorMessage
        throw $Message
    }
}
