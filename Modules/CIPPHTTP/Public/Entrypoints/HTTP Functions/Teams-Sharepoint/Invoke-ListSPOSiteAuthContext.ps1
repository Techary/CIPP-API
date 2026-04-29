function Invoke-ListSPOSiteAuthContext {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Sharepoint.Site.Read
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $APIName = $Request.Params.CIPPEndpoint
    $Headers = $Request.Headers
    Write-LogMessage -Headers $Headers -API $APIName -message 'Accessed this API' -Sev Debug

    $TenantFilter = $Request.Body.tenantFilter ?? $Request.Query.tenantFilter
    $SiteUrl = $Request.Body.siteUrl ?? $Request.Query.siteUrl

    if (-not $TenantFilter -or -not $SiteUrl) {
        return [HttpResponseContext]@{
            StatusCode = [HttpStatusCode]::BadRequest
            Body       = @{ Results = 'Error: tenantFilter and siteUrl are required.' }
        }
    }

    $PolicyNameMap = @{
        0 = 'AllowFullAccess'
        1 = 'AllowLimitedAccess'
        2 = 'BlockAccess'
        3 = 'AuthenticationContext'
    }

    try {
        $SharePointInfo = Get-SharePointAdminLink -Public $false -tenantFilter $TenantFilter
        $AdminUrl = $SharePointInfo.AdminUrl

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
        $AdditionalHeaders = @{ 'Accept' = 'application/json;odata=verbose' }
        $Result = New-GraphPostRequest -scope "$AdminUrl/.default" -tenantid $TenantFilter -Uri "$AdminUrl/_vti_bin/client.svc/ProcessQuery" -Type POST -Body $ReadXML -ContentType 'text/xml' -AddedHeaders $AdditionalHeaders

        $ErrorInfo = $Result | Where-Object { $_.ErrorInfo -and $_.ErrorInfo.ErrorMessage } | Select-Object -First 1
        if ($ErrorInfo) {
            throw $ErrorInfo.ErrorInfo.ErrorMessage
        }

        $SiteProperties = $Result | Where-Object { $null -ne $_.ConditionalAccessPolicy } | Select-Object -Last 1
        if (-not $SiteProperties) {
            throw "Site '$SiteUrl' not found or properties not returned."
        }

        $PolicyInt = [int]$SiteProperties.ConditionalAccessPolicy
        $PolicyName = if ($PolicyNameMap.ContainsKey($PolicyInt)) { $PolicyNameMap[$PolicyInt] } else { "Unknown($PolicyInt)" }

        $ResponseBody = [pscustomobject]@{
            webUrl                       = $SiteUrl
            conditionalAccessPolicy      = $PolicyInt
            conditionalAccessPolicyName  = $PolicyName
            authenticationContextName    = [string]$SiteProperties.AuthenticationContextName
            isAuthContextActive          = ($PolicyInt -eq 3)
        }

        return [HttpResponseContext]@{
            StatusCode = [HttpStatusCode]::OK
            Body       = $ResponseBody
        }
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -message "Failed to read SPO site auth context for $($SiteUrl): $($ErrorMessage.NormalizedError)" -Sev Error -LogData $ErrorMessage
        return [HttpResponseContext]@{
            StatusCode = [HttpStatusCode]::InternalServerError
            Body       = @{ Results = "Failed: $($ErrorMessage.NormalizedError)" }
        }
    }
}
