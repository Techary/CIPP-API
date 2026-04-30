function Invoke-ExecSetSPOSiteAuthContext {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Sharepoint.Site.ReadWrite
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $APIName = $Request.Params.CIPPEndpoint
    $Headers = $Request.Headers
    Write-LogMessage -Headers $Headers -API $APIName -message 'Accessed this API' -Sev Debug

    $TenantFilter = $Request.Body.tenantFilter ?? $Request.Query.tenantFilter
    $SiteUrl = $Request.Body.siteUrl ?? $Request.Query.siteUrl
    $ConditionalAccessPolicy = $Request.Body.conditionalAccessPolicy.value ?? $Request.Body.conditionalAccessPolicy ?? $Request.Query.conditionalAccessPolicy
    # Prefer .value (the raw displayName) over .label (the formatted "c1: name" display string).
    # The autocomplete sends both; the SPO API needs the exact displayName, not the prefixed label.
    $AuthenticationContextName = $Request.Body.authenticationContextName.value ?? $Request.Body.authenticationContextName.label ?? $Request.Body.authenticationContextName ?? $Request.Query.authenticationContextName

    $ValidPolicies = @('AllowFullAccess', 'AllowLimitedAccess', 'BlockAccess', 'AuthenticationContext')
    if (-not $TenantFilter -or -not $SiteUrl -or -not $ConditionalAccessPolicy) {
        return [HttpResponseContext]@{
            StatusCode = [HttpStatusCode]::BadRequest
            Body       = @{ Results = 'Error: tenantFilter, siteUrl and conditionalAccessPolicy are required.' }
        }
    }
    if ($ConditionalAccessPolicy -notin $ValidPolicies) {
        return [HttpResponseContext]@{
            StatusCode = [HttpStatusCode]::BadRequest
            Body       = @{ Results = "Error: conditionalAccessPolicy must be one of: $($ValidPolicies -join ', ')" }
        }
    }
    if ($ConditionalAccessPolicy -eq 'AuthenticationContext' -and [string]::IsNullOrWhiteSpace($AuthenticationContextName)) {
        return [HttpResponseContext]@{
            StatusCode = [HttpStatusCode]::BadRequest
            Body       = @{ Results = 'Error: authenticationContextName is required when conditionalAccessPolicy is AuthenticationContext.' }
        }
    }

    # Validate that the named auth context actually exists in Entra (and is available) before
    # we send a CSOM call that SPO would silently accept with any string. Catches typos that
    # would otherwise lock users out of the site against a non-existent context.
    if ($ConditionalAccessPolicy -eq 'AuthenticationContext') {
        try {
            $AuthContexts = New-GraphGetRequest -uri 'https://graph.microsoft.com/beta/identity/conditionalAccess/authenticationContextClassReferences' -tenantid $TenantFilter
            $MatchedContext = $AuthContexts | Where-Object { $_.displayName -eq $AuthenticationContextName } | Select-Object -First 1
            if (-not $MatchedContext) {
                $AvailableNames = (($AuthContexts | Where-Object { $_.isAvailable } | ForEach-Object { "'$($_.displayName)'" }) -join ', ')
                $ErrorBody = "Error: Authentication Context '$AuthenticationContextName' was not found in Entra for this tenant."
                if ($AvailableNames) {
                    $ErrorBody += " Available contexts: $AvailableNames."
                }
                Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -message $ErrorBody -Sev Warn
                return [HttpResponseContext]@{
                    StatusCode = [HttpStatusCode]::BadRequest
                    Body       = @{ Results = $ErrorBody }
                }
            }
            if ($MatchedContext.isAvailable -eq $false) {
                $ErrorBody = "Error: Authentication Context '$AuthenticationContextName' exists in Entra but is marked unavailable. Enable it before binding to a SharePoint site."
                Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -message $ErrorBody -Sev Warn
                return [HttpResponseContext]@{
                    StatusCode = [HttpStatusCode]::BadRequest
                    Body       = @{ Results = $ErrorBody }
                }
            }
        } catch {
            # Fail open: if Graph itself is unreachable we don't block the operation,
            # but record the validation skip so it's traceable.
            $ValidationError = Get-CippException -Exception $_
            Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -message "Could not validate Authentication Context against Entra ($($ValidationError.NormalizedError)); proceeding without validation." -Sev Warn
        }
    }

    try {
        $Result = Set-CIPPSPOSiteAuthContext -TenantFilter $TenantFilter `
            -SiteUrl $SiteUrl `
            -ConditionalAccessPolicy $ConditionalAccessPolicy `
            -AuthenticationContextName $AuthenticationContextName `
            -APIName $APIName `
            -Headers $Headers
        $StatusCode = [HttpStatusCode]::OK
    } catch {
        $Result = $_.Exception.Message
        $StatusCode = [HttpStatusCode]::InternalServerError
    }

    return [HttpResponseContext]@{
        StatusCode = $StatusCode
        Body       = @{ Results = $Result }
    }
}
