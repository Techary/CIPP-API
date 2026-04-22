function Invoke-AddCAPolicy {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Tenant.ConditionalAccess.ReadWrite
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $APIName = $Request.Params.CIPPEndpoint
    $Headers = $Request.Headers

    $Tenants = $Request.body.tenantFilter.value
    if ('AllTenants' -in $Tenants) { $Tenants = (Get-Tenants).defaultDomainName }

    $successCount = 0
    $results = foreach ($Tenant in $tenants) {
        try {
            $NewCAPolicy = @{
                replacePattern      = $Request.Body.replacename
                Overwrite           = $Request.Body.overwrite
                TenantFilter        = $Tenant
                state               = $Request.Body.NewState
                DisableSD           = $Request.Body.DisableSD
                CreateGroups        = $Request.Body.CreateGroups
                CreateAuthContexts  = [bool]$Request.Body.CreateAuthContexts
                AuthContextMapping  = $Request.Body.AuthContextMapping
                RawJSON             = $Request.Body.RawJSON
                APIName             = $APIName
                Headers             = $Headers
            }
            $CAPolicy = New-CIPPCAPolicy @NewCAPolicy
            $successCount += 1

            "$CAPolicy"
        } catch {
            "$($_.Exception.Message)"
            continue
        }

    }

    $body = [pscustomobject]@{'Results' = @($results) }
    $StatusCode = if ($successCount -eq 0) { [HttpStatusCode]::InternalServerError } else { [HttpStatusCode]::OK }

    return ([HttpResponseContext]@{
            StatusCode = $StatusCode
            Body       = $body
        })

}
