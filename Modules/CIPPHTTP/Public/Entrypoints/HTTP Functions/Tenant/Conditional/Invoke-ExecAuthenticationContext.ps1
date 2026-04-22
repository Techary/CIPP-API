function Invoke-ExecAuthenticationContext {
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
    $TenantFilter = $Request.Body.tenantFilter ?? $Request.Query.tenantFilter
    $Action = $Request.Body.Action ?? $Request.Query.Action
    $Id = $Request.Body.id ?? $Request.Query.id

    if (-not $Id -or $Id -notmatch '^c([1-9]|1[0-9]|2[0-5])$') {
        return [HttpResponseContext]@{
            StatusCode = [HttpStatusCode]::BadRequest
            Body       = @{ Results = 'Error: id must be c1 through c25' }
        }
    }

    $Uri = "https://graph.microsoft.com/beta/identity/conditionalAccess/authenticationContextClassReferences/$Id"

    try {
        switch ($Action) {
            'Add' {
                if (-not $Request.Body.displayName) {
                    return [HttpResponseContext]@{
                        StatusCode = [HttpStatusCode]::BadRequest
                        Body       = @{ Results = 'Error: displayName is required' }
                    }
                }
                $Body = [pscustomobject]@{
                    id          = $Id
                    displayName = $Request.Body.displayName
                    description = $Request.Body.description
                    isAvailable = if ($null -ne $Request.Body.isAvailable) { [System.Convert]::ToBoolean($Request.Body.isAvailable) } else { $true }
                } | ConvertTo-Json
                $null = New-GraphPOSTRequest -uri $Uri -tenantid $TenantFilter -body $Body -type PATCH
                $Result = "Successfully added authentication context $Id"
            }
            'Edit' {
                $EditBody = [ordered]@{}
                if ($null -ne $Request.Body.displayName) { $EditBody.displayName = $Request.Body.displayName }
                if ($null -ne $Request.Body.description) { $EditBody.description = $Request.Body.description }
                if ($null -ne $Request.Body.isAvailable) { $EditBody.isAvailable = [System.Convert]::ToBoolean($Request.Body.isAvailable) }
                if ($EditBody.Count -eq 0) {
                    return [HttpResponseContext]@{
                        StatusCode = [HttpStatusCode]::BadRequest
                        Body       = @{ Results = 'Error: no fields provided to edit' }
                    }
                }
                $Body = ConvertTo-Json -InputObject $EditBody
                $null = New-GraphPOSTRequest -uri $Uri -tenantid $TenantFilter -body $Body -type PATCH
                $Result = "Successfully updated authentication context $Id"
            }
            'Delete' {
                $null = New-GraphPOSTRequest -uri $Uri -tenantid $TenantFilter -type DELETE
                $Result = "Successfully deleted authentication context $Id"
            }
            default {
                $StatusCode = [HttpStatusCode]::BadRequest
                $Result = "Unknown action: $Action"
            }
        }
        if (-not $StatusCode) {
            Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -message $Result -sev Info
        }
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -message "Failed $Action authentication context $($Id): $($ErrorMessage.NormalizedError)" -sev Error -LogData $ErrorMessage
        $Result = "Failed: $($ErrorMessage.NormalizedError)"
        $StatusCode = [HttpStatusCode]::InternalServerError
    }

    return [HttpResponseContext]@{
        StatusCode = $StatusCode ?? [HttpStatusCode]::OK
        Body       = @{ Results = $Result }
    }
}
