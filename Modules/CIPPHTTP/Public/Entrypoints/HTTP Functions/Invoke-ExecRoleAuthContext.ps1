function Invoke-ExecRoleAuthContext {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Identity.Role.ReadWrite
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $APIName = $Request.Params.CIPPEndpoint
    $Headers = $Request.Headers
    $TenantFilter = $Request.Body.tenantFilter ?? $Request.Query.tenantFilter
    $RoleDefinitionId = $Request.Body.roleDefinitionId ?? $Request.Query.roleDefinitionId
    # claimValue comes from a frontend autoComplete as { label, value } or as a plain string via query
    $RawClaim = $Request.Body.claimValue ?? $Request.Query.claimValue
    $ClaimValue = if ($RawClaim -is [string]) {
        $RawClaim
    } elseif ($null -ne $RawClaim.value) {
        [string]$RawClaim.value
    } else {
        $null
    }

    if (-not $RoleDefinitionId -or $RoleDefinitionId -notmatch '^[0-9a-fA-F-]{36}$') {
        return [HttpResponseContext]@{
            StatusCode = [HttpStatusCode]::BadRequest
            Body       = @{ Results = 'Error: roleDefinitionId is required and must be a GUID' }
        }
    }

    $ShouldEnable = -not [string]::IsNullOrWhiteSpace($ClaimValue)
    # Spec (https://learn.microsoft.com/en-us/graph/api/resources/authenticationcontextclassreference?view=graph-rest-1.0) says c1 > c25, Entra shows 1-199.
    # I'm going to keep in line with the spec but if YOU want to expand, update all three in unison:
    #   - this regex
    #   - Invoke-ExecAuthenticationContext.ps1 (id regex)
    #   - CIPP/src/components/CippComponents/CippAddAuthContextDrawer.jsx (ALL_IDS constant)
    if ($ShouldEnable -and $ClaimValue -notmatch '^c([1-9]|1[0-9]|2[0-5])$') {
        return [HttpResponseContext]@{
            StatusCode = [HttpStatusCode]::BadRequest
            Body       = @{ Results = 'Error: claimValue must be c1 through c25' }
        }
    }

    try {
        $AssignmentUri = "https://graph.microsoft.com/beta/policies/roleManagementPolicyAssignments?`$filter=scopeId eq '/' and scopeType eq 'DirectoryRole' and roleDefinitionId eq '$RoleDefinitionId'"
        $Assignments = New-GraphGetRequest -uri $AssignmentUri -tenantid $TenantFilter
        $PolicyId = ($Assignments | Select-Object -First 1).policyId
        if (-not $PolicyId) {
            throw "No role management policy assignment found for role definition $RoleDefinitionId. The role may not support PIM in this tenant."
        }

        $RuleUri = "https://graph.microsoft.com/beta/policies/roleManagementPolicies/$PolicyId/rules/AuthenticationContext_EndUser_Assignment"
        $RuleBody = [ordered]@{
            '@odata.type' = '#microsoft.graph.unifiedRoleManagementPolicyAuthenticationContextRule'
            id            = 'AuthenticationContext_EndUser_Assignment'
            isEnabled     = $ShouldEnable
            claimValue    = if ($ShouldEnable) { $ClaimValue } else { '' }
            target        = [ordered]@{
                caller              = 'EndUser'
                operations          = @('all')
                level               = 'Assignment'
                inheritableSettings = @()
                enforcedSettings    = @()
            }
        } | ConvertTo-Json -Depth 5

        $null = New-GraphPOSTRequest -uri $RuleUri -tenantid $TenantFilter -body $RuleBody -type PATCH

        $Result = if ($ShouldEnable) {
            "Successfully set activation authentication context to $ClaimValue"
        } else {
            'Successfully cleared activation authentication context requirement'
        }
        Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -message $Result -sev Info
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -message "Failed to set activation authentication context for role $($RoleDefinitionId): $($ErrorMessage.NormalizedError)" -sev Error -LogData $ErrorMessage
        $Result = "Failed: $($ErrorMessage.NormalizedError)"
        $StatusCode = [HttpStatusCode]::InternalServerError
    }

    return [HttpResponseContext]@{
        StatusCode = $StatusCode ?? [HttpStatusCode]::OK
        Body       = @{ Results = $Result }
    }
}
