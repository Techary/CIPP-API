function Write-AlertTrace {
    <#
    .FUNCTIONALITY
        Internal function.
        Writes alert trace data to Azure Table Storage only when data changes.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $cmdletName,

        [Parameter(Mandatory)]
        $data,

        [Parameter(Mandatory)]
        $tenantFilter,

        [string]$PartitionKey = (Get-Date -UFormat '%Y%m%d'),

        [string]$AlertComment = $null
    )

    # Get table reference
    $Table = Get-CIPPTable -tablename AlertLastRun
    $RowKey = "$tenantFilter-$cmdletName"

    # Normalize alert data into a deterministic JSON string
    try {
        $NewLogData = ConvertTo-Json -InputObject $data -Depth 10 -Compress
    } catch {
        throw "Write-AlertTrace: Failed to serialize alert data to JSON: $($_.Exception.Message)"
    }

    # Attempt to get existing row
    try {
        $ExistingRow = Get-CIPPAzDataTableEntity @Table `
            -Filter "PartitionKey eq '$PartitionKey' and RowKey eq '$RowKey'"
    } catch {
        $ExistingRow = $null
    }

    # Extract old LogData safely
    $OldLogData = $null
    if ($ExistingRow -and $ExistingRow.PSObject.Properties.Name -contains 'LogData') {
        $OldLogData = $ExistingRow.LogData
    }

    # If data has not changed, do nothing
    if ($OldLogData -eq $NewLogData) {
        return
    }

    # Build entity to write
    $Entity = @{
        PartitionKey = $PartitionKey
        RowKey       = $RowKey
        CmdletName   = $cmdletName
        Tenant       = $tenantFilter
        LogData      = $NewLogData
    }

    if ($AlertComment) {
        $Entity.AlertComment = $AlertComment
    }

    # Write (upsert via Force)
    $Table.Entity = $Entity
    Add-CIPPAzDataTableEntity @Table -Force | Out-Null

    # Return data to alert pipeline
    return $data
}
