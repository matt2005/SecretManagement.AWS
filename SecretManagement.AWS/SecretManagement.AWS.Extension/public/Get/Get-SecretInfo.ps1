function Get-SecretInfo
{
    [OutputType([Microsoft.PowerShell.SecretManagement.SecretInformation[]])]
    [CmdletBinding()]
    param
    (
        [Alias('Name')]
        [System.String]
        $Filter,

        [Alias('Vault')]
        [System.String]
        $VaultName,

        [System.Collections.Hashtable]
        $AdditionalParameters
    )

    # This is set by adding the Verbose switch to Get-Secret. Not by adding it to VaultParameters
    if ($AdditionalParameters['Verbose'])
    {
        $VerbosePreference = 'Continue'
    }

    $AdditionalParameters | Out-String | Write-Verbose
    [Microsoft.PowerShell.SecretManagement.SecretInformation[]] $secretsInfo = @()
    return [Microsoft.PowerShell.SecretManagement.SecretInformation[]] $secretsInfo
}