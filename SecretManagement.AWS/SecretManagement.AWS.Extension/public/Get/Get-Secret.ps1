function Get-Secret
{
    [CmdletBinding()]
    param
    (
        [System.String]
        $Name,

        [System.String]
        $VaultName,

        [System.Collections.Hashtable]
        $AdditionalParameters = (Get-SecretVault -Name $Vault).VaultParameters
    )

    # This is set by adding the Verbose switch to Get-Secret. Not by adding it to VaultParameters
    if ($AdditionalParameters['Verbose'])
    {
        $VerbosePreference = 'Continue'
    }

    $AdditionalParameters | Out-String | Write-Verbose
}