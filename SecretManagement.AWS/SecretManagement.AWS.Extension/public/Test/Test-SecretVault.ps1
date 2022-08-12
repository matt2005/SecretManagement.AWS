function Test-SecretVault
{
    [OutputType([System.Boolean])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [System.String]
        $VaultName,

        [System.Collections.Hashtable]
        $AdditionalParameters = (Get-SecretVault -Name $VaultName).VaultParameters
    )

    # This is set by adding the Verbose switch to Get-Secret. Not by adding it to VaultParameters
    if ($AdditionalParameters['Verbose'])
    {
        $VerbosePreference = 'Continue'
    }

    $AdditionalParameters | Out-String | Write-Verbose
    if ($null -eq ($AdditionalParameters['AWSParameters']))
    {
        Write-Error -Message 'AWS Parameters not specified.'
        return $false
    }
    if ([string]::IsNullOrWhitespace(($AdditionalParameters['AWSParameters'])['Region']) -eq $true )
    {
        Write-Error -Message 'AWS Region not specified.'
        return $false
    }
    if ([string]::IsNullOrWhitespace($AdditionalParameters['VaultPath']) -eq $true )
    {
        Write-Error -Message 'VaultPath not specified.'
        return $false
    }
}