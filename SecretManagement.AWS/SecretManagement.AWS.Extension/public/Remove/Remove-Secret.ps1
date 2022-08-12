function Remove-Secret
{
    [CmdletBinding(SupportsShouldProcess)]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '')]
    param
    (
        [Parameter(Mandatory)]
        [System.String]
        $Name,

        [Parameter(Mandatory)]
        [System.String]
        $VaultName,

        [System.Collections.Hashtable]
        $AdditionalParameters
    )

    Write-Warning -Message 'Function not implemented'

    if ($PSCmdlet.ShouldProcess('Add a credential'))
    {

    }
}