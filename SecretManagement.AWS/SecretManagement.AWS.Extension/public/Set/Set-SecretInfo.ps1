function Set-SecretInfo
{
    [CmdletBinding(SupportsShouldProcess)]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '')]
    param
    (
        [Parameter(Mandatory)]
        [System.String]
        $Name,

        [Parameter(Mandatory)]
        [System.Collections.Hashtable]
        $Metadata,

        [Parameter(Mandatory)]
        [System.String]
        $Vault,

        [System.Collections.Hashtable]
        $AdditionalParameters
    )

    Write-Warning -Message 'Function not implemented'

    if ($PSCmdlet.ShouldProcess('Add a credential'))
    {

    }
}
