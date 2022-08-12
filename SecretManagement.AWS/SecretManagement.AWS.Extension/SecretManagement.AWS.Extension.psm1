$Enums = @( Get-ChildItem -Path $PSScriptRoot\Enums\*.ps*1 -ErrorAction SilentlyContinue -Recurse | Where-Object { $_.Name -notmatch '\.tests{0,1}\.ps1' } )
$Classes = @( Get-ChildItem -Path $PSScriptRoot\Classes\*.ps*1 -ErrorAction SilentlyContinue -Recurse | Where-Object { $_.Name -notmatch '\.tests{0,1}\.ps1' } )
$Data = @( Get-ChildItem -Path $PSScriptRoot\Data\*.ps*1 -ErrorAction SilentlyContinue -Recurse | Where-Object { $_.Name -notmatch '\.tests{0,1}\.ps1' } )
$Private = @( Get-ChildItem -Path $PSScriptRoot\Private\*.ps1 -ErrorAction SilentlyContinue -Recurse | Where-Object { $_.Name -notmatch '\.tests{0,1}\.ps1' } )
$Public  = @( Get-ChildItem -Path $PSScriptRoot\Public\*.ps1 -ErrorAction SilentlyContinue -Recurse | Where-Object { $_.Name -notmatch '\.tests{0,1}\.ps1' } )

foreach($FunctionFile in @($Enums + $Classes + $Data + $Private + $Public ))
{
    try
    {
        Write-Verbose -Message "  Importing $($FunctionFile.BaseName)"
        . $($FunctionFile.fullname)
    }
    catch
    {
        Write-Error -Message "Failed to import function $($FunctionFile.fullname): $_"
    }
}

Export-ModuleMember -Function $Public.Basename
