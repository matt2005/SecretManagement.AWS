function Get-ModuleRootPath
{
    [OutputType([System.IO.FileInfo])]
    param ()

    Join-Path -Path $PSScriptRoot -ChildPath '..\..' | Resolve-Path
}

function Get-ModuleCodePath
{
    [OutputType([System.IO.FileInfo])]
    [CmdletBinding()]
    param
    (
        [Parameter()]
        [String]
        $ModuleRootPath
    )

    $moduleFile = Get-ChildItem -Path $ModuleRootPath -Filter '*.psm1' -Recurse -Depth 1 | `
        Where-Object { $_.DirectoryName -match 'artifacts$' }

    return $moduleFile.DirectoryName | Resolve-Path
}

function Get-ModuleManifestPath
{
    [OutputType([System.IO.FileInfo])]
    [CmdletBinding()]
    param
    (
        [Parameter()]
        [String]
        $ModuleCodePath
    )

    [Array] $PowerShellDataFiles = Get-ChildItem -Path $ModuleCodePath -Filter '*.psd1'

    $manifestFile = @()

    foreach ($PowerShellDataFile in $PowerShellDataFiles)
    {
        $fileData = Import-PowerShellDataFile -Path $PowerShellDataFile.FullName

        if ($fileData.Keys -contains 'RootModule' -and $fileData.Keys -contains 'ModuleVersion')
        {
            $manifestFile += $PowerShellDataFile.FullName | Resolve-Path
        }
    }

    if ($manifestFile.Count -eq 1)
    {
        return $manifestFile
    }
    elseif ($manifestFile.Count -eq 0)
    {
        throw ('No module manifest found in path "{0}".' -f $ModuleCodePath)
    }
}

function Get-ModuleName
{
    [OutputType([String])]
    [CmdletBinding()]
    param
    (
        [Parameter()]
        [String]
        $ModuleManifestPath
    )

    $manifestFile = Get-Item -Path $ModuleManifestPath

    return $manifestFile.BaseName
}

function Get-FunctionNameForPester
{
    [OutputType([String])]
    param ()

    $callStack = (Get-PSCallStack)[2]

    $testFileName = $callStack.Command

    return $testFileName.SubString(0, $testFileName.IndexOf('.'))
}

function Get-PesterTestData
{
    [OutputType([HashTable])]
    param ()

    $moduleRootPath = Get-ModuleRootPath
    $moduleCodePath = Get-ModuleCodePath -ModuleRootPath $ModuleRootPath.Path
    $moduleManifestPath = Get-ModuleManifestPath -ModuleCodePath $moduleCodePath.Path
    $moduleName = Get-ModuleName -ModuleManifestPath $moduleManifestPath
    $functionName = Get-FunctionNameForPester

    return @{
        ModuleRootPath     = $moduleRootPath
        ModuleCodePath     = $moduleCodePath
        ModuleManifestPath = $moduleManifestPath
        ModuleName         = $moduleName
        FunctionName       = $functionName
    }
}