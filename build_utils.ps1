function Set-ProxySettings
{
    [CmdletBinding()]
    param ( #could improve with parameter sets
        [Parameter(Mandatory = $false)]
        [bool]$AutomaticDetect = $true
        ,
        [Parameter(Mandatory = $false)]
        [bool]$UseProxyForLAN = $false
        ,
        [Parameter(Mandatory = $false)]
        [AllowNull()][AllowEmptyString()]
        [string]$ProxyAddress = $null
        ,
        [Parameter(Mandatory = $false)]
        [int]$ProxyPort = 8080 #closest we have to a default port for proxies
        ,
        [AllowNull()][AllowEmptyString()]
        [bool]$UseAutomaticConfigurationScript = $false
    )
    begin
    {
        [string]$ProxyRegRoot = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
        [string]$DefaultConnectionSettingsPath = (Join-Path $ProxyRegRoot 'Connections')
        [byte]$MaskProxyEnabled = 2
        [byte]$MaskUseAutomaticConfigurationScript = 4
        [byte]$MaskAutomaticDetect = 8
        [int]$ProxyConnectionSettingIndex = 8
    }
    process
    {
        #this setting is affected by multiple options, so fetch once here
        [byte[]]$DefaultConnectionSettings = Get-ItemProperty -Path $DefaultConnectionSettingsPath -Name 'DefaultConnectionSettings' | Select-Object -ExpandProperty 'DefaultConnectionSettings'
        #region auto detect
        if ($AutomaticDetect)
        {
            Set-ItemProperty -Path $ProxyRegRoot -Name AutoDetect -Value 1
            $DefaultConnectionSettings[$ProxyConnectionSettingIndex] = $DefaultConnectionSettings[$ProxyConnectionSettingIndex] -bor $MaskAutomaticDetect
        }
        else
        {
            Set-ItemProperty -Path $ProxyRegRoot -Name AutoDetect -Value 0
            $DefaultConnectionSettings[$ProxyConnectionSettingIndex] = $DefaultConnectionSettings[$ProxyConnectionSettingIndex] -band (-bnot $MaskAutomaticDetect)
        }
        #endregion
        #region defined proxy
        if ($UseProxyForLAN)
        {
            if (-not ([string]::IsNullOrWhiteSpace($ProxyAddress)))
            {
                Set-ItemProperty -Path $ProxyRegRoot -Name ProxyServer -Value ("{0}:{1}" -f $ProxyAddress, $ProxyPort)
            }
            Set-ItemProperty -Path $ProxyRegRoot -Name ProxyEnable -Value 1
            $DefaultConnectionSettings[$ProxyConnectionSettingIndex] = $DefaultConnectionSettings[$ProxyConnectionSettingIndex] -bor $MaskProxyEnabled
        }
        else
        {
            Set-ItemProperty -Path $ProxyRegRoot -Name ProxyEnable -Value 0
            $DefaultConnectionSettings[$ProxyConnectionSettingIndex] = $DefaultConnectionSettings[$ProxyConnectionSettingIndex] -band (-bnot $MaskProxyEnabled)
        }
        #endregion
        #region config script
        if ($UseAutomaticConfigurationScript)
        {
            $DefaultConnectionSettings[$ProxyConnectionSettingIndex] = $DefaultConnectionSettings[$ProxyConnectionSettingIndex] -bor $MaskUseAutomaticConfigurationScript
        }
        else
        {
            $DefaultConnectionSettings[$ProxyConnectionSettingIndex] = $DefaultConnectionSettings[$ProxyConnectionSettingIndex] -band (-bnot $MaskUseAutomaticConfigurationScript)
        }
        #endregion
        #persist the updates made above
        Set-ItemProperty -Path $DefaultConnectionSettingsPath -Name 'DefaultConnectionSettings' -Value $DefaultConnectionSettings
    }
}
Function SignModule
{
    Param(
        [String]$Artifacts
    )
    $cert = GetSigningCert
    If ($cert)
    {
        Foreach ($file in (Get-childItem -Path $Artifacts -filter '*.ps*1*'))
        {
            Write-Verbose -Message ('Sigining file: {0}' -f $file.Name)
            $null = Set-AuthenticodeSignature -FilePath $file.FullName -Certificate $Cert
        }
    }
}

Function GetSigningCert
{
    $cert = (Get-ChildItem -Path 'Cert:\CurrentUser\My').Where{
        $psitem.Extensions.ForEach{
            if ($psitem.Oid.FriendlyName -eq 'Certificate Template Information')
            {
                $psitem.Format($true) -match 'Code Signing'
            }
        } -and
        $psitem.NotBefore -le [DateTime]::Now -and
        $psitem.NotAfter -ge ([DateTime]::Now).AddDays(90)
    } | sort-object NotAfter -Descending | select-object -first 1
    IF (!($cert))
    {
        try
        {
            $cert = (Get-Certificate -Template 'CodeSigning' -CertStoreLocation 'Cert:\CurrentUser\my').Certificate
        }
        Catch
        {
            Write-Warning -Message 'Unable to request CodeSigning Certificate'
        }
    }
    return $cert
}



function Publish-NugetModule
{
    <#
    .SYNOPSIS
    Publishes a PowerShell Module.

    .EXAMPLE
    $ModuleInfo = @{
        RepoName   = 'PoshRepo'
        RepoPath   = '\\server\PoshRepo'
        ModuleName = 'BuildHelpersTest'
        ModulePath = '.\BuildHelpersTest.psd1'
    }

    Publish-NuGetModule @ModuleInfo
#>
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '', Justification = "Placeholder")]
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [string] $RepoName,

        [Parameter(Mandatory = $true)]
        [string] $RepoPath,

        [Parameter(Mandatory = $true)]
        [string] $ScriptPath,

        [Parameter(Mandatory = $true)]
        [string] $ModuleName,

        [Parameter(Mandatory = $true)]
        [string] $ModulePath,

        [Parameter(Mandatory = $true)]
        [int] $BuildNumber,

        [string[]] $Tags,

        [string]$NuGetRepoAPIKey,
        [switch]$AllowPreRelease,
        [switch]$RemoveRepoAfterPublish,
        [string] $licenseUrl,
        [string] $projectUrl,
        [string] $iconUrl
    )
    $artifacts = Join-Path -Path $pwd -ChildPath "artifacts"
    # Just force it x.x
    $NugetPath = Install-Nuget -Path $(Resolve-Path -Path "$ModulePath\dependencies")

    # Register as Repository
    Write-Verbose -Message ("Checking if Repo: {0} is registered" -f $RepoName)
    $REPOParams = @{
        Name                  = $RepoName
        SourceLocation        = $RepoPath
        ScriptSourceLocation  = $ScriptPath
        InstallationPolicy    = 'Trusted'
        PublishLocation       = $RepoPath
        ScriptPublishLocation = $ScriptPath
    }
    if (Get-PSRepository -Name $RepoName -ErrorAction SilentlyContinue)
    {
        Write-Verbose -Message ("Unregistering Repo: {0}" -f $RepoName)
        Unregister-PSRepository -Name $RepoName
    }
    Write-Verbose -Message ("Registering Repo: {0}" -f $RepoName)
    Register-PSRepository @REPOParams
    $TempModulePath = New-Item -ItemType Directory -Path $Artifacts\$ModuleName -Force
    # sign module
    try
    {
        $cert = GetSigningCert
        If ($Cert)
        {
            SignModule -Artifacts $Artifacts
        }
    }
    Catch
    {
        Throw 'Error Signing Module'
    }
    # copy module to temp location
    Foreach ($file in (Get-childItem -Path $Artifacts -filter '*.ps*1*'))
    {
        Copy-Item -Path $file.FullName -Destination $TempModulePath
    }
    Foreach ($item in ('DSCResources','DSCClassResources'))
    {
        IF (Test-Path -Path (Join-Path -Path $Artifacts -ChildPath $Item))
        {
            Copy-Item -Path (Join-Path -Path $Artifacts -ChildPath $Item) -Destination (Join-Path -Path $TempModulePath -ChildPath $Item) -Recurse
        }
    }
    Foreach ($file in (Get-childItem -Path "$Artifacts" -filter '*.ps*1*'))
    {
        Copy-Item -Path $file.FullName -Destination $TempModulePath
    }
    # Catalog File
    # Create the catalog file
    try
    {
        $cert = GetSigningCert
        If ($cert)
        {
            $CatalogParams = @{
                Path            = $TempModulePath
                CatalogFilePath = Join-Path -Path $TempModulePath -ChildPath ('{0}.cat' -f $ModuleName)
                CatalogVersion  = '2.0'
                Verbose         = $true
            }
            New-FileCatalog @CatalogParams
            $CatlogFile = Get-Item -Path $CatalogParams.CatalogFilePath
            Write-Verbose -Message ('Sigining file: {0}' -f $CatlogFile.Name)
            Set-AuthenticodeSignature -FilePath $CatlogFile.FullName -Certificate $Cert
        }
    }
    catch
    {
        Throw 'Error Creating Catalog file'
    }
    # Publish ModuleInfo
    # - Fails if NuGet install needs confirmation in NonInteractive Mode.
    Write-Verbose -Message ("Publishing Module: {0} Version: {1}" -f $ModuleName, $version)
    try
    {
        $PublishParams = @{
            Repository = $RepoName
            Name       = $TempModulePath
            Force      = $true
        }
        IF ($AllowPreRelease.IsPresent)
        {
            $PublishParams.AllowPrerelease = $true
        }
        IF ($Tags)
        {
            $PublishParams.Tags = $Tags
        }
        IF ($licenseUrl)
        {
            $PublishParams.licenseUri = $licenseUrl
        }
        IF ($iconUrl)
        {
            $PublishParams.iconUri = $iconUrl
        }
        IF ($projectUrl)
        {
            $PublishParams.ProjectUri = $projectUrl
        }
        IF ($NuGetRepoAPIKey)
        {
            $PublishParams.NugetApiKey = $NuGetRepoAPIKey
        }
        #Publish to Repo
        Write-Verbose -Message ('Parameters: {0}' -f ($PublishParams | ft | out-string))
        Publish-Module @PublishParams
        # Remove repo after publish
        If ($RemoveRepoAfterPublish.IsPresent)
        {
            if (Get-PSRepository -Name $RepoName -ErrorAction SilentlyContinue)
            {
                Write-Verbose -Message ("Unregistering Repo: {0}" -f $RepoName)
                Unregister-PSRepository -Name $RepoName
            }
        }
    }
    catch [System.Exception]
    {
        # Write-Error "Publish Failed"
        throw($_.Exception)
    }
}
function Publish-ArtifactZip
{

    <#
    .SYNOPSIS
        Create a Zip Archive Build Artifact
#>
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('InjectionHunter\Measure-AddType', '', Justification = "Required for the function to work to create zip")]
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [string] $ModuleName,

        [Parameter(Mandatory = $true)]
        [int] $BuildNumber
    )

    # Creating project artifact
    $artifactPath = Join-Path -Path $pwd -ChildPath "artifacts"
    $modulePath = Join-Path -Path $pwd -ChildPath "$ModuleName"
    $zipFilePath = Join-Path -Path $artifactPath -ChildPath "$ModuleName.zip"
    Add-Type -assemblyname System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::CreateFromDirectory($modulePath, $zipFilePath)
}
function Build-NugetPackage
{
    <#
    .SYNOPSIS
        Create a NuGet Package for the Build Artifact
        Simple wrapper around DscResourceTestHelper Module
#>
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '', Justification = "Required for the function to work")]
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMOreThanAssignments', '', Justification = "Placeholder")]
    param
    (
        [Parameter(Mandatory = $true)]
        [string] $packageName,
        [Parameter(Mandatory = $true)]
        [string] $author,
        [Parameter(Mandatory = $true)]
        [int] $BuildNumber,
        [Parameter(Mandatory = $true)]
        [string] $owners,
        [string] $licenseUrl,
        [string] $projectUrl,
        [string] $iconUrl,
        [string] $packageDescription,
        [string] $releaseNotes,
        [string[]] $tags,
        [Parameter(Mandatory = $true)]
        [string] $destinationPath
    )

    $artifactPath = Join-Path -Path $pwd -ChildPath "artifacts"
    $BuiltModule = @{
        ModuleManifest = (Join-Path -Path $artifactPath -ChildPath "$ModuleName.psd1")
        ModuleFile     = (Join-Path -Path $artifactPath -ChildPath "$ModuleName.psm1")
    }
    IF ($Tags.Count -gt 1)
    {
        $ModuleTags = ($Tags | select -unique) -join ','
    }

    $CurrentVersion = (Get-Module -FullyQualifiedName $BuiltModule.ModuleManifest -ListAvailable).Version -as [version]
    $version = NormalizeVersion -version $currentversion


    Write-Verbose -Message ('Module version is: {0}' -f $version.ToString())
    <#
    $moduleInfo = @{
        packageName        = $packageName
        version            = ($version.ToString())
        author             = $author
        owners             = $owners
        licenseUrl         = $licenseUrl
        projectUrl         = $projectUrl
        packageDescription = $packageDescription
        tags               = $ModuleTags
        destinationPath    = $destinationPath
    }
    #>
    <#
    $moduleInfov2 = @{
        packageID          = $packageName
        packageVersion     = ($version.ToString())
        author             = $author
        owners             = $owners
        licenseUrl         = $licenseUrl
        projectUrl         = $projectUrl
        packageDescription = $packageDescription
        tags               = $ModuleTags
        OutputPath         = $TempModulePath
    }
    # Creating NuGet package artifact
    #Import-Module -Name DscResourceTestHelper
    #New-Nuspec @moduleInfo
    NewNuSpecXMLFile @moduleInfov2

    # Bootstrap NuGet if we don't have it
    if (-not ($NugetPath = (Get-Command -Name 'nuget.exe' -ErrorAction SilentlyContinue).Path))
    {
        $NugetPath = Install-Nuget -Path $(Resolve-Path -Path "$destinationPath\dependencies")
    }
    . $NugetPath pack "$TempModulePath\$packageName.nuspec" -OutputDirectory $TempModulePath

    #Publish to test repo
    $TestRepo=$Settings.NuGetScriptRepoPath
    $nugetPackage=Get-ChildItem -Path $destinationPath -File | where {($_.Name -match $packageName) -and ($_.extension -match 'nupkg')}
    Write-Verbose -Message ('Push to repo ({0}), using NuGet' -f $RepoPath)
    IF ($NuGetRepoAPIKey){
        Write-Verbose -Message 'Using API Key'
        #. $NugetPath push $nugetPackage -Source $RepoPath -ApiKey $NuGetRepoAPIKey
    }
    Else
    {
        Write-Verbose -Message 'API not used'
        #. $NugetPath push $nugetPackage -Source $RepoPath
    }
    #>
    <#
    # publish module locally
    $PublishLocalParams=@{
        RepoName = ('TempLocal_{0}_{1}' -f $ModuleName, $env:GIT_BRANCH)
        RepoPath = $destinationPath
        ScriptPath = $destinationPath
        ModuleName  = $ModuleName
        ModulePath = $destinationPath
        BuildNumber = $BuildNumber
        Tags = $Tags
        AllowPreRelease = $true
        RemoveRepoAfterPublish = $true
        licenseUrl = $licenseUrl
        projectUrl= $projectUrl
        iconUrl = $iconUrl
    }
    Publish-NugetModule @PublishLocalParams
    #>

}
function Install-Nuget
{
    <#
    .SYNOPSIS
        Used to address problem running Publish-Module in NonInteractive Mode when Nuget is not present.

    .NOTES
        https://github.com/OneGet/oneget/issues/173
        https://github.com/PowerShell/PowerShellGet/issues/79

        If Build Agent does not have permission to ProgramData Folder, may want to use the user specific folder.

        Package Provider Expected Locations (x86):
            C:\Program Files (x86)\PackageManagement\ProviderAssemblies
            C:\Users\{USER}\AppData\Local\PackageManagement\ProviderAssemblies
#>
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $false)]
        [switch] $Force = $false,
        [string]$Path = $( Join-Path -Path ([Environment]::GetFolderPath('MyDocuments')) -ChildPath 'WindowsPowerShell\Modules')
    )
    # Force Update Provider
    #Install-PackageProvider -Name Nuget -Force

    #$sourceNugetExe = "http://nuget.org/nuget.exe"
    $SourceNugetExe = 'https://dist.nuget.org/win-x86-commandline/latest/nuget.exe'
    try
    {

        if (-not ($NugetPath = (Get-Command -Name 'nuget.exe' -ErrorAction SilentlyContinue).Path))
        {
            $NugetPath = Join-Path -Path $path -ChildPath nuget.exe
            if (-not (Test-Path -Path $NugetPath))
            {
                Invoke-WebRequest -uri $sourceNugetExe -OutFile $NugetPath
            }
        }
    }
    Catch
    {
        Throw
    }
    Return $NugetPath
}

function Publish-CoverageHTML
{
    <#
        .SYNOPSIS
            Quick Attempt to create a HTML page to publish during CI builds
    #>
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [PSCustomObject] $TestResults,

        [Parameter(Mandatory = $true)]
        [int] $BuildNumber,

        [Parameter(Mandatory = $true)]
        [string] $Repository,

        [Parameter(Mandatory = $true)]
        [int] $PercentCompliance,

        [Parameter(Mandatory = $true)]
        [string] $OutputFile
    )

    $HitTable = $TestResults.CodeCoverage.HitCommands | ConvertTo-Html -Fragment
    $MissedTable = $TestResults.CodeCoverage.MissedCommands | ConvertTo-Html -Fragment
    $CommandsAnalyzed = $TestResults.CodeCoverage.NumberOfCommandsAnalyzed
    $FilesAnalyzed = $TestResults.CodeCoverage.NumberOfFilesAnalyzed
    $CommandsExecuted = $TestResults.CodeCoverage.NumberOfCommandsExecuted
    $CommandsMissed = $TestResults.CodeCoverage.NumberOfCommandsMissed

    $CoveragePercent = [math]::Round(($CommandsExecuted / $CommandsAnalyzed * 100), 2)
    $Date = (Get-Date)

    $AnalyzedFiles = "";
    foreach ($file in $TestResults.CodeCoverage.analyzedfiles)
    {
        $AnalyzedFiles += "<li>$file</li>"
    }

    $BuildColor = 'green'
    if ($CoveragePercent -lt $PercentCompliance)
    {
        $BuildColor = 'red'
    }

    $html = "
    <!DOCTYPE html>
    <html lang='en'>
    <head>
        <meta charset='UTF-8'>
        <title>Document</title>
        <style>
            body{font-family: sans-serif;}
            h2{margin: 0;}
            table{width: 100%;text-align: left;border-collapse: collapse;margin-top: 10px;}
            table th, table td {padding: 2px 16px 2px 0;border-bottom: 1px solid #9e9e9e;}
            table thead th {border-width: 2px;}
            .green{color: green;}
            .red{color: red;}
            .container {margin: 0 auto;width: 70%;}
            .analyzed, .coverage, .hit, .missed {padding: 10px;margin-bottom: 20px;border-radius: 6px;}
            .analyzed{ background: #BDE6FF;}
            .coverage{ background: #ECECEC;}
            .hit{ background: #BEFFC1; }
            .hit table td, .hit table th{ border-color: #5d925f;}
            .missed{ background: #FFC9C9;}
            .missed table td, .missed table th{ border-color: #804646;}
        </style>
    </head>
    <body>
    <div class='container'>
        <h1>Pester Coverage Report</h1>
        <!-- CI Meta -->
        <ul>
            <li><strong>Build:</strong> $($BuildNumber)</li>
            <li><strong>Repo:</strong> $($Repository)</li>
            <li><strong>Generated on:</strong> $($Date)</li>
        </ul>
        <!-- Overview -->
        <div class='coverage'>
            <h2>Coverage: <span class='$($BuildColor)'>$($CoveragePercent) %</span></h2>
            <table>
                <thead>
                    <tr>
                        <th>Metric</th>
                        <th>Value</th>
                    </tr>
                </thead>
                <tr>
                    <td>Commands Analyzed</td>
                    <td>$($CommandsAnalyzed)</td>
                </tr>
                <tr>
                    <td>Files Analyzed</td>
                    <td>$($FilesAnalyzed)</td>
                </tr>
                <tr>
                    <td>Commands Executed</td>
                    <td>$($CommandsExecuted)</td>
                </tr>
                <tr>
                    <td>Commands Missed</td>
                    <td>$($CommandsMissed)</td>
                </tr>
            </table>
        </div>
        <div class='analyzed'>
            <h2>Files Analyzed: $($FilesAnalyzed)</h2>
            <ul>$($AnalyzedFiles)</ul>
        </div>
        <div class='hit'>
            <h2>Hit: $($CommandsExecuted)</h2>
            $($HitTable)
        </div>
        <div class='missed'>
            <h2>Missed: $($CommandsMissed)</h2>
            $($MissedTable)
        </div>
    </div>
    </body>
    </html>
    ";

    Set-Content -Path $OutputFile -Value $html
}
Function Install-PSDepend
{
    <#
    .SYNOPSIS
        Bootstrap PSDepend

    .DESCRIPTION
        Bootstrap PSDepend

        Why? No reliance on PowerShellGallery

          * Downloads NuGet to your ~\ home directory
          * Creates $Path (and full path to it)
          * Downloads module to $Path\PSDepend
          * Moves nuget.exe to $Path\PSDepend (skips NuGet bootstrap on initial PSDepend import)

    .PARAMETER Path
        Module path to install PSDepend

        Defaults to Profile\Documents\WindowsPowerShell\Modules

    .EXAMPLE
        .\Install-PSDepend.ps1 -Path C:\Modules

        # Installs to C:\Modules\PSDepend
    #>
    [cmdletbinding()]
    param(
        [string]$Path = $( Join-Path -Path ([Environment]::GetFolderPath('MyDocuments')) -ChildPath 'WindowsPowerShell\Modules')
    )
    $ExistingProgressPreference = "$ProgressPreference"
    $ProgressPreference = 'SilentlyContinue'
    try
    {
        # Bootstrap NuGet if we don't have it
        if (-not ($NugetPath = (Get-Command -Name 'nuget.exe' -ErrorAction SilentlyContinue).Path))
        {
            $NugetPath = Install-Nuget -Path $Path
        }
        # Bootstrap PSDepend2, re-use nuget.exe for the module
        if ($path) { $null = mkdir -Path $path -Force }
        $NugetParams = 'install', 'PSDepend2', '-Source', 'https://www.powershellgallery.com/api/v2/',
        '-ExcludeVersion', '-NonInteractive', '-OutputDirectory', $Path
        & $NugetPath @NugetParams
    }
    finally
    {
        $ProgressPreference = $ExistingProgressPreference
    }
}
Function GetModuleScripts
{
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '', Justification = "Script variables", Scope = 'Function', Target = '')]
    [OutputType([HashTable])]
    param
    (
        [String]
        $ModuleName,

        [String]
        $ModulePath
    )
    $PowerShellScripts = '*.ps1'
    $PowerShellXML = '*.ps1xml'
    $PowerShellModules = '*.psm1'
    $PowerShellDataFiles = '*.psd1'
    $Data = 'Data'
    $Classes = 'Classes'
    $Enums = 'Enums'
    $Types = 'Types'
    $Formats = 'Formats'
    $Scripts = 'Scripts'
    $DSCClassResources = 'DSCClassResources'
    $DSCResources = 'DSCResources'

    $SourceScripts = @{ }

    Write-Output -InputObject ('    Gathering data [{0}]' -f $ModuleName)

    # The Public and Private folder can contain functions, aliases and variables. Each of these can be exposed with Export-ModuleMember
    foreach ($ScriptScope  in 'Public', 'Private')
    {
        $Files = Get-ChildItem -Path (Join-Path -Path $ModulePath -ChildPath $ScriptScope) -Filter $PowerShellScripts -Recurse

        $CategorizedFiles = @{
            Aliases   = @()
            Variables = $Files.Where{ $_.Basename -match '\.Variable$' }
            Functions = $Files.Where{ $_.Basename -notmatch '\.Alias$' -and $_.Basename -notmatch '\.Variable$' }
        }
        Foreach ($Item in $Files)
        {
            $CategorizedFiles.Aliases += FindAlias $Item.FullName
        }
        $SourceScripts.Add($ScriptScope, $CategorizedFiles)
    }

    Foreach ($file in Get-ChildItem -Path $ModulePath -Filter $PowerShellXML -Recurse)
    {
        [xml]$XMLData = Get-Content $file.FullName -Raw
        IF ($XMLData.SelectNodes('//Types').Count -gt 0)
        {
            Write-Verbose ('Type: {0}' -f $file.Basename)
            [array]$TypeFiles += $file
        }
        ElseIf ($XMLData.SelectNodes('//View').Count -gt 0)
        {
            Write-Verbose ('Format: {0}' -f $file.Basename)
            [array]$FormatFiles += $file
        }
        $XMLData = $null
    }
    $SourceScripts.Add($Formats, $FormatFiles)
    $SourceScripts.Add($Types, $TypeFiles)

    foreach ($fileType in $Data, $Classes, $Enums, $Scripts)
    {
        $getChildItemParams = @{
            Path        = Join-Path -Path $ModulePath -ChildPath $fileType
            ErrorAction = 'SilentlyContinue'
            Recurse     = $true
        }

        [System.IO.FileInfo[]] $files = (Get-ChildItem @getChildItemParams).Where{
            ($_.Name -notmatch '\.tests{0,1}\.ps1') -and ($_.Extension -match '\.psm?1')
        }

        $SourceScripts.Add($fileType, $files)
    }
    foreach ($fileType in $DSCClassResources, $DSCResources)
    {
        $getChildItemParams = @{
            Path        = Join-Path -Path $ModulePath -ChildPath $fileType
            ErrorAction = 'SilentlyContinue'
            Recurse     = $true
        }

        [System.IO.FileInfo[]] $files = (Get-ChildItem @getChildItemParams).Where{
            ($_.Name -notmatch '\.tests{0,1}\.ps1') -and ($_.Extension -match '\.ps(m|d)1')
        }

        $SourceScripts.Add($fileType, $files)
    }
    return $SourceScripts
}
function FindAlias
{
    param(
        $file
    )
    $ASTobject = [System.Management.Automation.Language.Parser]::ParseFile(
        $file,
        [ref]$null,
        [ref]$Null
    )
    $ASTObjectList = @()
    $AliasList = @()
    foreach ($child in $ASTobject.PSObject.Properties)
    {
        # Skip the Parent node, it's not useful here
        if ($child.Name -eq 'Parent') { continue }

        $childObject = $child.Value

        if ($null -eq $childObject) { continue }

        # Recursively add only AST nodes.
        if ($childObject -is [System.Management.Automation.Language.Ast])
        {
            $ASTObjectList += $childObject
            Continue
        }
    }
    Foreach ($ASTobject in $ASTObjectList)
    {
        IF ($ASTobject.Statements.PipelineElements.CommandElements | Where { $_.Value -eq 'Set-Alias' })
        {
            $ItemCount = 0
            Foreach ($Item in $ASTobject.Statements.PipelineElements.CommandElements)
            {
                $ItemCount++
                IF ($ASTobject.Statements.PipelineElements.CommandElements[$ItemCount].ParameterName -eq 'Name')
                {
                    $AliasList += ($ASTobject.Statements.PipelineElements.CommandElements[$ItemCount + 1]).Value
                }
            }
        }
    }
    Return $AliasList
}
Function UpdateModuleVersion
{
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('InjectionHunter\Measure-PropertyInjection', '', Justification = "Required for the function to work")]
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('InjectionHunter\Measure-UnsafeEscaping', '', Justification = "Required for the function to work")]
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '', Justification = "Script variables", Scope = 'Function', Target = '')]
    param(
        [string]$RepoName,
        [String]$ModuleName,
        [string[]]$Tags,
        [string]$BuildNumber
    )
    # Creating project artifact
    $ModuleRoot = $PWD
    $artifactPath = Join-Path -Path $ModuleRoot -ChildPath "artifacts"
    $modulePath = Join-Path -Path $ModuleRoot -ChildPath "$ModuleName"
    $DocumentationPath = Join-Path -Path $ModuleRoot -ChildPath 'Docs'
    $BuiltModuleDocumentationPath = Join-Path -Path $artifactPath -ChildPath 'Docs'

    # Update Existing Manifest
    # - Source Manifest controls Major/Minor
    # - Jenkins Controls Build Number.
    Write-Verbose -Message ("Checking if Module: {0} is registered" -f $ModuleName)
    $SourceModule = @{
        ModuleManifest = (Join-Path -Path $ModulePath -ChildPath "$ModuleName.psd1")
        ModuleFile     = (Join-Path -Path $ModulePath -ChildPath "$ModuleName.psm1")
        ReleaseNotes   = (Join-Path -Path $DocumentationPath -ChildPath "RELEASE.md")
        ChangeLog      = (Join-Path -Path $DocumentationPath -ChildPath "CHANGELOG.md")
    }
    $BuiltModule = @{
        ModuleManifest = (Join-Path -Path $artifactPath -ChildPath "$ModuleName.psd1")
        ModuleFile     = (Join-Path -Path $artifactPath -ChildPath "$ModuleName.psm1")
        ReleaseNotes   = (Join-Path -Path $BuiltModuleDocumentationPath -ChildPath "RELEASE.md")
        ChangeLog      = (Join-Path -Path $BuiltModuleDocumentationPath -ChildPath "CHANGELOG.md")
    }
    $SourceVersion = (Get-Module -FullyQualifiedName $SourceModule.ModuleManifest -ListAvailable).Version
    if ($SourceVersion -as [version])
    {
        $SourceVersion = $SourceVersion -as [version]
    }
    else
    {
        Throw 'Invalid version from sourceversion'
    }
    if (Get-PSRepository -Name $RepoName -ErrorAction SilentlyContinue)
    {
        $ExistingPublishedVersion = (Find-Module -Repository $RepoName -Name $ModuleName -ErrorAction SilentlyContinue | sort-object -Property Version | select -first 1).Version
    }
    # If not on master then add Beta tag and branch_name as a tag
    If ($env:GIT_BRANCH -ne 'master')
    {
        Write-Verbose -Message ('Branch is not master')
        Write-Verbose -Message ('Adding Pre-Release and branch_name to tags')
        $Tags += 'Pre-Release'
        $Tags += $env:GIT_BRANCH
        Write-Verbose -Message ('Increasing Revision by 1')
        IF ($ExistingPublishedVersion)
        {
            $Revision = $ExistingPublishedVersion.Revision + 1
            $SourceVersion = $ExistingPublishedVersion.Clone()
        }
        Else
        {
            $Revision = $Revision + 1
        }
    }
    if ($ExistingPublishedVersion)
    {
        #convert version from string to version type (older cmdlets returned the value as a string)
        if ($ExistingPublishedVersion -as [version])
        {
            $ExistingPublishedVersion = $ExistingPublishedVersion -as [version]
        }
        else
        {
            Throw 'Invalid version from PSRepository'
        }
        Write-Verbose -Message ("Existing published verison: {0}" -f $ExistingPublishedVersion.ToString())
        IF (($null -eq $BuildNumber) -or (0 -eq $BuildNumber))
        {
            Write-Verbose -Message ('Using Build version from Existing and incrementing the revision')
            $BuildNumber = $ExistingPublishedVersion.Build
            $Revision = $ExistingPublishedVersion.Revision + 1
        }
        $newVersion = New-Object -TypeName Version -ArgumentList $ExistingPublishedVersion.major, $ExistingPublishedVersion.minor, $BuildNumber, $Revision
        IF ($ExistingPublishedVersion -ge $newVersion)
        {
            Write-Verbose -Message ('Existing version: {0} higher than version: {1} to be published' -f $ExistingPublishedVersion.ToString(), $newVersion.ToString())
            If ($ExistingPublishedVersion -le $SourceVersion)
            {
                Write-Verbose -Message ('Existing version: {0} less than source version: {1}' -f $ExistingPublishedVersion.ToString(), $SourceVersion.ToString())
                $newversion = $SourceVersion
                Write-Verbose -Message ('New version is now: ({0})' -f $newVersion.ToString())
            }
            Else
            {
                Throw ('Existing version: {0} higher than version: {1} to be published' -f $ExistingPublishedVersion.ToString(), $newVersion.ToString())
            }
        }
    }
    else
    {
        Write-Verbose -Message ("Existing source version: {0}" -f $SourceVersion.ToString())
        $newversion = New-Object -TypeName Version -ArgumentList $SourceVersion.major, $SourceVersion.minor, $BuildNumber, $Revision
    }
    IF (Test-Path $BuiltModule.ModuleFile) # Fix for no module psm1
    {
        $RootModule = Get-Item -Path $BuiltModule.ModuleFile
        Update-ModuleManifest -Path $BuiltModule.ModuleManifest -RootModule $RootModule.Name
    }
    else
    {
        $content = get-content $builtmodule.ModuleManifest -raw
        $content.Replace('RootModule', '#RootModule') | out-File -FilePath $builtmodule.ModuleManifest -Encoding utf8 -force
    }
    Write-Verbose -message ('Normalize version to SemVer from version: ({0})' -f $newversion)
    $newversion = NormalizeVersion -Version $newversion
    Write-Verbose -message ('Normalize version to SemVer to version: ({0})' -f $newversion)
    Write-Verbose -Message ("Updating Source version to: {0}" -f $newVersion)
    Update-ModuleManifest -Path $SourceModule.ModuleManifest -ModuleVersion $newVersion
    Write-Verbose -Message ("Updating artifacts version to: {0}" -f $newVersion)
    Update-ModuleManifest -Path $BuiltModule.ModuleManifest -ModuleVersion $newVersion

    [string[]]$ModuleTags = @($ModuleName)
    $BuiltModulePrivateData = (Import-PowerShellDataFile -Path $BuiltModule.ModuleManifest).PrivateData
    [string[]]$ModuleTags += ($BuiltModulePrivateData.Tags) -split ','
    [string[]]$ModuleTags += (Get-Module -FullyQualifiedName $SourceModule.ModuleManifest -ListAvailable).Tags -split ','
    [string[]]$ModuleTags += $Tags -split ','
    [string[]]$ModuleTags = $ModuleTags | where { $_.length -gt 0 } # remove blanks
    $UpdateModuleParams = @{
        Path       = $BuiltModule.ModuleManifest
        Verbose    = $true
        Prerelease = $null
    }
    If (($ModuleTags -join ' ') -match 'Pre\-Release')
    {
        Write-Verbose -Message ('Adding Pre-Release')
        $PreReleaseTag = (('{0}{1}' -f $env:GIT_BRANCH, $env:BUILD_Number) -Replace '[^a-zA-Z0-9]', '')
        $VersionString = ('{0}.{1}.{2}' -f $NewVersion.Major, $NewVersion.minor, $NewVersion.Build)
        $UpdateModuleParams.Prerelease = $PreReleaseTag
        $UpdateModuleParams.ModuleVersion = $VersionString
    }
    IF ($null -ne $ModuleTags)
    {
        # Get unique tags and add them to the script variable
        [string]$JoinedTags = ($ModuleTags | select -unique) -join ','
        Write-Verbose -Message ('Tags contain: {0}' -f $JoinedTags)
        IF ($ModuleTags.Count -gt 0)
        {
            [string]$UpdateModuleParams.Tags = $JoinedTags
        }
    }
    Write-Verbose -Message ('Updating module manifest using parameter block')
    Update-ModuleManifest @UpdateModuleParams
    Write-Verbose -Message ('Update Release notes and Changelog')
    $null = New-Item -ItemType Directory -Path $BuiltModuleDocumentationPath -Force -ErrorAction:'Continue'
    UpdateRelease -ModuleManifest $SourceModule.ModuleManifest -ReleaseNotes $SourceModule.ReleaseNotes -ChangeLog $SourceModule.ChangeLog -BuildVersion $newVersion
    Write-Verbose -Message ('Copy Release and Changelog to Artifacts')
    Foreach ($item in ('ReleaseNotes', 'ChangeLog'))
    {
        Copy-Item -Path $SourceModule.$item -Destination $BuiltModule.$item -Force
    }
}
Function UpdateDscResourcesVersion
{
    # Getting Root Module Version
    $ModuleRoot = $PWD
    $artifactPath = Join-Path -Path $ModuleRoot -ChildPath "artifacts"
    $ModuleName = (Get-ChildItem -Path $artifactPath | Where ( { $psitem.Extension -match 'psm1' }))[0].BaseName
    $BuiltModule = @{
        ModuleManifest = (Join-Path -Path $artifactPath -ChildPath "$ModuleName.psd1")
        ModuleFile     = (Join-Path -Path $artifactPath -ChildPath "$ModuleName.psm1")
    }
    $BuiltVersion = (Get-Module -FullyQualifiedName $BuiltModule.ModuleManifest -ListAvailable).Version
    $DSCResourcesModuleDatafiles=@()
    foreach ($Type in 'DSCResources', 'DSCClassResources')
    {
        $DSCResourcesModuleDatafiles += Get-ChildItem -Path (Join-Path -Path $Artifacts -ChildPath $Type) -Recurse -File | where ( { $psitem.extension -match 'psd1' })
    }
    foreach ($file in $DSCResourcesModuleDatafiles)
    {
        Write-Verbose -Message ("Updating DSCResource {0} version to match Module Version: {0}" -f $File.BaseName, $BuiltVersion)
        Update-ModuleManifest -Path $File.FullName -ModuleVersion $BuiltVersion
    }
}
Function NewNuSpecXMLFile
{
    <#
    .SYNOPSIS
    Creates the nuspec file for building the nupkg

    .DESCRIPTION
    Creates a nuspec for use in building a nupkg file

    .PARAMETER packageId
    packageId.

    .PARAMETER packageVersion
    packageVersion.

    .PARAMETER OutputPath
    OutputPath.

    .PARAMETER author
    author

    .PARAMETER owners
    Owners

    .PARAMETER licenseUrl
    licenseUrl

    .PARAMETER projectUrl
    projectUrl

    .PARAMETER iconUrl
    iconUrl

    .PARAMETER packageDescription
    packageDescription

    .PARAMETER releaseNotes
    releaseNotes

    .PARAMETER Tags
    Tags.

    .PARAMETER requireLicenseAcceptance
    requireLicenseAcceptance

    .PARAMETER Language
    Language

    .PARAMETER Files
    Files

    .PARAMETER WhatIF
    What If

    .PARAMETER Confirm
    Confirm.

    .EXAMPLE
    NewNuSpecXMLFile -packageId 'SomePackage' -packageVersion '1.0.0.0' -OutputPath 'C:\temp' -Tags 'NoConfiguration'
    Describe what this call does

    .NOTES

    .LINK

    .INPUTS

    .OUTPUTS

#>


    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, HelpMessage = 'PackageID')][string] $packageId,
        [Parameter(Mandatory, HelpMessage = 'Package Version')] [alias('Version')][string] $packageVersion,
        [Parameter(Mandatory, HelpMessage = 'Output Path')] [alias('SourcePath')][string] $OutputPath,
        [Parameter(Mandatory, HelpMessage = 'Package Author')][string] $author,
        [Parameter(Mandatory, HelpMessage = 'Package Owner')][string] $owners,
        [AllowNull()][string] $licenseUrl,
        [AllowNull()][string] $projectUrl,
        [AllowNull()][string] $iconUrl,
        [AllowNull()][string] $packageDescription,
        [AllowNull()][string] $releaseNotes,
        [AllowNull()][String] $Tags,
        [object] $Files = @{
            src     = '.\*'
            target  = '.'
            exclude = 'dependencies\**;CustomScriptAnalyzerRules\**;TestSuite\**;lib\**;**\*.pdb;**\*.cs;**\*.nuspec;**\*.nupkg;*Results.*;Test*.*'
        },
        [bool]$requireLicenseAcceptance = $false,
        [string]$Language = 'en-GB'
    )
    process
    {

        $OutputFile = Join-Path -Path $OutputPath -ChildPath ('{0}.nuspec' -f $packageId)
        $nuspecTemplate = @'
<?xml version="1.0" encoding="utf-8"?>
<package xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <metadata xmlns="http://schemas.microsoft.com/packaging/2010/07/nuspec.xsd">
        <id></id>
        <version></version>
        <authors></authors>
        <owners></owners>
        <requireLicenseAcceptance>false</requireLicenseAcceptance>
        <description></description>
        <releaseNotes></releaseNotes>
        <copyright></copyright>
        <tags></tags>
        <language></language>
    <dependencies>
    </dependencies>
    </metadata>
    <files>
    </files>
</package>
'@
        $year = (Get-Date).Year
        [xml]$xml = $nuspecTemplate.clone()
        # Set ID
        $node = $xml.package.metadata
        $node.ID = $packageId
        $node.version = $packageversion
        $node.description = ('Autogenerated NuGet package for {0}' -f $packageId)
        $node.Tags = $Tags
        $node.authors = $author
        $node.owners = $owners
        $node.requireLicenseAcceptance = 'false'
        IF ($requireLicenseAcceptance)
        {
            $node.requireLicenseAcceptance = 'true'
        }
        $node.language = $language
        $node.releaseNotes = $releaseNotes
        $node.copyright = ('Copyright {0}' -f $year)
        $group = $xml.SelectNodes('//package/files')
        Foreach ($file in $files)
        {
            $element = $xml.CreateElement('file')
            $element.SetAttribute('src', $file.src )
            $element.SetAttribute('target', $file.target)
            $element.SetAttribute('exclude', $file.exclude)
            $null = $group.AppendChild($element)
        }
        if ($PSCmdlet.ShouldProcess($packageId, 'Creating nuspec file for PackageID'))
        {
            Write-Verbose -Message ('Writing output to: {0}' -f $OutputFile)
            $xml.Save($OutputFile)
        }
    }
}
function NormalizeVersion
{
    # Normalize version to match SemVer. Nuget publish will truncate leading zeros
    # see https://github.com/NuGet/Home/issues/3050
    param(
        [version]$version
    )
    $major = $version.major
    $minor = $version.minor
    $build = $version.build
    $revision = $version.revision

    If ($minor -eq '-1')
    {
        $minor = 0
    }
    If ($build -eq '-1')
    {
        $build = 0
    }
    if (($revision -eq '-1') -or ($revision -eq 0))
    {
        $newversion = New-Object -TypeName Version -ArgumentList $major, $minor, $Build
    }
    else
    {
        $newversion = New-Object -TypeName Version -ArgumentList $major, $minor, $Build, $Revision
    }
    return $newversion
}
function UpdateRelease
{
    param(
        [string]$ReleaseNotes,
        [string]$ChangeLog,
        [string]$ModuleManifest,
        [version]$BuildVersion
    )
    # Update release notes with Version info and set the PSD1 release notes
    $parameters = @{
        Path        = $ReleaseNotes
        ErrorAction = 'SilentlyContinue'
    }
    $ReleaseNotesData = Get-Content @parameters
    [bool]$ReleaseNotesCurrent = $ReleaseNotesData -match ('^# Version {0} \(' -f $BuildVersion.ToString()) -as [bool]
    $ReleaseText = ($ReleaseNotesData | Where-Object { $_ -notmatch '^# Version' }) -join "`r`n"
    if (-not $ReleaseText)
    {
        $ReleaseText = (@'

## Notes

## Functions

## Documentation

'@) -join "`r`n"
    }
    if ($ReleaseNotesCurrent -eq $true)
    {
        "Skipping release notes`n"
        "Already set for Current version`n"
        return
    }
    $Header = "# Version {0} ({1})`r`n" -f $BuildVersion, (Get-Date -Format 'yyyy-MM-dd')
    $ReleaseText = $Header + $ReleaseText
    $ReleaseText | Set-Content $ReleaseNotes -Encoding utf8
    Update-ModuleManifest -Path $ModuleManifest -ReleaseNotes $ReleaseText

    # Update the ChangeLog with the current release notes
    $releaseparameters = @{
        Path        = $ReleaseNotes
        ErrorAction = 'SilentlyContinue'
    }
    $changeparameters = @{
        Path        = $ChangeLog
        ErrorAction = 'SilentlyContinue'
    }
    IF (-not (Test-Path @changeparameters))
    {
        Write-Verbose -Message ('Changelog being crreated')
        $null | Set-Content @changeparameters -Encoding utf8
    }
    (Get-Content @releaseparameters), "`r`n`r`n", (Get-Content @changeparameters) | Set-Content $ChangeLog -Encoding utf8
}
Function BuildHelp
{

    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('InjectionHunter\Measure-PropertyInjection', '', Justification = "Required for the function to work")]
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('InjectionHunter\Measure-UnsafeEscaping', '', Justification = "Required for the function to work")]
    param(
        [string]$ModuleName,
        [string]$DocumentationRoot,
        [string]$repo_url,
        [string]$author
    )
    $mkdocsHeader = Join-Path -Path $DocumentationRoot -ChildPath 'header-mkdocs.yml'
    $mkdocsfile = Join-Path -Path $DocumentationRoot -ChildPath 'mkdocs.yml'
    $ReleaseNotes = Join-Path -Path $DocumentationRoot -ChildPath 'RELEASE.md'
    $ChangeLog = Join-Path -Path $DocumentationRoot -ChildPath 'ChangeLog.md'
    $FunctionDocumentationPath = Join-Path -Path $DocumentationRoot -ChildPath 'Functions'

    If (-not (Test-Path -Path $mkdocsheader))
    {
        $parameters = @{
            Path        = $mkdocsHeader
            encoding    = 'utf8'
            ErrorAction = 'SilentlyContinue'
        }
        @'
site_name: {0} Documentation
repo_url: {1}
site_author: {2}
edit_uri: edit/master/docs/
theme: readthedocs
copyright: ""
pages:
  - Home: index.md

'@ -f $modulename, $repo_url, $author | set-content @parameters
    }
    #Build YAMLText starting with the header
    $YMLtext = (Get-Content $mkdocsHeader) -join "`n"
    $YMLtext = "$YMLtext`n"
    $parameters = @{
        Path        = $ReleaseNotes
        ErrorAction = 'SilentlyContinue'
    }
    $ReleaseText = (Get-Content @parameters) -join "`n"
    if ($ReleaseText)
    {
        $ReleaseText | Set-Content $ReleaseNotes -encoding utf8
        $YMLText = "$YMLtext  - Release Notes: RELEASE.md`n"
    }
    if ((Test-Path -Path $ChangeLog))
    {
        $YMLText = "$YMLtext  - Change Log: ChangeLog.md`n"
    }
    $YMLText = "$YMLtext  - Functions:`n"
    # Drain the swamp
    $parameters = @{
        Recurse     = $true
        Force       = $true
        Path        = $FunctionDocumentationPath
        ErrorAction = 'SilentlyContinue'
    }
    $null = Remove-Item @parameters
    $Params = @{
        Path        = $FunctionDocumentationPath
        type        = 'directory'
        ErrorAction = 'SilentlyContinue'
    }
    $null = New-Item @Params
    $Params = @{
        Module       = $ModuleName
        Force        = $true
        OutputFolder = $FunctionDocumentationPath
        NoMetadata   = $true
    }
    New-MarkdownHelp @Params | foreach-object -Process {
        $Function = $_.Name -replace '\.md', ''
        $Part = "    - {0}: functions/{1}" -f $Function, $_.Name
        $YMLText = "{0}{1}`n" -f $YMLText, $Part
        $Part
    }
    $YMLtext | Set-Content -Path $mkdocsfile -encoding utf8
}
Function BuildModule
{
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '', Justification = "Script variables", Scope = 'Function', Target = '')]
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '', Justification = "Required for the function to work")]
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('InjectionHunter\Measure-PropertyInjection', '', Justification = "Required for the function to work")]
    param(
        [string]$ModuleName,
        [string]$ModulePath,
        [string]$Artifacts,
        [string]$MinimumPowershellVersion = '5.0'
    )
    Write-Output -InputObject ('    Creating module [{0}]' -f $ModuleName)
    $sourceScripts = GetModuleScripts -ModuleName $ModuleName -ModulePath $ModulePath

    $SourceManifestPath = Join-Path -Path $ModulePath -ChildPath ($ModuleName + '.psd1')
    $OutputModulePath = Join-Path -Path $Artifacts -ChildPath ($ModuleName + '.psm1')
    $OutputManifestPath = Join-Path -Path $Artifacts -ChildPath ($ModuleName + '.psd1')
    $Output = New-Item -Name $OutputModulePath -Force -ItemType File
    # Merge Enums and Classes
    foreach ($Type in 'Enums', 'Classes')
    {
        $Combine += ($SourceScripts.$Type | Sort-Object -Property BaseName).ForEach{ Get-Content -Path $_.FullName }
    }
    # Merge Functions
    $Combine += ($SourceScripts.Private.Functions + $SourceScripts.Public.Functions | Sort-Object -Property BaseName).ForEach{ Get-Content -Path $_.FullName }
    # Merge Variables
    foreach ($Type in 'Variables')
    {
        $Combine += ($SourceScripts.Private.$Type + $SourceScripts.Public.$Type | Sort-Object -Property BaseName).ForEach{ Get-Content -Path $_.FullName }
    }
    # Create the full path to the module. This will be module path inside the root folder, e.g. c:\Work\MyModule\MyModule
    $ProjectPath = $PSCmdlet.GetUnresolvedProviderPathFromPSPath($ModuleName)

    # Copy Format and type files
    Foreach ($file in $SourceScripts.Formats)
    {
        $null = Copy-Item -Path $file.FullName -destination $Artifacts -force
        [array]$FormatsToProcess += $file.Name
    }
    Foreach ($file in $SourceScripts.Types)
    {
        $null = Copy-Item -Path $file.FullName -destination $Artifacts -force
        [array]$TypesToProcess += $file.Name
    }
    # Copy DSCClassResources, DSCResources
    foreach ($Type in 'DSCClassResources', 'DSCResources')
    {
        Foreach ($file in $SourceScripts.$Type)
        {
            $DScResource = $true
            $DscResourcePath = [regex]::Match($file.FullName, ('({0}\\.+)' -f $Type)).Groups[1].Value
            $DestinationPath = Join-Path -Path $Artifacts -ChildPath  $DscResourcePath
            $null = New-Item -Path $DestinationPath -Force
            $null = Copy-Item -Path $file.FullName -destination $DestinationPath -force
            IF ($File.Extension -match 'psd1')
            {
                IF ($Type -eq 'DSCClassResources')
                {
                    [array]$NestedModules += $DscResourcePath
                    [array]$DscResourcesToExport += ($file.BaseName -replace '\..+', '') # strip an additional extensions like schema.psm1
                }
            }
        }
    }
    <#
            Functions that use classes must load them with a 'Using' statement at the top of the file.
            This removes these lines while keeping the rest. It will also keep the 'Using' statements that are external to this module.
        #>
    $Combine.Where{
        ($_ -match '^Using' -and $_ -notmatch [Regex]::Escape($ProjectPath)) -or ($_ -notmatch '^Using')
    } | Out-File -FilePath $Output.FullName -Encoding utf8

    If ((Get-Item -path $Output.FullName).Length -eq 0)
    {
        Write-Warning -Message ('Removing Empty Base psm1 file: {0}' -f $Output.FullName)
        Remove-Item -path $Output.FullName -force
    }

    Write-Output -InputObject ("    Exported functions:`n      {0}" -f ($SourceScripts.Public.Functions -join "`n      "))
    Write-Output -InputObject ("    DSCResources:`n      {0}" -f ($DscResourcesToExport -join "`n      "))

    if (($SourceScripts.Public.Functions.Count -lt 1) -and ($DScResource -eq $false))
    {
        # Added to ensure at least one public function exists
        throw 'No public functions exported'
    }
    else
    {
        Copy-Item -Path $SourceManifestPath -Destination $OutputManifestPath -force

        $UpdateModuleManifestParams = @{
            Path              = $OutputManifestPath
            PowershellVersion = $MinimumPowershellVersion
        }
        if ($SourceScripts.Public.Functions)
        {
            $UpdateModuleManifestParams.FunctionsToExport = [string[]]$SourceScripts.Public.Functions.BaseName
        }
        if ($SourceScripts.Public.Aliases)
        {
            $UpdateModuleManifestParams.AliasesToExport = [string[]]$SourceScripts.Public.Aliases
        }
        if ($SourceScripts.Public.Variables)
        {
            $UpdateModuleManifestParams.VariablesToExport = [string[]]$SourceScripts.Public.Variables.BaseName
        }

        if ($DscResourcesToExport)
        {
            $UpdateModuleManifestParams.DscResourcesToExport = [string[]]$DscResourcesToExport
        }
        if ($NestedModules)
        {
            $UpdateModuleManifestParams.NestedModules = [string[]]$NestedModules
        }
        #if ($SourceScripts.Formats)
        #{
        #    $UpdateModuleManifestParams.FormatsToProcess = [string[]]$FormatsToProcess
        #}
        #if ($SourceScripts.Types)
        #{
        #    $UpdateModuleManifestParams.TypesToProcess = [string[]]$TypesToProcess
        #}
        Update-ModuleManifest @UpdateModuleManifestParams
    }
}
Function Join-PesterJson
{
    <#

    .EXAMPLE

    Join-PesterJson -ResultsPath $Artifacts  -FileName "PesterResults.json"

#>

    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('InjectionHunter\Measure-PropertyInjection', '', Justification = "Required for the function to work")]
    param(

        [string]$ResultsPath,
        [string]$FileName = 'PesterResults.json'
    )
    $AllResults = $null
    $ResultsPath = Resolve-Path -Path $ResultsPath
    $ResultFiles = (Get-ChildItem -Path $ResultsPath | Where { $_.name -match ('.+{0}\.{1}' -f $FileName.Split('.')[0], $FileName.Split('.')[1]) })
    Foreach ($file in $ResultFiles)
    {
        $Results = (Get-Content -Path $file.Fullname -Raw | ConvertFrom-Json)
        # Convert Time to actual timespan object
        $Results.Time = [timespan]::new($Results.Time.Days, $Results.Time.hours, $Results.Time.mintues, $Results.Time.seconds, $Results.Time.milliseconds)
        IF ($null -eq $AllResults)
        {
            # Copy $results to $allResults so we can combine them
            $AllResults = $Results | ConvertTo-Json -depth 10 | ConvertFrom-Json
            # Convert Time to actual timespan object
            $AllResults.Time = [timespan]::new($AllResults.Time.Days, $AllResults.Time.hours, $AllResults.Time.mintues, $AllResults.Time.seconds, $AllResults.Time.milliseconds)
        }
        Else
        {
            #Ensure all properties exist
            Foreach ($Property in ($Results.psobject.Properties).Name)
            {
                IF ($null -eq ($AllResults.psobject.Properties | where { $_.name -eq $Property }))
                {
                    # Add missing properties
                    $AllResults | Add-Member -MemberType NoteProperty -Name $Property -Value $Results.$Property
                }
                Else
                {
                    # Combine Integer Values
                    Foreach ($IntProperty in ($Results.psobject.Properties | where { $_.TypeNameofValue -match 'System.Int' }).Name)
                    {
                        $AllResults.$IntProperty = $AllResults.$IntProperty + $Results.$IntProperty
                    }
                    # Combine System.Object[]
                    Foreach ($ObjProperty in ($Results.psobject.Properties | where { $_.TypeNameofValue -match 'System.Object' }).Name)
                    {
                        IF (($Results.$ObjProperty.count -ge 1) -and ($Results.$ObjProperty[0] -ne ''))
                        {
                            $AllResults.$ObjProperty += $Results.$ObjProperty
                        }
                    }
                }
            }
            # Combine timespans to get overall
            $AllResults.Time = [timespan]($AllResults.Time + $Results.Time)
        }
    }
    #Create JSON file containing the combined results and return object to pipeline
    $AllResults | ConvertTo-Json -Depth 10 | Out-File (Join-Path -Path $ResultsPath -ChildPath $FileName) -Encoding utf8 -force -verbose
    return $allResults
}
Function Fix-Testreport
{

    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '', Justification = "Required for the function to work")]
    param(
        $ReportFile,
        $ModuleName
    )
    $html = Get-Content -Path $reportFile -Raw
    $head = ([regex]'<head[^\>]*>([\s\S]*)<\/head>').Match($html).value
    $head = [Regex]::Replace($head, '(?<=<title>)([\s\S]*)(?=<\/title>)', ('Code Health Report - {0}' -f $ModuleName))
    $meta = ([regex]'<meta.+\>').Matches($head)
    $csp = ([regex]'http-equiv\=\"Content-Security-Policy\" content\=\"([\s\S]*)\"\/\>').Match($meta).Success
    if ($csp -eq $false)
    {
        $MetaCSP = @'
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src *; font-src *;child-src *; style-src 'self' https://cdnjs.cloudflare.com 'unsafe-inline';script-src 'self' https://cdnjs.cloudflare.com 'unsafe-inline';"/>
  {0}
'@ -f ('<title>Code Health Report - {0}</title>' -f $ModuleName)
        $head = ([regex]'<title[^\>]*>([\s\S]*)<\/title>').Replace($head, $MetaCSP)
    }
    $html = ([regex]'<head[^\>]*>([\s\S]*)<\/head>').Replace($html, $head)
    $html = [Regex]::Replace($html, '(?<=Code Health Report - <small>)([\s\S]*)(?=<\/small>)', $ModuleName)
    $html | Set-Content -Path $reportFile -Encoding utf8 -force
}
<# ANSI Colourisation #>
function Global:Write-JenkinsAnsi
{
    <#
.Synopsis
   Write output with ANSI character set
.DESCRIPTION
   Write output with ANSI character set
.EXAMPLE
   Write-JenkinsAnsi - Message "Hello World" -Mt "Verbose"
.INPUTS
   Message - Message to output to the console
   MessageType - The type of message to be output
   ForegroundColor - The color of the text to be used when using 'host' message type
   JenkinsWkPath - Jenkins path to determine/evaluate if the function is being run on a Jenkins server workspace
.FUNCTIONALITY
    The cmdlet outputs the text prepended with the ANSI character codes to colour the output
    in the Jenkins Console Output. Requires Color ANSI Console Output plugin installed in Jenkins.
    If this function is not run on a Jenkins server then output will be sent to the appropriate "write-" cmdlet
#>
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '', Justification = "Placeholder")]
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('InjectionHunter\Measure-UnsafeEscaping', '', Justification = "Required for the function to work")]
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('InjectionHunter\Measure-PropertyInjection', '', Justification = "Required for the function to work")]
    [CmdletBinding()]
    [OutputType([String])]
    param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [AllowEmptyString()]
        [String]
        $Message,

        [Parameter()]
        [ValidateSet(
            'info'
            , 'host'
            , 'output'
            , 'warning'
            , 'error'
            , 'debug'
            , 'verbose'
            , 'ok'
            , 'panic'
        )]
        [Alias('Mt')]
        [String]
        $MessageType = 'host',

        [Parameter()]
        [ValidateSet(
            'black'
            , 'red'
            , 'green'
            , 'yellow'
            , 'blue'
            , 'magenta'
            , 'cyan'
            , 'white'
        )]
        [Alias('fgc')]
        [String]
        $ForegroundColor = 'white',

        [Parameter()]
        [ValidateSet(
            'black'
            , 'red'
            , 'green'
            , 'yellow'
            , 'blue'
            , 'magenta'
            , 'cyan'
            , 'white'
        )]
        [Alias('bgc')]
        [String]
        $BackgroundColor = 'white',

        # Error params
        $ErrorID,
        $Category,
        $CategoryActivity,
        $CategoryReason,
        $CategoryTargetName,
        $CategoryTargetType,
        $TargetObject,
        $RecommendedAction,
        $Exception,

        # Info params
        $Tags
    )

    Begin
    {
        $e = [char]27
        $fore = (Get-Variable "ForegroundColor").Attributes.ValidValues | ForEach-Object { $i = 0 } { @{$_ = $i + 30 }; $i++
        }

        # Check if we're called from a Write-* alias and set the MessageType appropriately if we are
        $Aliases = @("Write-Verbose", "Write-Info", "Write-Warning", "Write-Error", "Write-Debug")
        if ($Aliases -contains $MyInvocation.InvocationName)
        {
            $MessageType = $MyInvocation.InvocationName -replace 'Write-', ''
        }
        $ansiClear = '[0m'
        $ansiboldon = '[1m'
        $ansiboldoff = '[22m'
        $ansiitalicon = '[3m'
        $ansiitalicoff = '[23m'
        $ansiunderlineon = '[4m'
        $ansiunderlineoff = '[24m'
        $ansiblinkon = '[5m'
        $ansiblinkoff = '[25m'
        $ansiinverseon = '[7m'
        $ansiinverseoff = '[27m'
        $ansistrikethroughon = '[9m'
        $ansistrikethroughoff = '[29m'

        switch ($MessageType)
        {
            'info' { $ForegroundColor = 'white' }
            'output' { $ForegroundColor = 'white' }
            'warning' { $ForegroundColor = 'yellow' }
            'error' { $ForegroundColor = 'red'; $Message = ('{0}{1}{2}{0}{3}' -f $e, $ansiblinkon, $Message, $ansiblinkoff) }
            'debug' { $ForegroundColor = 'cyan' }
            'verbose' { $ForegroundColor = 'blue' }
            'ok' { $ForegroundColor = 'green' }
            'panic' { $ForegroundColor = 'magenta'; $Message = ('{0}{1}{2}{0}{3}' -f $e, $ansiblinkon, $Message, $ansiblinkoff) }
        }
        If ($MessageType -eq 'host')
        {
            $back = (Get-Variable "BackgroundColor").Attributes.ValidValues | ForEach-Object { $i = 0 } { @{$_ = $i + 30 }; $i++
            }
            $Message = ('{0}[{1}m{2}' -f $e, $($back.$BackgroundColor), $Message)
        }
        $Message = ('{0}[{1}m{2}{0}{3}' -f $e, $Fore.$ForegroundColor, $Message, $ansiClear)
    }

    Process
    {
        switch ($MessageType)
        {
            'info' { Microsoft.PowerShell.Utility\Write-Information $Message }
            'host' { Microsoft.PowerShell.Utility\Write-Host $Message }
            'output' { Microsoft.PowerShell.Utility\Write-Output $Message }
            'warning' { Microsoft.PowerShell.Utility\Write-warning $Message }
            'error' { Microsoft.PowerShell.Utility\Write-error $Message }
            'debug' { Microsoft.PowerShell.Utility\Write-debug $Message }
            'verbose' { Microsoft.PowerShell.Utility\Write-verbose $Message }
            'ok' { Microsoft.PowerShell.Utility\Write-host $Message }
            'panic' { Microsoft.PowerShell.Utility\Write-error $Message }
        }
    }
}
Function Global:Remove-JenkinsAnsiAliasList
{
    <#
.Synopsis
   This cmdlet removes the MonkeyPatches of Write-Verbose, Warning, Error, Debug, and Info setup by Set-JenkinsAnsiAliases
.DESCRIPTION
   This cmdlet removes the MonkeyPatches of Write-Verbose, Warning, Error, Debug, and Info setup by Set-JenkinsAnsiAliases
.EXAMPLE
   Remove-JenkinsAnsiAliases
#>
    $Aliases = @("Write-Verbose", "Write-Info", "Write-Warning", "Write-Error", "Write-Debug")
    foreach ($Alias in $Aliases)
    {
        Write-Verbose "Removing $Alias"
        Remove-Item alias:\$Alias
    }
}
Function Global:Set-JenkinsAnsiAliasList
{
    <#
    .Synopsis
   This cmdlet MonkeyPatches Write-Verbose, Warning, Error, Debug, and Info to prepend them with the appropriate ANSI
   colors for use in Jenkins
    .DESCRIPTION
   This cmdlet MonkeyPatches Write-Verbose, Warning, Error, Debug, and Info to prepend them with the appropriate ANSI
   colors for use in Jenkins
    .EXAMPLE
   Set-JenkinsAnsiAliasList
#>
    $Aliases = @("Write-Verbose", "Write-Info", "Write-Warning", "Write-Error", "Write-Debug")
    foreach ($Alias in $Aliases)
    {
        Write-Verbose "Aliasing $Alias to Write-JenkinsAnsi"
        Set-Alias $Alias Write-JenkinsAnsi -Scope global
    }
}
Set-JenkinsAnsiAliasList
