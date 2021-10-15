param(
    [string]$TestScript = (Join-Path -Path $PSScriptRoot -ChildPath "Tests")
)

# Settings File
$SettingsFile = (Get-Item -Path ".\*.settings.ps1")
# Get Module Name
$ModuleName = $SettingsFile.Name.Split('.')[0]

# Include: Settings
. $SettingsFile.FullName

# Include: build_utils
$BuildUtilsFile =  (Get-Item -Path ".\build_utils.ps1")
. $BuildUtilsFile.FullName

# Synopsis: Run/Publish Tests and Fail Build on Error
task Test Clean, Analyze, BuildPSM1, CreateMissingTests, RunTests, PublishTestResults, ConfirmTestsPassed, ConfirmCodeCoverage

# Synopsis: Executes before the Test Task.
# task BeforeTest {} -Before Test {}

# Synopsis: Executes after the Test Task.
# task AfterTest {} -After Test {}


# Synopsis: Run full Pipleline.
task . Build, Archive, Publish

# Synopsis: Run Build
task Build Clean, Analyze, BuildPSM1, Test, BuildDocumentation
# Synopsis: Run Publish
task Publish Build, PublishNuget, clean
# Synopsis: Install Build Dependencies
# Synopsis: Executes before the InstallDependencies task.
task BeforeInstallDependencies -Before InstallDependencies {
    Write-Verbose -Message 'Running Pre-Dependencies task'
    #$credential=Get-credential
    IF ($null -eq $Script:PSDefaultParameterValues)
    {
        $Script:PSDefaultParameterValues = @{ }
    }
    IF (($Settings.ProxyServer -ne '') -and ($null -ne $Settings.ProxyServer))
    {
        $Script:PSDefaultParameterValues.'Invoke-RestMethod:Proxy' = $Settings.ProxyServer
        $Script:PSDefaultParameterValues.'Invoke-RestMethod:ProxyUseDefaultCredentials' = $true
        $Script:PSDefaultParameterValues.'Invoke-RestMethod:Verbose' = $true
        $Script:PSDefaultParameterValues.'Invoke-WebRequest:Proxy' = $Settings.ProxyServer
        $Script:PSDefaultParameterValues.'Invoke-WebRequest:ProxyUseDefaultCredentials' = $true
        $Script:PSDefaultParameterValues.'Invoke-WebRequest:Verbose' = $true
        [System.Net.WebRequest]::DefaultWebProxy = New-Object System.Net.WebProxy($Settings.ProxyServer)
        [System.Net.WebRequest]::DefaultWebProxy.BypassProxyOnLocal = $True
        [System.Net.WebRequest]::DefaultWebProxy.UseDefaultCredentials = $True
        git config --global http.proxy $Settings.ProxyServer
    }
    else
    {
        Set-ProxySettings -AutomaticDetect:$false
        $Script:PSDefaultParameterValues.Remove('Invoke-RestMethod:Proxy')
        $Script:PSDefaultParameterValues.Remove('Invoke-RestMethod:ProxyUseDefaultCredentials')
        $Script:PSDefaultParameterValues.Remove('Invoke-RestMethod:Verbose')
        $Script:PSDefaultParameterValues.Remove('Invoke-WebRequest:Proxy')
        $Script:PSDefaultParameterValues.Remove('Invoke-WebRequest:ProxyUseDefaultCredentials')
        $Script:PSDefaultParameterValues.Remove('Invoke-WebRequest:Verbose')
        git config --global --unset http.proxy
        git config --global --unset https.proxy
        git config --unset http.proxy
        git config --unset https.proxy
        [System.Net.WebRequest]::DefaultWebProxy = $null
    }
}

# Synopsis: Executes after the InstallDependencies task.
task AfterInstallDependencies -After InstallDependencies {
    $Script:PSDefaultParameterValues.Remove('Invoke-RestMethod:Proxy')
    $Script:PSDefaultParameterValues.Remove('Invoke-RestMethod:ProxyUseDefaultCredentials')
    $Script:PSDefaultParameterValues.Remove('Invoke-RestMethod:Verbose')
    $Script:PSDefaultParameterValues.Remove('Invoke-WebRequest:Proxy')
    $Script:PSDefaultParameterValues.Remove('Invoke-WebRequest:ProxyUseDefaultCredentials')
    $Script:PSDefaultParameterValues.Remove('Invoke-WebRequest:Verbose')
    git config --global --unset http.proxy
    git config --global --unset https.proxy
    git config --unset http.proxy
    git config --unset https.proxy
    [System.Net.WebRequest]::DefaultWebProxy = $null
}
task InstallDependencies {
    $null = New-Item -ItemType Directory -Path "$Artifacts\dependencies" -Force
    $DependenciesFolder = Resolve-Path -Path "$Artifacts\dependencies"
    $ENV:PSModulePath = $ENV:PSModulePath + ";$DependenciesFolder"
    # Bootstrap PSDepend for other dependencies
    if (-not (Get-Module -ListAvailable PSDepend))
    {
        Install-PSDepend -Path $DependenciesFolder
    }
    Import-Module PSDepend2
    Write-Verbose -Message ('BuildRoot is {0}' -f $BuildRoot)
    $null = Invoke-PSDepend -Path "$BuildRoot\requirements.psd1" -Install -Import -Force -Target $DependenciesFolder
}
task ImportModules {
    $DependenciesFolder = Resolve-Path -Path "$Artifacts\dependencies"
    IF (-not($ENV:PSModulePath.split(';') -contains $DependenciesFolder))
    {
        $ENV:PSModulePath = $ENV:PSModulePath + ";$DependenciesFolder"
    }
    Import-Module PSDepend2
    $null = Invoke-PSDepend -Path "$BuildRoot\requirements.psd1" -Import -Force -Target $DependenciesFolder
}

# Synopsis: Clean Artifacts Directory

task Clean {
    if (Test-Path -Path $Artifacts)
    {
        Remove-Item "$Artifacts/*" -Recurse -Force
    }
}

task Prep {
    $null = New-Item -ItemType Directory -Path $Artifacts -Force -ErrorAction:'SilentlyContinue'
}, InstallDependencies
# Synopsis: Executes before the Analyze task.
# task BeforeAnalyze -Before Analyze {}

# Synopsis: Executes after the Analyze task.
# task AfterAnalyze -After Analyze {}


# Synopsis: Lint Code with PSScriptAnalyzer
task Analyze Prep, ImportModules, {
    $scriptAnalyzerParams = @{
        Path     = $ModulePath
        Severity = @('Error', 'Warning')
        Recurse  = $true
        Verbose  = $false
        Setting  = '.vscode\PSScriptAnalyzerSettings.psd1'
    }

    $saResults = Invoke-ScriptAnalyzer @scriptAnalyzerParams

    # Save Analyze Results as JSON
    $saResults | ConvertTo-Json | Set-Content (Join-Path $Artifacts "ScriptAnalysisResults.json")

    if ($saResults)
    {
        $saResults | Format-Table
        throw "One or more PSScriptAnalyzer errors/warnings where found."
    }
}


# Synopsis: Executes before the Analyze task.
# task BeforeAnalyze -Before Analyze {}

# Synopsis: Executes after the Analyze task.
# task AfterAnalyze -After Analyze {}


# Synopsis: Test the project with Pester. Publish Test and Coverage Reports
task RunTests InstallDependencies, ImportModules, RunGenericTests, RunAllTests
task RunGenericTests {
    $invokePesterParams = @{
        OutputFile   = (Join-Path $Artifacts "GenericTestResults.xml")
        OutputFormat = 'NUnitXml'
        Strict       = $true
        PassThru     = $true
        Verbose      = $false
        EnableExit   = $false
        Script       = "$Artifacts\TestSuite"
    }

    # Publish Test Results as NUnitXml
    $testResults = Invoke-Pester @invokePesterParams;

    # Save Test Results as JSON
    try
    {
        $testresults | ConvertTo-Json -Depth 5 | Set-Content  (Join-Path $Artifacts "GenericPesterResults.json")
    }
    catch
    {
        throw 'Error converting Pester results for JSON'
    }
}, ConfirmTestsPassed
task RunAllTests {
    $invokePesterParams = @{
        OutputFile   = (Join-Path $Artifacts "TestResults.xml")
        OutputFormat = 'NUnitXml'
        Strict       = $true
        PassThru     = $true
        Verbose      = $false
        EnableExit   = $false
        CodeCoverage = "$Artifacts\$ModuleName.psm1"
        Script       = $TestScript
    }
    IF (-not(Test-path -Path $invokePesterParams.CodeCoverage))
    {
        $invokePesterParams.Remove('CodeCoverage')
    }
    # Publish Test Results as NUnitXml
    $testResults = Invoke-Pester @invokePesterParams;

    # Save Test Results as JSON
    try
    {
        $testresults | ConvertTo-Json -Depth 5 | Set-Content  (Join-Path $Artifacts "ModulePesterResults.json")
    }
    catch
    {
        throw 'Error converting Pester results for JSON'
    }
}

# Synopsis: Publish Test results to git
task PublishTestResults ImportModules, {
    # Old: Publish Code Coverage as HTML
    # $moduleInfo = @{
    #     TestResults = $testResults
    #     BuildNumber = $BuildNumber
    #     Repository = $Settings.Repository
    #     PercentCompliance  = $PercentCompliance
    #     OutputFile =  (Join-Path $Artifacts "Coverage.htm")
    # }
    #
    # Publish-CoverageHTML @moduleInfo


    # Join Pester Results
    Write-Verbose -Message 'Running Join-PesterJSON'
    $allResults = Join-PesterJson -ResultsPath (Resolve-Path $Artifacts) -FileName 'PesterResults.json'

    $TestReportPath = Join-Path -Path (Resolve-Path $Artifacts) -ChildPath 'TestReport'
    $null = New-Item -Path $TestReportPath -ItemType Directory -Force 4>$null
    # Temp: Publish Test Report
    $options = @{
        BuildNumber        = $BuildNumber
        GitRepo            = $ModuleName
        GitRepoURL         = $Settings.ProjectUrl
        CiURL              = $Settings.CiURL
        ShowHitCommands    = $true
        Compliance         = ($PercentCompliance / 100)
        ScriptAnalyzerFile = (Join-Path $Artifacts "ScriptAnalyzerResults.json")
        PesterFile         = (Join-Path $Artifacts "PesterResults.json")
        OutputDir          = $TestReportPath
    }
    $DependenciesFolder = Resolve-Path -Path "$Artifacts\dependencies"
    . "$DependenciesFolder\PSTestReport\Invoke-PSTestReport.ps1" @options
    $TempModulePath = New-Item -ItemType Directory -Path $Artifacts\$ModuleName
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
    $null = Remove-Item -Path $TempModulePath -Force -Recurse
    IF ($allResults)
    {
        <# Removed as it was causing long delay
    Invoke-PSCodeHealth -Path (Resolve-Path $TempModulePath) -TestsResult $allResults -HtmlReportPath (Join-Path -Path $TestReportPath -ChildPath "PSCodeHealthReport.html")
    #TODO: fix up CSP in PSCodeHealthReport
    Fix-Testreport -ReportFile (Join-Path -Path $TestReportPath -ChildPath "PSCodeHealthReport.html") -ModuleName $ModuleName
    #>
    }
}

# Synopsis: Throws and error if any tests do not pass for CI usage
task ConfirmTestsPassed {
    # Fail Build after reports are created, this allows CI to publish test results before failing
    $TestResults = 'GenericTestResults.xml', 'TestResults.xml'
    $NumberFails = 0
    Foreach ($testresult in $Testresults)
    {
        $ResultFile = (Join-Path $Artifacts $TestResult)
        IF (Test-Path $ResultFile)
        {
            [xml] $xml = Get-Content (Join-Path $Artifacts $TestResult)
            $numberFails = $numberFails + $xml."test-results".failures
        }
    }
    assert($numberFails -eq 0) ('Failed "{0}" unit tests.' -f $numberFails)
}

# Synopsis: Set build to Beta if code coverage doesn't meet the PercentCompliance
task ConfirmCodeCoverage {
    # Fail Build if Coverage is under requirement
    $json = Get-Content (Join-Path $Artifacts "PesterResults.json") | ConvertFrom-Json
    IF (($null -ne $json.CodeCoverage.NumberOfCommandsExecuted) -or ($null -ne $json.CodeCoverage.NumberOfCommandsAnalyzed))
    {
    $overallCoverage = [Math]::Floor(($json.CodeCoverage.NumberOfCommandsExecuted / $json.CodeCoverage.NumberOfCommandsAnalyzed) * 100)
    }
    else {
        $OverallCoverage = 0
    }
    #Set build to Beta if code coverage doesn't meet the PercentCompliance
    IF ($OverallCoverage -lt $PercentCompliance)
    {
        Write-Verbose -Message 'Code coverage does not meet requirements, Tagging as Pre-Release version'
        IF ($script:Settings.Tags -contains 'Release Candidate')
        {
            $script:Settings.Tags = $script:Settings.Tags | where { $_ -notin @('Release Candidate') }
        }
        $script:Settings.Tags += @('Pre-Release', 'MissedCodeCoverage')
    }
    Else
    {
        Write-Verbose -Message 'Code coverage meets requirements, Tagging as Release candidate version'
        IF ($script:Settings.Tags -contains 'Release Candidate')
        {
            $script:Settings.Tags = $script:Settings.Tags | where { $_ -notin @('Beta', 'MissedCodeCoverage') }
        }
        $script:Settings.Tags += @('Release Candidate')
    }
    #assert($OverallCoverage -gt $PercentCompliance) ('A Code Coverage of "{0}" does not meet the build requirement of "{1}"' -f $overallCoverage, $PercentCompliance)
}, UpdateModuleVersion

# Synopsis: Get the Public and Private script files
task GetScriptFiles {
    $Global:SourceScripts = GetModuleScripts -ModuleName $ModuleName -ModulePath $ModulePath
    Write-Output -InputObject ('      Public functions:      {0}' -f $SourceScripts.Public.Functions.Count)
    Write-Output -InputObject ('      Private functions:     {0}' -f $SourceScripts.Private.Functions.Count)
    Write-Output -InputObject ('      Public aliases:        {0}' -f $SourceScripts.Public.Aliases.Count)
    Write-Output -InputObject ('      Public variables:      {0}' -f $SourceScripts.Public.Variables.Count)
    Write-Output -InputObject ('      Private variables:     {0}' -f $SourceScripts.Private.Variables.Count)
    Write-Output -InputObject ('      Classes:               {0}' -f $SourceScripts.Classes.Count)
    Write-Output -InputObject ('      Enums:                 {0}' -f $SourceScripts.Enums.Count)
    Write-Output -InputObject ('      Types:                 {0}' -f $SourceScripts.Types.Count)
    Write-Output -InputObject ('      Formats:               {0}' -f $SourceScripts.Formats.Count)
    Write-Output -InputObject ('      DSCResources:          {0}' -f $(IF ($SourceScripts.DSCResources.Count -ge 2) { $SourceScripts.DSCResources.Count / 2 }; 0))
    Write-Output -InputObject ('      DSCClassResources:     {0}' -f $(IF ($SourceScripts.DSCClassResources.Count -ge 2) { $SourceScripts.DSCClassResources.Count / 2 }; 0))
}

task UpdateModuleVersion ImportModules, {
    $UpdateModuleParams = @{
        RepoName    = $Settings.SMBRepoName
        ModuleName  = $ModuleName
        Tags        = $Settings.Tags
        BuildNumber = $BuildNumber
        Verbose     = $true
    }
    IF ($Settings.NuGetRepoAPIKey)
    {
        $UpdateModuleParams.RepoName = $Settings.NuGetRepoName
    }
    $CurrentVerbosePref = $VerbosePreference
    $VerbosePreference = 'Continue'
    UpdateModuleVersion @UpdateModuleParams
    UpdateDscResourcesVersion
    $VerbosePreference = $CurrentVerbosePref
}, Sign

# Synopsis: Combines the ps1 files into a single psm1
task BuildPSM1 GetScriptFiles, ImportModules, {
    $BuildModuleParams = @{
        ModuleName = $ModuleName
        ModulePath = $ModulePath
        Artifacts  = $Artifacts
    }
    BuildModule @BuildModuleParams
}, UpdateModuleVersion

task CreateMissingTests GetScriptFiles, {
    $TemplateTest = @'
$currentModulePath = Resolve-Path -Path ($PSScriptRoot | Split-Path -Parent | Split-Path -Parent | Join-Path  -ChildPath 'artifacts')
$ModuleManifest = (Get-ChildItem -Path (Join-Path -Path $currentModulePath.Path -ChildPath '*') -include '*.psd1')

Get-Module $ModuleManifest.BaseName | Remove-Module -ErrorAction:SilentlyContinue

Import-Module $ModuleManifest.FullName
$functionName = ($MyInvocation.MyCommand.Name).Split('.')[0]
Describe -Name ('{{0}}{1} Functional Tests' -f $functionName) -Fixture {{
	InModuleScope -ModuleName $ModuleManifest.BaseName  -ScriptBlock {{
        Context -Name 'Success' -Fixture {{

        }}
        Context -Name 'Failure' -Fixture {{

        }}
    }}
}}

Remove-Module $ModuleManifest.BaseName
'@
    Write-Output -InputObject ('      Public functions:  {0}' -f $SourceScripts.Public.Functions.Count)
    Write-Output -InputObject ('      Private functions: {0}' -f $SourceScripts.Private.Functions.Count)
    Foreach ($item in $SourceScripts.Private.Functions.BaseName)
    {
        Write-Verbose -Message ('Checking for Tests for: {0}' -f $item)
        $TestPath = (Join-Path -Path (Split-Path $ModulePath -Parent) -ChildPath Tests)
        $null = New-Item -Name 'Unit' -Path $TestPath -ItemType Directory -ErrorAction:'SilentlyContinue'
        IF (-not (Get-ChildItem -Path $TestPath -Filter ('{0}*.Tests.ps1' -f $Item) -recurse))
        {
            $templateTest -f $item, ' Private Function' | Out-File -FilePath $(Join-Path -Path (Join-Path -Path $TestPath -ChildPath Unit) -ChildPath ('{0}.Functional.Tests.ps1' -f $Item)) -Encoding utf8
        }
    }
    Foreach ($item in $SourceScripts.Public.Functions.BaseName)
    {
        Write-Verbose -Message ('Checking for Tests for: {0}' -f $item)
        $TestPath = (Join-Path -Path (Split-Path $ModulePath -Parent) -ChildPath Tests)
        $null = New-Item -Name 'Unit' -Path $TestPath -ItemType Directory -ErrorAction:'SilentlyContinue'
        IF (-not (Get-ChildItem -Path $TestPath -Filter ('{0}*.Tests.ps1' -f $Item) -recurse))
        {
            $templateTest -f $item, $null | Out-File -FilePath $(Join-Path -Path (Join-Path -Path $TestPath -ChildPath Unit) -ChildPath ('{0}.Functional.Tests.ps1' -f $Item)) -Encoding utf8
        }
    }
}

task Sign {
    $cert = GetSigningCert
    If ($Cert)
    {
        SignModule -Artifacts $Artifacts
    }
}

# Synopsis: Executes before the BuildDocumentation task.
task BeforeBuildDocumentation -Before BuildDocumentation {
    If (-not $Artifacts)
    {
        $Artifacts = Join-Path -Path $PSScriptRoot -ChildPath 'artifacts'
    }
    $ModuleFile = Join-Path -Path $Artifacts -ChildPath ('{0}.psd1' -f $ModuleName)
    Write-Verbose -Message 'Importing module'
    Remove-module -Name $moduleName -force -ErrorAction:'silentlycontinue'
    Import-Module $ModuleFile -force
}
task BuildDocumentation Test, ImportModules, {
    $DocumentationRoot = Join-Path -Path $PSScriptRoot -ChildPath 'Docs'
    BuildHelp -ModuleName $modulename -DocumentationRoot $DocumentationRoot -Author $Settings.Author -repo_url $Settings.Repository
    Copy-Item -Path $DocumentationRoot -Destination $artifacts -force -Recurse
}
# Synopsis: Creates Archived Zip and Nuget Artifacts
task Archive ConfirmCodeCoverage, UpdateModuleVersion, {
    $moduleInfo = @{
        ModuleName  = $ModuleName
        BuildNumber = $BuildNumber
    }
    Publish-ArtifactZip @moduleInfo -Verbose
    <#
    $nuspecInfo = @{
        packageName        = $ModuleName
        author             = $Settings.Author
        owners             = $Settings.Owners
        licenseUrl         = $Settings.LicenseUrl
        projectUrl         = $Settings.ProjectUrl
        packageDescription = $Settings.PackageDescription
        tags               = $Settings.Tags
        destinationPath    = $Artifacts
        BuildNumber        = $BuildNumber
    }
    Build-NugetPackage @nuspecInfo -Verbose
#>
}


# Synopsis: Executes before the Archive task.
# task BeforeArchive -Before Archive {}

# Synopsis: Executes after the Archive task.
# task AfterArchive -After Archive {}


# Synopsis: Publish to nuget
task PublishNuget ConfirmCodeCoverage, {
    $moduleInfo = @{
        RepoName    = $Settings.SMBRepoName
        RepoPath    = $Settings.SMBRepoPath
        ModuleName  = $ModuleName
        ModulePath  = "$PSScriptRoot\$Artifacts"
        BuildNumber = $BuildNumber
        Tags        = $Settings.Tags
    }
    IF ($Settings.NuGetRepoAPIKey)
    {
        $moduleInfo.RepoName = $Settings.NuGetRepoName
        $moduleInfo.RepoPath = $Settings.NuGetRepoPath
        $ModuleInfo.ScriptPath = $Settings.NuGetScriptRepoPath
        $moduleInfo.NuGetRepoAPIKey = $settings.NuGetRepoAPIKey
    }
    Publish-nugetModule @moduleInfo -Verbose
}


# Synopsis: Executes before the Publish task.
# task BeforePublish -Before Publish {}

# Synopsis: Executes after the Publish task.
# task AfterPublish -After Publish {}







