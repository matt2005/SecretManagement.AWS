@{
    # Some defaults for all dependencies
    PSDependOptions                      = @{
        Target    = '.\artifacts\dependencies'
        AddToPath = $True
    }

    # Grab some modules without depending on PowerShellGet
    'nugetexe'                           = @{
        DependencyType = 'FileDownload'
        Source         = 'https://dist.nuget.org/win-x86-commandline/latest/nuget.exe'
        Target         = '.\artifacts\dependencies\PSDepend\nuget.exe'
    }
    'InvokeBuild'                        = @{
        DependencyType = 'PSGalleryNuget'
        Version        = '5.4.1'
    }
    'DscResourceTestHelper'              = @{
        DependencyType = 'PSGalleryNuget'
        Version        = '0.3.0.0'
    }
    'Pester'                             = @{
        DependencyType = 'PSGalleryNuget'
        Version        = '4.3.1'
    }
    'PSScriptAnalyzer'                   = @{
        DependencyType = 'PSGalleryNuget'
        Version        = '1.18.0'
    }
    'platyps'                            = @{
        DependencyType = 'PSGalleryModule'
        Version        = '0.14.0'
    }
    'Assert'                             = @{
        DependencyType = 'PSGalleryNuget'
        Version        = '0.9.1'
    }
    'PowerShellGet'                      = @{
        DependencyType = 'PSGalleryModule'
        Parameters     = @{
            Repository = 'PSGallery'
        }
        Version        = '2.1.5' # due to https://github.com/RamblingCookieMonster/PSDepend/issues/66
    }
    'PSTestReport'                       = @{
        DependencyType = 'Git'
        Name           = 'https://github.com/Xainey/PSTestReport.git'
    }
    'ScriptAnalyzerCustomRulesSubFolder' = @{
        DependencyType = 'Command'
        Source         = '$BuildRoot="$PWD"
    $DepFolder = "$BuildRoot\artifacts\CustomScriptAnalyzerRules"
    $PSScriptAnalyzerRequirementsFile = "$BuildRoot\ScriptAnalyzer.requirements.psd1"
    IF (Test-Path $PSScriptAnalyzerRequirementsFile)
    {
        $Subfolders = (Import-PowershellDataFile -Path $PSScriptAnalyzerRequirementsFile)
        if(-not (Test-Path $DepFolder))
        {
            $null = New-Item $DepFolder -ItemType Directory -Force
        }
        foreach ($req in ($Subfolders.keys | where { $_ -ne "PSDependOptions" }))
        {
            IF ($subfolders.$req.Target)
            {
                $folder = Split-Path $subfolders.$req.Target -Parent
                if (-not (Test-path $Folder))
                {
                    New-Item -itemType Directory -Path $Folder
                }
            }
        }
        $null = Invoke-PSDepend -Path $PSScriptAnalyzerRequirementsFile -Install -Force
    }'
        DependsOn      = 'PSScriptAnalyzer'
    }
    'ModuleSpecificRequirements'         = @{
        DependencyType = 'Command'
        Source         = '$BuildRoot = "$PWD"
    $DepFolder = "$BuildRoot\artifacts\dependencies"
    $ModuleRequirementsFile = "$BuildRoot\module.requirements.psd1"
    IF (Test-Path $ModuleRequirementsFile)
    {
        $Subfolders = (Import-PowershellDataFile -Path $ModuleRequirementsFile)
        if(-not (Test-Path $DepFolder))
        {
            $null = New-Item $DepFolder -ItemType Directory -Force
        }
        foreach ($req in ($Subfolders.keys | where { $_ -ne "PSDependOptions" }))
        {
            IF ($subfolders.$req.Target)
            {
                $folder = Split-Path $subfolders.$req.Target -Parent
                if (-not (Test-path $Folder))
                {
                    New-Item -itemType Directory -Path $Folder
                }
            }
        }
        $null = Invoke-PSDepend -Path $ModuleRequirementsFile -Install -Force
    }'
    }
    'TestSuiteRequirements'              = @{
        DependencyType = 'Command'
        Source         = '$BuildRoot = "$PWD"
    $DepFolder = "$BuildRoot\artifacts\TestSuite"
    $TestSuiteRequirementsFile = "$BuildRoot\TestSuite.requirements.psd1"
    IF (Test-Path $TestSuiteRequirementsFile)
    {
        $Subfolders = (Import-PowershellDataFile -Path $TestSuiteRequirementsFile)
        if(-not (Test-Path $DepFolder))
        {
            $null = New-Item $DepFolder -ItemType Directory -Force
        }
        foreach ($req in ($Subfolders.keys | where { $_ -ne "PSDependOptions" }))
        {
            IF ($subfolders.$req.Target)
            {
                $folder = Split-Path $subfolders.$req.Target -Parent
                if (-not (Test-path $Folder))
                {
                    New-Item -itemType Directory -Path $Folder
                }
            }
        }
        $null = Invoke-PSDepend -Path $TestSuiteRequirementsFile -Install -Force
    }'
        DependsOn      = 'Pester'
    }
}






