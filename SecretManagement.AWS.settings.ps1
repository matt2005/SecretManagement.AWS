###############################################################################
# Customize these properties and tasks
###############################################################################
param(
    $Artifacts = '.\artifacts',
    $ModuleName = 'SecretManagement.AWS',
    $ModulePath = '.\SecretManagement.AWS',
    $BuildNumber = $env:BUILD_NUMBER,
    $PercentCompliance = '20'
)

###############################################################################
# Static settings -- no reason to include these in the param block
###############################################################################
$Settings = @{
    SMBRepoName         = 'DSCGallery'
    SMBRepoPath         = '\\localhost\Repository$'
    NuGetRepoName       = 'PSGallery'
    NuGetRepoPath       = ''
    NuGetScriptRepoPath = ''
    NuGetRepoAPIKey     = $ENV:nugetapikey

    Author              = 'Matthew Hilton'
    Owners              = 'Matthew Hilton'
    LicenseUrl          = 'https://github.com/SecretManagement.AWS/LICENSE'
    ProjectUrl          = 'https://github.com/SecretManagement.AWS'
    PackageDescription  = ('{0}' -f $ModuleName)
    Repository          = 'https://github.com/SecretManagement.AWS'
    Tags                = @('SecretManagement','AWS','SSM','SecretStore')

    # Proxy
    ProxyServer         = ''

    # TODO: fix any redundant naming
    CIUrl               = ''
}
IF (($Settings.NuGetRepoAPIKey -eq 'False') -or ($Settings.NuGetRepoAPIKey -eq ''))
{
    $Settings.NuGetRepoAPIKey = $false
}
<################################################################################
# Before/After Hooks for the Core Task: Clean
###############################################################################

# Synopsis: Executes before the Clean task.
task BeforeClean {}

# Synopsis: Executes after the Clean task.
task AfterClean {}

###############################################################################
# Before/After Hooks for the Core Task: Analyze
###############################################################################

# Synopsis: Executes before the Analyze task.
task BeforeAnalyze {}

# Synopsis: Executes after the Analyze task.
task AfterAnalyze {}

###############################################################################
# Before/After Hooks for the Core Task: Archive
###############################################################################

# Synopsis: Executes before the Archive task.
task BeforeArchive {}

# Synopsis: Executes after the Archive task.
task AfterArchive {}

###############################################################################
# Before/After Hooks for the Core Task: Publish
###############################################################################

# Synopsis: Executes before the Publish task.
task BeforePublish {}

# Synopsis: Executes after the Publish task.
task AfterPublish {}

###############################################################################
# Before/After Hooks for the Core Task: Test
###############################################################################

# Synopsis: Executes before the Test Task.
task BeforeTest {}

# Synopsis: Executes after the Test Task.
task AfterTest {}#>

