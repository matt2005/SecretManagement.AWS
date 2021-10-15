@{
    # Some defaults for all dependencies
    PSDependOptions            = @{
        Target = '.\artifacts\CustomScriptAnalyzerRules'
    }
    <# PSScriptAnalyzer Community Rules
    'PSScriptAnalyzerCommunityRules_psd1'     = @{
        DependencyType = 'FileDownload'
        Source         = 'https://raw.githubusercontent.com/PowerShell/PSScriptAnalyzer/development/Tests/Engine/CommunityAnalyzerRules/CommunityAnalyzerRules.psd1'
        Target         = '.\artifacts\CustomScriptAnalyzerRules\CommunityAnalyzerRules\CommunityAnalyzerRules.psd1'
    }
    'PSScriptAnalyzerCommunityRules_psm1'       = @{
        DependencyType = 'FileDownload'
        Source         = 'https://raw.githubusercontent.com/PowerShell/PSScriptAnalyzer/development/Tests/Engine/CommunityAnalyzerRules/CommunityAnalyzerRules.psm1'
        Target         = '.\artifacts\CustomScriptAnalyzerRules\CommunityAnalyzerRules\CommunityAnalyzerRules.psm1'
    }
    'PSScriptAnalyzerCommunityRules_en-us_psd1' = @{
        DependencyType = 'FileDownload'
        Source         = 'https://raw.githubusercontent.com/PowerShell/PSScriptAnalyzer/development/Tests/Engine/CommunityAnalyzerRules/en-US/CommunityAnalyzerRules.psd1'
        Target         = '.\artifacts\CustomScriptAnalyzerRules\CommunityAnalyzerRules\en-US\CommunityAnalyzerRules.psd1'
    }
    #>
    'MBAnalyzerRules'          = @{
        DependencyType = 'FileDownload'
        Source         = 'https://raw.githubusercontent.com/MathieuBuisson/PowerShell-DevOps/master/CustomPSScriptAnalyzerRules/MBAnalyzerRules.psm1'
        Target         = '.\artifacts\CustomScriptAnalyzerRules\MBAnalyzerRules\MBAnalyzerRules.psm1'
    }
    'matt2005/InjectionHunter' = @{
        Version        = '1.0.1'
        DependencyType = 'GitHub'
        Parameters     = @{
            TargetType = 'Parallel'
        }
    }
    <#'InjectionHunter' = @{
        DependencyType = 'PSGalleryModule'
        Parameters     = @{
            Repository = 'PSGallery'
        }
    }
    #>
}


