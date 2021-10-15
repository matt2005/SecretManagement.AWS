$currentModulePath = Resolve-Path -Path ($PSScriptRoot | Split-Path -Parent | Split-Path -Parent | Join-Path  -ChildPath 'artifacts')
$ModuleManifest = (Get-ChildItem -Path (Join-Path -Path $currentModulePath.Path -ChildPath '*') -include '*.psd1')

Get-Module $ModuleManifest.BaseName | Remove-Module -ErrorAction:SilentlyContinue

Import-Module $ModuleManifest.FullName
$functionName = ($MyInvocation.MyCommand.Name).Split('.')[0]
Describe -Name ('{0} Private Function Functional Tests' -f $functionName) -Fixture {
	InModuleScope -ModuleName $ModuleManifest.BaseName  -ScriptBlock {
        Context -Name 'Success' -Fixture {

        }
        Context -Name 'Failure' -Fixture {

        }
    }
}

Remove-Module $ModuleManifest.BaseName
