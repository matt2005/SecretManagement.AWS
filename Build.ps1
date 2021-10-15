#requires -Version 7
#requires -Module InvokeBuild
param(
    [string]$Task,
	[string]$TestScript
)
$InformationPreference = 'Continue'
$InvokeBuildParams = @{
    Task = $Task
    File = (Get-Item -Path ".\*.build.ps1").FullName
}
If (($null -ne $TestScript) -or ('' -ne $TestScript))
{
    $InvokeBuildParams.TestScript = $TestScript
}

IF ($env:BUILD_URL)
{
    # Ensure the build fails if there is a problem.
    # The build will fail if there are any errors on the remote machine too!
    $ErrorActionPreference = 'Stop'

    # Create a PSCredential Object using the "User" and "Password" parameters that you passed to the job
    $SecurePassword = $env:SERVICE_CREDS_PSW | ConvertTo-SecureString -AsPlainText -Force
    $Credential = New-Object System.Management.Automation.PSCredential -ArgumentList $env:SERVICE_CREDS_USR, $SecurePassword

    # Invoke a command on the remote machine.
    # It depends on the type of job you are executing on the remote machine as to if you want to use "-ErrorAction Stop" on your Invoke-Command.
    $ScriptBlock = {
        $InvokeBuildParams = $args[0]
        $SecurePassword = $args[2] | ConvertTo-SecureString -AsPlainText -Force
        $InvokeBuildParams.Credential = New-Object System.Management.Automation.PSCredential -ArgumentList $args[1], $SecurePassword
        try
        {
            Invoke-Build @InvokeBuildParams
        }
        catch
        {
            throw $_
            exit 1
        }
        exit 0
    }
    Invoke-Command -ComputerName $env:ComputerName -Credential $Credential -Authentication Credssp -ScriptBlock $ScriptBlock -ArgumentList $InvokeBuildParams, $env:SERVICE_CREDS_USR, $env:SERVICE_CREDS_PSW
}
else
{
    Invoke-Build @InvokeBuildParams
}