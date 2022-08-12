using Namespace Microsoft.PowerShell.SecretManagement

enum SecretManagementAWSVaultType
{
    SSMParameterStore = 0
    SecretsManagement = 1
}

class SecretManagementAWS
{
    [Microsoft.PowerShell.SecretManagement.SecretVaultInfo]$Vault
    SecretManagementAWS()
    {
    }
    SecretManagementAWS([string]$VaultName)
    {
        $this.SetSecretVault($VaultName)
    }
    [Void]SetSecretVault([string]$VaultName)
    {
        $this.Vault = Get-SecretVault -Name $VaultName
    }
    [Microsoft.PowerShell.SecretManagement.SecretInformation]GetSecret([string]$Name)
    {
        return $this.GetSecret($Name, $this.Vault.Name)
    }
    [Microsoft.PowerShell.SecretManagement.SecretInformation]GetSecret([string]$Name, [string]$VaultName)
    {
        return $this.GetSecretInfo($Name, $VaultName)
    }
    [Microsoft.PowerShell.SecretManagement.SecretInformation]GetSecretInfo([string]$Name, [string]$VaultName)
    {
        $Secret = '' # placeholder
        $secretType = $This.GetSecretType($Secret)
        $metaData = @{}
        $secretInfo = [Microsoft.PowerShell.SecretManagement.SecretInformation]::new($name, $secretType, $VaultName, $metaData)
        return $secretInfo
    }
    [boolean]SetSecret([string]$Name, [System.Object]$Secret)
    {
        $Success = $false
        $Success = $this.SetSecret($Name, $this.Vault, $Secret)
        return $Success
    }
    [boolean]SetSecret([string]$Name, [string]$VaultName, [System.Object]$Secret)
    {
        $Success = $false
        Return $Success
    }
    [boolean]SetSecretInfo([string]$Name, [Hashtable]$metaData)
    {
        $Success = $false
        $Success = $this.SetSecretInfo($Name, $this.Vault, $metaData)
        Return $Success
    }
    [boolean]SetSecretInfo([string]$Name, [string]$VaultName, [Hashtable]$metaData)
    {
        $Success = $false
        Return $Success
    }
    [boolean]RemoveSecret([string]$Name)
    {
        $Success = $false
        $Success = $this.RemoveSecret($Name, $this.Vault)
        Return $Success
    }
    [boolean]RemoveSecret([string]$Name, [string]$VaultName)
    {
        $Success = $false
        Return $Success
    }
    [boolean]TestSecretVault()
    {
        $Success = $this.TestSecretVault($this.Vault)
        Return $Success
    }
    [boolean]TestSecretVault([string]$VaultName)
    {
        $Success = $false
        Return $Success
    }
    [Microsoft.PowerShell.SecretManagement.SecretType]GetSecretType([System.Object]$Secret)
    {
        $secretType = [Microsoft.PowerShell.SecretManagement.SecretType]::String
        switch ($Secret.GetType().FullName)
        {
            'System.Byte[]]'
            {
                $secretType = [Microsoft.PowerShell.SecretManagement.SecretType]::ByteArray
            }
            'System.Collections.Hashtable'
            {
                $secretType = [Microsoft.PowerShell.SecretManagement.SecretType]::Hashtable
            }
            'System.Management.Automation.PSCredential'
            {
                $secretType = [Microsoft.PowerShell.SecretManagement.SecretType]::PSCredential
            }
            'System.Security.SecureString'
            {
                $secretType = [Microsoft.PowerShell.SecretManagement.SecretType]::SecureString
            }
            'System.String'
            {
                $secretType = [Microsoft.PowerShell.SecretManagement.SecretType]::String
            }
        }
        Return $secretType
    }
    [hashtable]GetSecretVaultParameters()
    {
        $VaultParameters = $this.GetSecretVaultParameters($this.VaultName)
        return $VaultParameters
    }
    [hashtable]GetSecretVaultParameters([string]$VaultName)
    {
        $VaultParameters = $this.Vault.VaultParameters
        return $VaultParameters
    }
}

class SecretManagementAWSParameterStore : SecretManagementAWS
{
    [Microsoft.PowerShell.SecretManagement.SecretInformation]GetSecretInfo([string]$Name, [string]$VaultName)
    {
        $ParameterList = @{
            Name      = $Name
            VaultName = $VaultName
        }
        $InvokeOutput = $this.InvokeSSMCmdlet('GetSecretInfo', $ParameterList)
        $Secret = '' # placeholder
        $secretType = $This.GetSecretType($Secret)
        $metaData = @{}
        $secretInfo = [Microsoft.PowerShell.SecretManagement.SecretInformation]::new($name, $secretType, $VaultName, $metaData)
        return $secretInfo
    }
    [boolean]SetSecret([string]$Name, [string]$VaultName, [System.Object]$Secret)
    {
        $ParameterList = @{
            Name       = $Name
            VaultName  = $VaultName
            Secret     = $Secret
            SecretType = $This.GetSecretType($Secret)
        }
        $InvokeOutput = $this.InvokeSSMCmdlet('SetSecret', $ParameterList)
        $Success = $false
        Return $Success
    }
    [boolean]SetSecretInfo([string]$Name, [string]$VaultName, [Hashtable]$metaData)
    {
        $ParameterList = @{
            Name      = $Name
            VaultName = $VaultName
            MetaData  = $metaData
        }
        $InvokeOutput = $this.InvokeSSMCmdlet('SetSecretInfo', $ParameterList)
        $Success = $false
        Return $Success
    }
    [boolean]RemoveSecret([string]$Name, [string]$VaultName)
    {
        $ParameterList = @{
            Name      = $Name
            VaultName = $VaultName
        }
        $InvokeOutput = $this.InvokeSSMCmdlet('RemoveSecret', $ParameterList)
        $Success = $false
        Return $Success
    }
    [boolean]TestSecretVault()
    {
        $ParameterList = @{
            VaultName = $this.Vault.Name
        }
        $InvokeOutput = $this.InvokeSSMCmdlet('TestSecretVault', $ParameterList)
        $Success = $false
        Return $Success
    }
    [System.Object]InvokeSSMCmdlet([string]$FunctionCall, [hashtable]$ParameterList)
    {
        $Output = [System.Object]::new()
        $AdditionalParameters = $this.GetSecretVaultParameters($this.Vault)
        $VaultPath = $AdditionalParameters['VaultPath']
        $AWSParameters = $AdditionalParameters.AWSParameters
        $ParameterBasePath = ('{0}/{1}' -f $VaultPath, $ParameterList.Name)

        switch -regex ($FunctionCall)
        {
            '^SetSecret$'
            {
                Switch ($ParameterList.SecretType)
                {
                    [Microsoft.PowerShell.SecretManagement.SecretType]::PSCredential
                    {
                        $UsernameParam = @{
                            Name  = ('{0}/username' -f $ParameterBasePath)
                            Value = $ParameterList.Secret.username
                            Type  = 'String'
                        }
                        $PasswordParam = @{
                            Name  = ('{0}/password' -f $ParameterBasePath)
                            Value = $ParameterList.Secret.GetNetworkCredential().Password
                            Type  = "SecureString"
                        }
                        $UsernameOutput = Write-SSMParameter @AWSParameters @UsernameParam
                        $PasswordOutput = Write-SSMParameter @AWSParameters @PasswordParam
                        $Output = @{
                            UsernameOutput = $UsernameOutput
                            PasswordOutput = $PasswordOutput
                        }
                    }
                }
            }
            '^GetSecretInfo$'
            {
                Switch ($ParameterList.SecretType)
                {
                    [Microsoft.PowerShell.SecretManagement.SecretType]::PSCredential
                    {
                        $UsernameParam = @{
                            Name = ('{0}/username' -f $ParameterBasePath)
                        }
                        $PasswordParam = @{
                            Name           = ('{0}/password' -f $ParameterBasePath)
                            WithDecryption = $True
                        }
                        $Username = (Get-SSMParameterValue @AWSParameters @UsernameParam).Parameters[0].Value
                        $Password = (Get-SSMParameterValue @AWSParameters @PasswordParam).Parameters[0].Value  | ConvertTo-SecureString -asPlainText -Force
                        $Output = New-Object System.Management.Automation.PSCredential($Username, $Password)
                    }
                }
            }
            '^Remove'
            {

            }
        }
        return $Output
    }
}