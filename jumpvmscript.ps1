Param (
    [Parameter(Mandatory = $true)]
    [string]
    $AzureUserName,

    [string]
    $AzurePassword,
    
    [string]
    $AzureTenantID,

    [string]
    $AzureSubscriptionID,

    [string]
    $ODLID,
    
    [string]
    $DeploymentID,

    [string]
    $InstallCloudLabsShadow,

    [string]
    $vmAdminUsername,

    [string]
    $jvmadminPassword,

    [string]
    $trainerUserName,

    [string]
    $trainerUserPassword
)

$Inputstring = $AzureUserName
$CharArray =$InputString.Split("@")
$CharArray[1]
$tenantName = $CharArray[1]

Start-Transcript -Path C:\WindowsAzure\Logs\CloudLabsCustomScriptExtension.txt -Append
[Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls
[Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls" 

# tls issue fix
If (-Not (Test-Path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319'))
{
    New-Item 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319' -Force | Out-Null
}
New-ItemProperty -Path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319' -Name 'SystemDefaultTlsVersions' -Value '1' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -Value '1' -PropertyType 'DWord' -Force | Out-Null



If (-Not (Test-Path 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319'))
{
    New-Item 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319' -Force | Out-Null
}
New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319' -Name 'SystemDefaultTlsVersions' -Value '1' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -Value '1' -PropertyType 'DWord' -Force | Out-Null



If (-Not (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server'))
{
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Force | Out-Null
}
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Name 'Enabled' -Value '1' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Name 'DisabledByDefault' -Value '0' -PropertyType 'DWord' -Force | Out-Null



If (-Not (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client'))
{
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Force | Out-Null
}
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Name 'Enabled' -Value '1' -PropertyType 'DWord' -Force | Out-Null

#Import Common Functions
$path = pwd
$path=$path.Path
$commonscriptpath = "$path" + "\cloudlabs-common\cloudlabs-windows-functions.ps1"
. $commonscriptpath

#Use the commonfunction to install the required files for cloudlabsagent service 
CloudlabsManualAgent Install


# Run Imported functions from cloudlabs-windows-functions.ps1
WindowsServerCommon
InstallEdgeChromium
InstallAzPowerShellModule
InstallChocolatey

Sleep 60

choco install az.powershell

#ENABLE VM SHADOW
InstallCloudLabsShadow $ODLID $InstallCloudLabsShadow
CreateCredFile $AzureUserName $AzurePassword $AzureTenantID $AzureSubscriptionID $DeploymentID
#Enable Cloudlabs Embedded Shadow Feature
Enable-CloudLabsEmbeddedShadow $vmAdminUsername $trainerUserName $trainerUserPassword

#Install AzureAD Module

Install-PackageProvider -Name NuGet -RequiredVersion 2.8.5.201 -Force
Install-Module AzureAD -Force

New-Item -ItemType directory -Path C:\LabFiles

$WebClient = New-Object System.Net.WebClient
$WebClient.DownloadFile("https://experienceazure.blob.core.windows.net/templates/nerdio/scripts/logontask.ps1","C:\LabFiles\logontask.ps1")

$LabFilesDirectory = "C:\LabFiles"

Sleep 2

#Install AVD Client
$WebClient = New-Object System.Net.WebClient
$WebClient.DownloadFile("https://go.microsoft.com/fwlink/?linkid=2068602","C:\LabFiles\avdclient.msi")

msiexec.exe /i "C:\LabFiles\avdclient.msi" /qn ALLUSERS=2 MSIINSTALLPERUSER=1

#Connect to the user account


. C:\LabFiles\AzureCreds.ps1

$userName = $AzureUserName
$password = $AzurePassword
$securePassword = $password | ConvertTo-SecureString -AsPlainText -Force
$cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $userName, $SecurePassword

Connect-AzAccount -Credential $cred | Out-Null

Set-AzContext -SubscriptionId $AzureSubscriptionID

$domainName = $AzureUserName.Split("@")[1]
$VnetName = "aadds-vnet"
$templateSourceLocation = "https://experienceazure.blob.core.windows.net/templates/nerdio/deploy-01.json"

#Start creating Prerequisites 
#Register the provider 
Register-AzResourceProvider -ProviderNamespace Microsoft.AAD 

if(!($AADDSServicePrincipal = Get-AzADServicePrincipal -ApplicationId "2565bd9d-da50-47d4-8b85-4c97f669dc36")){ 
$AADDSServicePrincipal = New-AzADServicePrincipal -ApplicationId "2565bd9d-da50-47d4-8b85-4c97f669dc36" -ea SilentlyContinue} 

if(!($AADDSGroup = Get-AzADGroup -DisplayName "AAD DC Administrators")) 
{$AADDSGroup = New-AzADGroup -DisplayName "AAD DC Administrators" -Description "Delegated group to administer Azure AD Domain Services" -MailNickName "AADDCAdministrators" -ea SilentlyContinue}  


# Add the user to the 'AAD DC Administrators' group. 
Add-AzADGroupMember -MemberUserPrincipalName $AzureUserName -TargetGroupObjectId $($AADDSGroup).Id -ea SilentlyContinue  

#Get RG Name 
$resourceGroup = (Get-AzResourceGroup -Name "AVD-*") 
$resourceGroupName = $resourceGroup[0].ResourceGroupName 
$location = $resourceGroup[0].Location  
$Params = @{ 

     "domainName" = $domainName 

} 
 
#Deploy the AADDS template 
New-AzResourceGroupDeployment -ResourceGroupName $resourceGroupName -TemplateUri $templateSourceLocation -TemplateParameterObject $Params #Deploy the template


Sleep 300



#Update Virtual Network DNS servers 
$Vnet = Get-AzVirtualNetwork -Name $VnetName -ResourceGroupName $resourceGroupName 
$Vnet.DhcpOptions.DnsServers = @() 
$NICs = Get-AzResource -ResourceGroupName $resourceGroupName -ResourceType "Microsoft.Network/networkInterfaces" -Name "aadds*" 
ForEach($NIC in $NICs){ 
$Nicip = (Get-AzNetworkInterface -Name $($NIC.Name) -ResourceGroupName $resourceGroupName).IpConfigurations[0].PrivateIpAddress
 ($Vnet.DhcpOptions.DnsServers).Add($Nicip) 

} 

$Vnet | Set-AzVirtualNetwork    


#Nerdio Manager for MSPs deployment
DO
{
#checkADDSdeployment
$status = (Get-AzResourceGroupDeployment -ResourceGroupName $resourceGroupName -Name "deploy-01").ProvisioningState
$status

 

} Until($status -eq 'Succeeded' )

#Get RG Name 
$nerdioresourceGroup = (Get-AzResourceGroup -Name "NMM-*") 
$nerdioresourceGroupName = $nerdioresourceGroup[0].ResourceGroupName 
$location = $nerdioresourceGroup[0].Location

$nerdiotemplateSourceLocation = "https://experienceazure.blob.core.windows.net/templates/nerdio/deploy-02.json"

#depoy NMM template
if ($status -eq "Succeeded")
{
   $agreementTerms = Get-AzMarketplaceTerms -Name 'nmm-plan' -Publisher 'nerdio' -Product 'nmm'
   Set-AzMarketplaceTerms -Name 'nmm-plan' -Publisher 'nerdio' -Product 'nmm' -Terms $agreementTerms -Accept  
   New-AzResourceGroupDeployment -ResourceGroupName $nerdioresourceGroupName -TemplateUri $nerdiotemplateSourceLocation -Name "deploynerdio" #Deploy the template
}

Sleep 300


#nerdiocheckdeployment
$status = (Get-AzResourceGroupDeployment -ResourceGroupName $nerdioresourceGroupName -Name "deploynerdio").ProvisioningState
$status
if ($status -eq "Succeeded")
{
 
    $Validstatus="Pending"  ##Failed or Successful at the last step
    $Validmessage="Main Deployment is successful, logontask is pending"

 

 # Scheduled Task
$Trigger= New-ScheduledTaskTrigger -AtLogOn
$User= "$($env:ComputerName)\demouser" 
$Action= New-ScheduledTaskAction -Execute "C:\Windows\System32\WindowsPowerShell\v1.0\Powershell.exe" -Argument "-executionPolicy Unrestricted -File $LabFilesDirectory\logontask.ps1"
Register-ScheduledTask -TaskName "Setup" -Trigger $Trigger -User $User -Action $Action -RunLevel Highest -Force 

 

}
else {
    Write-Warning "Validation Failed - see log output"
    $Validstatus="Failed"  ##Failed or Successful at the last step
    $Validmessage="ARM template Deployment Failed"
      }

 
$Username = "demouser"
$RegistryPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
Set-ItemProperty $RegistryPath 'AutoAdminLogon' -Value "1" -Type String
Set-ItemProperty $RegistryPath 'DefaultUsername' -Value "$Username" -type String
Set-ItemProperty $RegistryPath 'DefaultPassword' -Value "$jvmadminPassword" -type String

#Use the cloudlabs common function to write the status to validation status txt file 
$Validstatus="Pending"  ##Failed or Successful at the last step
$Validmessage="Post Deployment is Pending"
CloudlabsManualAgent setStatus


#Reset user password  
Connect-AzureAD -Credential $cred | Out-Null
Set-AzureADUserPassword -ObjectId  (Get-AzADUser -UserPrincipalName $AzureUserName).Id -Password $securePassword

Stop-Transcript
Sleep 10
Restart-Computer -Force