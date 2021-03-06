<#

The sample scripts are not supported under any Microsoft standard support 
program or service. The sample scripts are provided AS IS without warranty  
of any kind. Microsoft further disclaims all implied warranties including,  
without limitation, any implied warranties of merchantability or of fitness for 
a particular purpose. The entire risk arising out of the use or performance of  
the sample scripts and documentation remains with you. In no event shall 
Microsoft, its authors, or anyone else involved in the creation, production, or 
delivery of the scripts be liable for any damages whatsoever (including, 
without limitation, damages for loss of business profits, business interruption, 
loss of business information, or other pecuniary loss) arising out of the use 
of or inability to use the sample scripts or documentation, even if Microsoft 
has been advised of the possibility of such damages.

#>

##Reference command to create self-signed non-exportable cert for auth. Public key needs to be added to app registration
#New-SelfSignedCertificate -Subject "CN=OptOutAppCert" -CertStoreLocation "Cert:\LocalMachine\My"  -KeyExportPolicy NonExportable -KeySpec Signature
####ADAL and Token Related variables

#Read previously saved clientID from secure string in TXT file. This prevents the clientID from explicitly called in the script - Can use KeepPass/Credman as well

$clientidsecstring = Get-Content C:\Scripts\ClientID.txt
$secureclientid = $clientidsecstring | ConvertTo-SecureString
$BSTR = `
    [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureclientid)
$clientid = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

#Client Credential Flow with client certificate created in Azure AD Portal
$adalpath = "C:\Nuget\Microsoft.IdentityModel.Clients.ActiveDirectory.3.13.8\lib\net45\Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
Add-Type -Path $adalpath
#Tenant ID can be retrieved from the Azure AD Portal or with Azure AD PS
$tenantid = "54e3b73f-9b86-4bb5-808e-167a29866205"
#Get Cert from machine store
$cert = Get-ChildItem Cert:\LocalMachine\My | ? {$_.Subject -match "OptOutAppCert"}
#Resource in this example is hitting the unified Graph API. This should work against Outlook API as well
$resource = "https://graph.microsoft.com"
#Authority needs to be specific to tenant for client credential flow
$authority = "https://login.microsoftonline.com/" + $tenantid + "/oauth2/authorize"

####EXO Related Variables 

$optoutemail = "opt-out@M365x851637.onmicrosoft.com"

####Exchange On-Premises Setup
$psuri = "http://exchange.contoso.com/powershell"
$reportfrom = "Optoutreport@contoso.com"
$reportto = "user@contoso.com"
$smtpserver = "tma-ex13-01"

#Retrieve OAuth Token for Graph API

#Steps to azuire Async token from Azure AD with app-only scope
$authcontext = New-Object Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext -ArgumentList $authority, $false
#Build a client assertion using the client ID and client certificate
$clientassertcert = New-Object Microsoft.IdentityModel.Clients.ActiveDirectory.ClientAssertionCertificate($clientid, $Cert)
$authresult = $authcontext.AcquireTokenAsync($resource, $clientassertcert)

####The Magic

#Get All Folder IDs and determine target folder IDs
$folderurl = "https://graph.microsoft.com/v1.0/users/$($optoutemail)/mailFolders"
$allfolders = Invoke-RestMethod -Uri $folderurl -Method GET -Headers @{Authorization = $authresult.result.CreateAuthorizationHeader()}
$inboxfolder = $allfolders.value | Where-Object {$_.displayName -eq "Inbox"}
$processedfolder = $allfolders.value | Where-Object {$_.displayName -eq "Processed"}
$failedfolder = $allfolders.value | Where-Object {$_.displayName -eq "Failed"}

#Get all messages in the Inbox

$messageurl = "https://graph.microsoft.com/v1.0/users/$($optoutemail)/mailFolders/$($inboxfolder.id)/messages"
$messages = Invoke-RestMethod -Uri $messageurl -Method GET -Headers @{Authorization = $authresult.result.CreateAuthorizationHeader()}

#If there are messages to process, connect to on-premises Exchange Remote PowerShell and create list variable for report
if ($messages.value.count -gt 0) {
    $exsession = New-PSSession -ConnectionUri $psuri -Authentication Kerberos -ConfigurationName Microsoft.Exchange
    Import-PSSession $exsession
    $optoutreport = New-Object System.Collections.ArrayList
}

#Loop through and process each message
foreach ($m in $messages.value) {
    $failed = $false
    $optoutobj = New-Object PSObject
    $fromsmtp = $m.from.emailAddress.address
    $subject = $m.subject
    $group = ($subject -split "- ")[1]
    #Attempt to validate DL
    try {
        $dl = Get-DistributionGroup $group -ErrorAction Stop
    }
    catch {
        $failed = $true
        $failedmessage = "Unable to locate Distribution Group"
    }
    #Attempt to remove member from DL
    if ($group.count -eq 1 -and $failed -eq $false) {
        try {
            Remove-DistributionGroupMember -Identity $dl.Identity -Member $fromsmtp -Confirm:$false -ErrorAction Stop
        }
        catch {
            $failed = $true
            $failedmessage = "Unable to Remove Member"
        }
    }
    #If opt-out failed, move email to Failed folder. Otherwise, move it to processed
    if ($failed -eq $true) {
        $messagemovebody = @{"destinationId" = $failedfolder.id}
        $messagemovebody = $messagemovebody | ConvertTo-Json
        $messagemoveurl = "https://graph.microsoft.com/v1.0/users/$($optoutemail)/messages/$($m.id)/move"
        Invoke-RestMethod -Method Post -Uri $messagemoveurl -Body $messagemovebody -Headers @{Authorization = $authresult.result.CreateAuthorizationHeader()} -ContentType application/json
    }
    else {
        $messagemovebody = @{"destinationId" = $processedfolder.id}
        $messagemovebody = $messagemovebody | ConvertTo-Json
        $messagemoveurl = "https://graph.microsoft.com/v1.0/users/$($optoutemail)/messages/$($m.id)/move"
        Invoke-RestMethod -Method Post -Uri $messagemoveurl -Body $messagemovebody -Headers @{Authorization = $authresult.result.CreateAuthorizationHeader()} -ContentType application/json

    }
    $optoutobj | Add-Member -MemberType NoteProperty -Name "User" -Value $fromsmtp
    $optoutobj | Add-Member -MemberType NoteProperty -Name "Group" -Value $group
    if ($failed -eq $true) {
        $optoutobj | Add-Member -MemberType NoteProperty -Name "Status" -Value "Failed"
        $optoutobj | Add-Member -MemberType NoteProperty -Name "ErrorMessage" -Value $failedmessage
    }
    else {
        $optoutobj | Add-Member -MemberType NoteProperty -Name "Status" -Value "Succeeded"
        $optoutobj | Add-Member -MemberType NoteProperty -Name "ErrorMessage" -Value "N/A"
    }
    [void]$optoutreport.Add($optoutobj)
}

#Export report to CSV
$optoutreport | Export-Csv OptOutReport.csv -NoTypeInformation
#Send email report
Send-MailMessage -From $reportfrom -To $reportto -Attachments OptOutReport.csv -SmtpServer $smtpserver -Subject "DL Opt Out Report"
Remove-Item OptOutReport.csv
