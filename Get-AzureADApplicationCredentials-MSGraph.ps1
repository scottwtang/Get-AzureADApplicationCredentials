<#
    .SYNOPSIS
        This script gets information on expiring certificates and client secrets for all Azure AD applications.

    .DESCRIPTION
        This scripts uses the Microsoft.Graph module to get information for all Azure AD app registrations and Enterprise Applications with expiring certificates and client secrets, to assist with application management.
        Results are exported as a CSV file to the location determined in the script parameters.

    .PARAMETER SearchPeriod
        The number of upcoming days to search within for expiring credentials.

    .PARAMETER Expired
        Whether or not to include expired credentials in the results.

    .PARAMETER FolderPath
        Folder path to export the results to.

    .PARAMETER FileName
        File name to to export the results as.

    .EXAMPLE
        # Run script and save results to the default folder with the default filename
        .\Get-AzureADApplicationCredentials-MSGraph.ps1

        # Run script and return only credentials expiring within the next 10 days.
        .\Get-AzureADApplicationCredentials-MSGraph.ps1 -SearchPeriod 10

        # Run script and return credentials expiring within the next 10 days, and all credentials already expired.
        .\Get-AzureADApplicationCredentials-MSGraph.ps1 -SearchPeriod 10 -Expired

        # Run script and return only credentials already expired within the last 10 days.
        .\Get-AzureADApplicationCredentials-MSGraph.ps1 -SearchPeriod -10

        # Run script and return all credentials already expired.
        .\Get-AzureADApplicationCredentials-MSGraph.ps1 -Expired
        
        # Run script and save results to the folder C:\AzureADAppsCredentials with the default filename
        .\Get-AzureADApplicationCredentials-MSGraph.ps1 -FolderPath C:\AzureADAppsCredentials
        
        # Run script and save results to the default folder with the filename ScriptResults.csv
        .\Get-AzureADApplicationCredentials-MSGraph.ps1 -FileName ScriptResults.csv
        
        # Run script and save results to the folder C:\AzureADAppsCredentials with the filename ScriptResults.csv
        .\Get-AzureADApplicationCredentials-MSGraph.ps1 -FolderPath C:\AzureADAppsCredentials -FileName ScriptResults.csv
#>
    
[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [double]$SearchPeriod = [double]::PositiveInfinity,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [switch]$Expired = $false,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$FolderPath = "$env:USERPROFILE\Downloads",

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$FileName = "$(Get-Date -f 'yyyy-MM-dd')-AzureADAppsCredentials.csv"
)    

function Export-Credential {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        $App,        

        [Parameter(Mandatory = $true)]
        [string]$ObjectType,        

        [Parameter(Mandatory = $false)]
        $OwnerNames,
        
        [Parameter(Mandatory = $false)]
        $OwnerIds,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        $Credential,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("Certificate", "ClientSecret")]
        [string]$CredentialType
    )

    $now = Get-Date
    $daysToExpire = ($Credential.EndDateTime - $now).Days

    $cred = [PSCustomObject] @{
        "ApplicationName"        = $App.DisplayName
        "ApplicationId"          = $App.AppId
        "ApplicationObjectId"    = $App.Id
        "ObjectType"             = $ObjectType
        "Owners"                 = $OwnerNames
        "OwnerIds"               = $OwnerIds
        "CredentialType"         = $CredentialType
        "CredentialDescription"  = $Credential.DisplayName
        "CredentialId"           = $Credential.KeyId
        "Expired"                = ($Credential.EndDateTime -lt $now)
        "StartDate"              = $Credential.StartDateTime
        "EndDate"                = $Credential.EndDateTime
        "DaysToExpire"           = $daysToExpire
        "CertificateUsage"       = $Credential.Usage
    }

    if ($Expired) {
        if ($SearchPeriod -lt 0) {
            if ( ($SearchPeriod -le $daysToExpire) -and ($daysToExpire -lt 0) ) {
                return $cred
            }
        }

        else {
            if ($SearchPeriod -ge $daysToExpire) {
                return $cred
            }
        }
    }

    else {
        if ( ($Credential.EndDateTime -gt $now) -and ($SearchPeriod -ge $daysToExpire) ) {
            return $cred
        }
    }
}

function Get-Owners {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$AppObjectId,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ObjectType
    )

    # Determine the object type which each use different cmdlets for retrieving the owner
    switch ($ObjectType) {
        Application {
            $owners = Get-MgApplicationOwner -ApplicationId $AppObjectId
        }

        ServicePrincipal {
            $owners = Get-MgServicePrincipalOwner -ServicePrincipalId $AppObjectId
        }
    }

    # Join all owner IDs as one string
    $ownerIds = $owners.Id -Join ";"

    # Set ownerNames to null for applications with no assigned owner
    $ownerNames = $null

    # Determine if each owner is a user or application and join into one string
    $ownerNames = @(
        foreach ($owner in $owners) {
            switch ($owner.AdditionalProperties."@odata.type") {
                "#microsoft.graph.user" {
                    $owner.AdditionalProperties.userPrincipalName
                }

                "#microsoft.graph.servicePrincipal" {
                    $owner.AdditionalProperties.appDisplayName
                }
            }
        }
    ) -Join ";"

    return $ownerNames, $ownerIds
}

# Check if an Azure AD session is active
try {
    Get-MgOrganization -ErrorAction Stop | Out-Null
}

catch {
    Connect-MgGraph -Scopes "Application.Read.All", "User.Read.All"
}

# Automatically set the Expired switch if the search period is in the past
if ($SearchPeriod -lt 0) {
    $Expired = $true
}

# Get all Azure AD App Registrations
$applications = Get-MgApplication -All | Where-Object { ($_.KeyCredentials) -or ($_.PasswordCredentials) }

# Get all Azure AD Enterprise Applications configured for SAML SSO
$servicePrincipals = Get-MgServicePrincipal -All | Where-Object { 
    (($_.KeyCredentials) -and
    (($_.Tags -contains "WindowsAzureActiveDirectoryCustomSingleSignOnApplication") -or 
    ($_.Tags -contains "WindowsAzureActiveDirectoryGalleryApplicationNonPrimaryV1") -or 
    ($_.Tags -contains "WindowsAzureActiveDirectoryGalleryApplicationPrimaryV1") -or 
    ($_.Tags -contains "WindowsAzureActiveDirectoryIntegratedApp")))   
}

$output = @(

    # Loop through each App Registration and retrieve the credentials properties
    foreach ($app in $applications) {
        Write-Host "Evaluating application $($applications.IndexOf($app)) of $(@($applications).Count): [$($app.DisplayName)] with app Id [$($app.AppId)]"

        # Get the app owners and their object ID
        $ownerNames, $ownerIds = Get-Owners -AppObjectId $app.Id -ObjectType "Application"

        # Get certificate properties
        foreach ($cert in $app.KeyCredentials) {
            Export-Credential -App $app -ObjectType "Application" -OwnerNames $ownerNames -OwnerIds $ownerIds -Credential $cert -CredentialType "Certificate"
        }

        # Get client secret properties
        foreach ($secret in $app.PasswordCredentials) {
            Export-Credential -App $app -ObjectType "Application" -OwnerNames $ownerNames -OwnerIds $ownerIds -Credential $secret -CredentialType "ClientSecret"
        }
    }

    # Loop through each Enterprise Application and retrieve the credentials properties 
    foreach ($app in $servicePrincipals) {
        Write-Host "Evaluating service principal $($servicePrincipals.IndexOf($app)) of $(@($servicePrincipals).Count): [$($app.DisplayName)] with app Id [$($app.AppId)]"

        # Get the app owners and their object ID
        $ownerNames, $ownerIds = Get-Owners -AppObjectId $app.Id -ObjectType "ServicePrincipal"

        # Get certificate properties filtering for certificates with Usage of Verify, to exclude the private key objects used for signing
        foreach ($cert in $app.KeyCredentials | Where-Object {$_.Usage -eq "Verify"} ) {
            Export-Credential -App $app -ObjectType "ServicePrincipal" -OwnerNames $ownerNames -OwnerIds $ownerIds -Credential $cert -CredentialType "Certificate"
        }
    }
)

# Export the results as a CSV file
$filePath = Join-Path $FolderPath -ChildPath $FileName

try {
    $output | Sort-Object ApplicationName | Export-CSV $filePath -NoTypeInformation
    Write-Host "Export to $filePath succeeded" -ForegroundColor Cyan
}

catch {
    Write-Error "Export to $filePath failed | $_ "
}
