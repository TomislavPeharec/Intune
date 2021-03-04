function Get-AuthToken
{

    <#
.SYNOPSIS
This function is used to authenticate with the Graph API REST interface
.DESCRIPTION
The function authenticate with the Graph API Interface with the tenant name
.EXAMPLE
Get-AuthToken
Authenticates you with the Graph API interface
.NOTES
NAME: Get-AuthToken
#>

    [cmdletbinding()]

    param
    (
        [Parameter(Mandatory = $true)]
        $User
    )

    $userUpn = New-Object System.Net.Mail.MailAddress -ArgumentList $User

    $tenant = $userUpn.Host

    Write-Host "Checking for AzureAD module..."

    $AadModule = Get-Module -Name "AzureAD" -ListAvailable

    if ($AadModule -eq $null)
    {

        Write-Host "AzureAD PowerShell module not found, looking for AzureADPreview"
        $AadModule = Get-Module -Name "AzureADPreview" -ListAvailable

    }

    if ($AadModule -eq $null)
    {
        Write-Host
        Write-Host "AzureAD Powershell module not installed..." -f Red
        Write-Host "Install by running 'Install-Module AzureAD' or 'Install-Module AzureADPreview' from an elevated PowerShell prompt" -f Yellow
        Write-Host "Script can't continue..." -f Red
        Write-Host
        exit
    }

    # Getting path to ActiveDirectory Assemblies
    # If the module count is greater than 1 find the latest version

    if ($AadModule.count -gt 1)
    {

        $Latest_Version = ($AadModule | select version | Sort-Object)[-1]

        $aadModule = $AadModule | ? { $_.version -eq $Latest_Version.version }

        # Checking if there are multiple versions of the same module found

        if ($AadModule.count -gt 1)
        {

            $aadModule = $AadModule | select -Unique

        }

        $adal = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
        $adalforms = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"

    }

    else
    {

        $adal = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
        $adalforms = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"

    }

    [System.Reflection.Assembly]::LoadFrom($adal) | Out-Null

    [System.Reflection.Assembly]::LoadFrom($adalforms) | Out-Null

    $clientId = "d1ddf0e4-d672-4dae-b554-9d5bdfd93547"

    $redirectUri = "urn:ietf:wg:oauth:2.0:oob"

    $resourceAppIdURI = "https://graph.microsoft.com"

    $authority = "https://login.microsoftonline.com/$Tenant"

    try
    {

        $authContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $authority

        # https://msdn.microsoft.com/en-us/library/azure/microsoft.identitymodel.clients.activedirectory.promptbehavior.aspx
        # Change the prompt behaviour to force credentials each time: Auto, Always, Never, RefreshSession

        $platformParameters = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters" -ArgumentList "Always"

        $userId = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier" -ArgumentList ($User, "OptionalDisplayableId")

        $authResult = $authContext.AcquireTokenAsync($resourceAppIdURI, $clientId, $redirectUri, $platformParameters, $userId).Result

        # If the accesstoken is valid then create the authentication header

        if ($authResult.AccessToken)
        {

            # Creating header for Authorization token

            $authHeader = @{
                'Content-Type'  = 'application/json'
                'Authorization' = "Bearer " + $authResult.AccessToken
                'ExpiresOn'     = $authResult.ExpiresOn
            }

            return $authHeader

        }

        else
        {

            Write-Host
            Write-Host "Authorization Access Token is null, please re-run authentication..." -ForegroundColor Red
            Write-Host
            break

        }

    }

    catch
    {

        Write-Host $_.Exception.Message -f Red
        Write-Host $_.Exception.ItemName -f Red
        Write-Host
        break

    }

}

################################################
function New-AADDynamicGroup
{

    <#
    .SYNOPSIS
    This function is used to create dynamic AAD group.

    .DESCRIPTION
    Used to create a new AAD dynamic group (dynamic membership rule is determined by $Rule variable in foreach loop). 
    Due to delays in the group becoming visible for the cmdlet Add-AzureADGroupOwner, process will sleep for 20 seconds until it sets the owner.
    Script is passing the variable $NewGroup further with using $Script:NewGroup which allows the variable to be used with later functions in the script.

    .LINK
    https://github.com/TomislavPeharec

    Script is provided "AS IS" with no warranties.
    #>

    Param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Description,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Rule,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$GroupName,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Owner
    )

    TRY
    {

        $Script:NewGroup = New-AzureADMSGroup -DisplayName $GroupName -MailNickname $GroupName -MailEnabled $false -SecurityEnabled $true -GroupTypes DynamicMembership -Description $Description -MembershipRule $Rule -MembershipRuleProcessingState On

        if ($NewGroup -eq $null)
        {
            Write-Host "Group was not created successfully. Please restart the process." -ForegroundColor Red
            BREAK
        }
        elseif ($NewGroup -ne $null)
        {
            Write-Host "AAD Group created:" $NewGroup.DisplayName -ForegroundColor Green
            Write-Host "20 seconds sleep for the sync." -ForegroundColor Yellow
            Start-Sleep -Seconds 20
        }

        $Failed = $false
        TRY
        {
            $UserObjectID = Get-AzureADUser -ObjectId $Owner
            Add-AzureADGroupOwner -ObjectId $NewGroup.Id -RefObjectId $UserObjectID.ObjectID
            Write-Host "Owner of the group has been set:" $Owner -ForegroundColor Green
            Write-Host ""
            $Failed = $false
        }
        CATCH
        {
            Write-Host "User was not found in the tenant, please assign the owner manually. Process will continue." -ForegroundColor Yellow
            Write-Host ""
            $Failed = $true
        }

    }
    CATCH
    {
        Write-Host ""
        Write-Host ""
        THROW $_.Exception.Message  
    }
    
}
################################################
function New-ScopeTag
{

    <#
    .SYNOPSIS
    This function creates Scope Tag object in Intune.

    .DESCRIPTION
    This function is used to create Scope Tag in Intune and catch its properties.
    Script is passing the variable $NewScopeTag further with using $Script:NewScopeTag which allows the variable to be used with later functions in the script.

    .LINK
    https://github.com/TomislavPeharec

    Script is provided "AS IS" with no warranties.
    #>

    Param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Location,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$OS
    )
    
    $URI_create = "https://graph.microsoft.com/beta/deviceManagement/roleScopeTags"
    
    $DisplayNameScopeTag = $Location + "_" + $OS
    $UserName = (Get-WmiObject -Class Win32_Process -Filter 'Name="explorer.exe"').GetOwner().User | Select-Object -First 1
    $DescriptionScopeTag = "All $Location $OS devices (created by $($UserName) \ $(Get-Date -Format 'dd.MM.yyyy'))"
    $Body_create = @{displayName = $DisplayNameScopeTag; description = $DescriptionScopeTag }
    $JSON_create = $Body_create | ConvertTo-Json

    TRY
    {
        $Script:NewScopeTag = Invoke-RestMethod -Uri $URI_create -Method POST -Headers $authToken -Body $JSON_create

        if ($NewScopeTag -ne $null)
        {
            Write-Host "Scope tag created:" $NewScopeTag.displayName -ForegroundColor Green
        }
        else
        {
            Write-Host  "Something went wrong during the scope tag creation, please check displayed error." -ForegroundColor Red
        }

    }
    CATCH
    {
        Write-Host ""
        Write-Host ""
        THROW $_.Exception.Message
    }

}

################################################
function Update-ScopeTag
{

    <#
    .SYNOPSIS
    This function updates the existing Scope Tag object in Intune.

    .DESCRIPTION
    This function is used to update existing Scope Tag in Intune with assigning the previously created AAD group to it.

    .LINK
    https://github.com/TomislavPeharec

    Script is provided "AS IS" with no warranties.
    #>

    Param
    (

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ScopeTag

    )

    TRY
    {
        $URI_update = "https://graph.microsoft.com/beta/deviceManagement/roleScopeTags/$($NewScopeTag.id)/assign"

        $Body_update = '
        {
            "assignments": [
            {"target":
            {"@odata.type":
            "#microsoft.graph.groupAssignmentTarget",
            "groupId":"' + $NewGroup.Id + '"}}]
        }'

        $UpdateScopeTag = Invoke-RestMethod -Uri $URI_update -Method POST -Headers $authToken -Body $Body_update

        if ($UpdateScopeTag -ne $null)
        {
            Write-Host "Scope tag $($NewScopeTag.DisplayName) has been associated with AAD group" $NewGroup.DisplayName -ForegroundColor Green
            Write-Host ""
            Write-Host "#===============================================================================================#" -ForegroundColor Green
            Write-Host ""
        }
        else
        {
            Write-Host  "Something went wrong during the scope tag update, please check displayed error." -ForegroundColor Red
        }

    }
    CATCH
    {
        Write-Host ""
        Write-Host ""
        THROW $_.Exception.Message
    }


}

################################################
function Get-ScopeTag
{

    <#
    .SYNOPSIS
    This function gets the properties of existing Scope Tag object in Intune.

    .DESCRIPTION
    This function is used to get the current properties of existing Scope Tag object in Intune. 
    It should output the scope tag name, ID, description and name of the AAD group which is in assignment.

    .LINK
    https://github.com/TomislavPeharec

    Script is provided "AS IS" with no warranties.
    #>

    Param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ScopeTag
    )

    TRY
    {
        $URI_get_assignment = "https://graph.microsoft.com/beta/deviceManagement/roleScopeTags/$($NewScopeTag.Id)/assignments"
        $Tag_get_assignment = Invoke-RestMethod -Uri $URI_get_assignment  -Headers $authToken -Method GET

        $GroupIDAssignment = $Tag_get_assignment.value.target.groupId
        $GroupNameAssignment = (Get-AzureADGroup -ObjectId $GroupIDAssignment).DisplayName

        $ScopeTagProperties = [pscustomobject]@{
            ScopeTagName        = $NewScopeTag.DisplayName
            ScopeTagDescription = $NewScopeTag.description
            ScopeTagID          = $NewScopeTag.id
            AssignedGroup       = $GroupNameAssignment
        }

        RETURN $ScopeTagProperties
    }

    CATCH
    {
        Write-Host ""
        Write-Host ""
        THROW $_.Exception.Message
    }

}

################################################

#region Parameters to define
################################################
$OS = "Windows"
$Owner = "tomislav@company.xyz"
$UserName = (Get-WmiObject -Class Win32_Process -Filter 'Name="explorer.exe"').GetOwner().User | Select-Object -First 1

$Locations = Get-Content "C:\Users\$UserName\Desktop\Locations.txt"
$GroupExport = "C:\Users\$UserName\Desktop\AAD_groups_created_$(Get-Date -Format 'dd_MM_yyyy_HH_mm_ss').csv"
$TagExport = "C:\Users\$UserName\Desktop\Scope_tags_assignment_$(Get-Date -Format 'dd_MM_yyyy_HH_mm_ss').csv"
################################################
#endregion Parameters to define


$GroupExportParameters = @(
    "DisplayName", @{n = 'GroupTypes'; e = { $_.GroupTypes } },
    "Description", 
    "MembershipRule", 
    "MembershipRuleProcessingState"
)

Clear-Host

#region Main script
$global:authToken = Get-AuthToken
Connect-AzureAD

foreach ($item in $Locations)
{
    $Location = $Item
    $Description = "Group contains all " + $Location + " $OS devices (created by $UserName \ $(Get-Date -Format 'dd.MM.yyyy'))"
    $Rule = '(device.deviceOSType -eq ' + '"' + $OS + '"' + ")" + ' and (device.displayName -startsWith ' + '"' + $Location + '"' + ")"
    $GroupName = "SG_D_" + $Location + "_$OS"

    New-AADDynamicGroup -Description $Description -Rule $Rule -GroupName $GroupName -Owner $Owner
    Get-AzureADMSGroup -SearchString $GroupName | Select-Object $GroupExportParameters | Export-Csv $GroupExport -NoTypeInformation -Append

    New-ScopeTag -Location $Location -OS $OS
    Update-ScopeTag -ScopeTag $NewScopeTag
    Get-ScopeTag -ScopeTag $NewScopeTag | Export-Csv $TagExport -NoTypeInformation -Append
}
#endregion Main script