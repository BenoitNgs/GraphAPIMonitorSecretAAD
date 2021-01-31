################################# Start Functions #################################
Function Get-OAuthGraphAPITocken{
    [CmdletBinding()]
    param(
    [Parameter(Mandatory=$true)][string]$Resource,
    [Parameter(Mandatory=$true)][string]$ClientID,
    [Parameter(Mandatory=$true)][string]$ClientSecret,
    [Parameter(Mandatory=$true)][string]$TenantID
    )


    $ReqTokenBody = @{
        Grant_Type    = "client_credentials"
        Scope         = "https://graph.microsoft.com/.default"
        client_Id     = $clientID
        Client_Secret = $clientSecret
    } 

    $TokenOAuth = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token" -Method POST -Body $ReqTokenBody

    return $TokenOAuth
}


Function Get-GraphAPIQuery{
    [CmdletBinding()]
    param(
    [Parameter(Mandatory=$true)]$TokenOAuth,
    [Parameter(Mandatory=$true)][string]$apiUrlQuery
    )

    $Data = @()
    
    $resQuery = Invoke-RestMethod -Headers @{Authorization = "$($TokenOAuth.token_type) $($TokenOAuth.access_token)"} -Uri $apiUrlQuery -Method Get
    $Data += $resQuery.Value

    while($resquery."@odata.nextLink"){
        $resQuery = Invoke-RestMethod -Headers @{Authorization = "$($TokenOAuth.token_type) $($TokenOAuth.access_token)"} -Uri $resquery."@odata.nextLink" -Method Get
        $Data += $resQuery.Value
    }

    return $Data
}


Function zGet-AADAppsRegistredCertAndSecrestStatus{
    [CmdletBinding()]
    param(
    [Parameter(Mandatory=$true)]$GraphAPIResQueryApplications
    )
    
    $lstAADApps = $GraphAPIResQueryApplications
    $res=@()

    foreach($AADApps in $lstAADApps){

        foreach($AADAppsPasswordCredentials in $AADApps.passwordCredentials){
    
            $dataCollect = New-Object System.object
            $dataCollect | Add-Member -name ‘AppDisplayName’ -MemberType NoteProperty -Value $AADApps.displayName
            $dataCollect | Add-Member -name ‘AppId’ -MemberType NoteProperty -Value $AADApps.appId
            $dataCollect | Add-Member -name ‘id’ -MemberType NoteProperty -Value $AADApps.id
            $dataCollect | Add-Member -name ‘CredExpiration’ -MemberType NoteProperty -Value $AADAppsPasswordCredentials.endDateTime
            $dataCollect | Add-Member -name ‘CredKeyID’ -MemberType NoteProperty -Value $AADAppsPasswordCredentials.keyId
            $dataCollect | Add-Member -name ‘CredType’ -MemberType NoteProperty -Value "Secret"
            $dataCollect | Add-Member -name ‘TTLInDays’ -MemberType NoteProperty -Value $(New-TimeSpan –Start $(get-date) -End $(get-date $AADAppsPasswordCredentials.endDateTime)).Days

            $res += $dataCollect
        }

        foreach($AADAppskeyCredentials in $AADApps.keyCredentials){

            $dataCollect = New-Object System.object
            $dataCollect | Add-Member -name ‘AppDisplayName’ -MemberType NoteProperty -Value $AADApps.displayName
            $dataCollect | Add-Member -name ‘AppId’ -MemberType NoteProperty -Value $AADApps.appId
            $dataCollect | Add-Member -name ‘id’ -MemberType NoteProperty -Value $AADApps.id
            $dataCollect | Add-Member -name ‘CredExpiration’ -MemberType NoteProperty -Value $AADAppskeyCredentials.endDateTime
            $dataCollect | Add-Member -name ‘CredKeyID’ -MemberType NoteProperty -Value $AADAppskeyCredentials.keyId
            $dataCollect | Add-Member -name ‘CredType’ -MemberType NoteProperty -Value "Certificat"
            $dataCollect | Add-Member -name ‘TTLInDays’ -MemberType NoteProperty -Value $(New-TimeSpan –Start $(get-date) -End $(get-date $AADAppsPasswordCredentials.endDateTime)).Days

            $res += $dataCollect
        }
    }

    return $res
}


################################# End Functions #################################

################################# Start Cst and var #################################
#Teddycorp
$cstResource = "https://graph.microsoft.com"
$cstClientID = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXx"
$cstClientSecret = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXx"
$cstTenantID = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXx"


$strQueryURLAPI = "https://graph.microsoft.com/v1.0/applications"

################################# End Cst and var #################################

################################# Start Main #################################

$TokenOAuth = Get-OAuthGraphAPITocken -Resource $cstResource -ClientID $cstClientID -ClientSecret $cstClientSecret -TenantID $cstTenantID

zGet-AADAppsRegistredCertAndSecrestStatus -GraphAPIResQueryApplications $(Get-GraphAPIQuery -TokenOAuth $TokenOAuth -apiUrlQuery $strQueryURLAPI) | FT

################################# End Main #################################
