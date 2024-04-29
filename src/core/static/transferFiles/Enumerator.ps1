function Get-Privilege {
    $privilegeInformation = (whoami /priv) | Out-String

    if ($privilegeInformation.Contains("SeDebugPrivilege")) {
        return $true
    } else {
        return $false
    }
}

function Get-ComputerOsArchitecture {
    $result = (gwmi win32_computersystem).SystemType

    if ($result.Contains("64")) {
        return "64-bit"
    } elseif ($result.Contains("86")) {
        return "32-bit"
    } else {
        return "Unknown"
    }
}

function Get-TargetComputerInformation {
    $hostname = (hostname)
    $currentUser = [System.Environment]::UserName
    $computerOsArchitechure = Get-ComputerOsArchitecture
    $hasDebugPrivilege = Get-Privilege
    $isDomainJoinedComputer = (Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain

    $targetComputer = @{
        hostname = $hostname;
        currentUser = $currentUser;
        computerOsArchitechure = $computerOsArchitechure;
        hasDebugPrivilege = $hasDebugPrivilege;
        isDomainJoinedComputer = $isDomainJoinedComputer;
    }
    return $targetComputer
}

function Get-LdapSearchResult {
    param (
        [string[]]$ldapFilter
    )
    $domain = New-Object System.DirectoryServices.DirectoryEntry
    $search = New-Object System.DirectoryServices.DirectorySearcher
    $search.SearchRoot = $domain
    $search.PageSize = 1000
    $search.Filter = $ldapFilter
    $search.SearchScope = "Subtree"

    $results = $search.FindAll()
    return $results
}

# from https://blog.netwrix.com/2022/08/31/discovering-service-accounts-without-using-privileges/
function Get-ServiceAccountsServicePrincipalNames {
    # build LDAP filters to look for users, but not krbtgt, with SPN values registered for the current domain
    # TODO 1: change the LDAP filters to find more service accounts
    # TODO 2: use `setspn -Q */*`to get SPNs 
    $ldapFilter = "(&(objectclass=user)(objectcategory=user)(!(cn=krbtgt))(servicePrincipalName=*))"
    $results = Get-LdapSearchResult -ldapFilter $ldapFilter

    foreach ($result in $results) {
        $servicePrincipalNames = @()
        $resultHashTable = @{}
        $userEntry = $result.GetDirectoryEntry()

        foreach ($sAMAccountName in $userEntry.sAMAccountName) {
            $formattedsAMAccountName = $sAMAccountName
        }
        foreach ($SPN in $userEntry.servicePrincipalName) {
            $servicePrincipalNames += $SPN
        }
        $resultHashTable.Add($formattedsAMAccountName, @{"servicePrincipalNames" = $servicePrincipalNames})
        $formattedResultArray += $resultHashTable
    }

    return $formattedResultArray
}

# from https://github.com/BornToBeRoot/PowerShell/blob/master/Module/LazyAdmin/Functions/Network/Convert-Subnetmask.ps1
function Convert-Subnetmask {
    param(
        [Int32]$CIDR
    )

    $cidrBits = ("1" * $CIDR).PadRight(32, "0")
    $octets = $cidrBits -split "(.{8})" -ne ''
    $mask = ($octets | ForEach-Object -Process {[Convert]::ToInt32($_, 2) }) -join "."
    return $mask
}

function Get-Subnets {
    $EXCLUDED_SUBNETS = @(
        "255.255.255.255",
        "224.0.0.0",
        "127.0.0.1",
        "127.0.0.0",
        "127.255.255.255",
        "0.0.0.0"
    )
    $EXCLUDED_PREFIXES = @(
        "32",
        "0"
    )

    $destinationPrefix = Get-NetRoute -AddressFamily IPv4 | Select-Object DestinationPrefix

    $resultHashTable = @{}
    foreach ($property in $destinationPrefix) {
        $network = $property.DestinationPrefix
        $subnetIpAddress = ($network -split "/")[0]
        $subnetPrefix = [int]($network -split "/")[1]

        if (($EXCLUDED_SUBNETS -notcontains $subnetIpAddress) -and ($EXCLUDED_PREFIXES -notcontains $subnetPrefix)) {
            $filteredSubnet = @{
                "subnetIpAddress" = $subnetIpAddress;
                "subnetPrefix" = $subnetPrefix;
                "subnetMask" = Convert-Subnetmask -CIDR $subnetPrefix
            }
            $resultHashTable.Add($subnetIpAddress, @{"subnetPrefix" = $subnetPrefix; "subnetMask" = Convert-Subnetmask -CIDR $subnetPrefix})
        }
    }

    return $resultHashTable
}

function Get-DomainComputers {
    $ldapFilter = "(&(objectclass=computer)(objectcategory=computer))"
    $results = Get-LdapSearchResult -ldapFilter $ldapFilter

    foreach ($result in $results) {
        $resultHashTable = @{}
        $computerEntry = $result.GetDirectoryEntry()

        foreach ($CN in $computerEntry.CN) {
            $formattedCN = $CN
        }
        foreach ($dNSHostName in $computerEntry.dNSHostName) {
            $formattedDNSHostName = $dNSHostName
            $ipEntry = [System.Net.Dns]::GetHostEntry($formattedDNSHostName)
            $ipAddress = ($ipEntry.AddressList | Where-Object { $_.AddressFamily -eq "InterNetwork" } | Select-Object -First 1).IPAddressToString
        }
        
        $resultHashTable.Add($formattedCN, @{"dNSHostName" = $formattedDNSHostName; "ipAddress" = $ipAddress})
        $formattedResultArray += $resultHashTable
    } 

    return $formattedResultArray
}

function Get-DomainUsers {
    $ldapFilter = "(&(objectclass=user)(objectcategory=user)(!(cn=krbtgt))(!(cn=Administrator))(!(cn=Guest)))"
    $results = Get-LdapSearchResult -ldapFilter $ldapFilter

    foreach ($result in $results) {
        $resultHashTable = @{}
        $computerEntry = $result.GetDirectoryEntry()

        foreach ($sAMAccountName in $computerEntry.sAMAccountName) {
            $formattedsAMAccountName = $sAMAccountName
        }
        foreach ($displayName in $computerEntry.displayName) {
            $formattedDisplayName = $displayName
        }
        
        $resultHashTable.Add($formattedsAMAccountName, @{"displayName" = $formattedDisplayName})
        $formattedResultArray += $resultHashTable
    }

    return $formattedResultArray
}

function Get-TargetDomainInformation {
    $fullDomainName = (Get-WmiObject -Namespace root\cimv2 -Class Win32_ComputerSystem).Domain
    $domainSid = ([System.Security.Principal.SecurityIdentifier]::new(([ADSI]("LDAP://$fullDomainName")).objectSid.Value, 0)).AccountDomainSid.ToString()
    
    $targetDomain = @{
        $fullDomainName = @{
            "domainSid" = $domainSid;
            "kerberoastableServiceAccounts" = Get-ServiceAccountsServicePrincipalNames;
            "computers" = Get-DomainComputers;
            "users" = Get-DomainUsers;
            "networks" = Get-Subnets
        }
    }

    return $targetDomain
}

function Run-Enumeration {
    $targetComputerInformation = Get-TargetComputerInformation
    $enumeratedInformation = @{
        targetComputer = $targetComputerInformation;
    }

    if ($targetComputerInformation.isDomainJoinedComputer) {
        $targetDomainInformation = Get-TargetDomainInformation
        $enumeratedInformation.Add("targetDomain", $targetDomainInformation)
    }

    $enumeratedJsonInformation = $enumeratedInformation | ConvertTo-Json -Compress -Depth 10
    Write-Output $enumeratedJsonInformation
}

Run-Enumeration