Configuration MVPre {

    Import-DSCResource -ModuleName 'PSDscResources'

    # Version 2.1.46
    Script OS.Verify_SMB1ProtocolDisabled
    {
      # What: Disable (and remove) SMB1 protocol
      # How:  Script resource (PsDscResource module) -- 'Disable-WindowsOptionalFeature' command
      # Why:  DCs should not have older SMB Protocols enabled

      SetScript = { Write-Output "Verify SMB1 Protocol Disabled"}
      TestScript = { (Get-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol").State -in ("Disabled","DisabledWithPayloadRemoved") }
      GetScript = { @{ Result = (Get-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol").State -in ("Disabled","DisabledWithPayloadRemoved")} }
    }

    Script Svc.Verify_WinDefend
    {
      # What: Ensure WinDefend service is running (Automatic startup type)
      # How:  Script resource (Default DSC module)
      # Why:  The WinDefend service must be running for Defender to function properly

      SetScript = { Write-Output "Start the Windows Defender Service" }
      TestScript = { (get-service windefend).status -eq "Running" }
      GetScript = { @{ Result = $((get-service windefend).status -eq "Running" ) } }
    }

    Script WinDefend.Verify_RealTimeProtection
    {
        # What: Ensure Windows Defender 'RealTimeProtection' feature is enabled 
        # How:  DSC Script resource ('Set-MpPreference' cmdlet)
        # Why:  Realtime Protection must be enabled on AD DCs

        SetScript  = { Write-Output "Enable RealTimeProtection" } 
        TestScript = { !([bool](Get-MpPreference | Select-Object -ExpandProperty DisableRealtimeMonitoring)) }
        GetScript  = { @{Result = !([bool](Get-MpPreference | Select-Object -ExpandProperty DisableRealtimeMonitoring))} }
    }

    Script WinDefend.Verify_AntivirusSignatureAge
    {
        # What: Ensure Windows Defender Antivirus Signatures are updated
        # How:  DSC Script resource (No 'SetScript' configuration occurring)
        # Why:  Realtime Protection must be enabled and updating on AD DCs

        SetScript  = { Write-Output "Antivirus signatures have not been updated in the past day." }
        TestScript = { (Get-MpComputerStatus).AntivirusSignatureAge -le 1  }
        GetScript  = { @{Result = (Get-MpComputerStatus).AntivirusSignatureAge -le 1} }
    }

    Script WinDefend.Verify_AntispywareSignatureAge
    {
        # What: Ensure Windows Defender Antispyware Signatures are updated
        # How:  DSC Script resource (No 'SetScript' configuration occurring)
        # Why:  Realtime Protection must be enabled and upoating on AD DCs

        SetScript  = { Write-Output "Antispyware signatures have not been updated in the past day." }
        TestScript = { (Get-MpComputerStatus).AntispywareSignatureAge -le 1  }
        GetScript  = { @{Result = (Get-MpComputerStatus).AntispywareSignatureAge -le 1} }
    }

    Script MDISensor.Verify_ServiceRunning
    {
      # What: Ensure MDI service is running (ATP Sensor)
      # How:  Script resource (Default DSC module)
      # Why:  The MDI Sensor is required on each Domain Controller

      SetScript = { Write-Output "MDI Sensor is Not Running" }
      TestScript = { (get-service AATPSensor).status -eq "Running" -AND (get-service AATPSensorUpdater).status}
      GetScript = { @{ Result = (get-service AATPSensor).status -eq "Running" -AND (get-service AATPSensorUpdater).status} }
    }

    Script MDISensor.Verify_OnboardingComplete
    {
      # What: Ensure MDI Service is onboarded correctly to the Azure endpoint (ATP Sensor)
      # How:  Script resource (Default DSC module)
      # Why:  The MDI Sensor must be onboarded correctly after installation or updates

      SetScript = { Write-Output "MDI Onboarding Did Not Complete" }
      TestScript = { (Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status" -Name "OnboardingState") -eq 1}
      GetScript = { @{ Result = (Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status" -Name "OnboardingState") -eq 1} }
    }

    Script MDE.Verify_NoEventLogAlerts
    {
      # What: Ensure there are no Warning, Error or Critical Alerts in the Event Log over the past 30 minutes 
      # How:  Script resource (Default DSC module)
      # Why:  The MDE Sensor is required to be functioning without errors on all Domain Controllers

      SetScript = { Write-Output "MDE Event Log Search" }
      TestScript = {
        $xpath = "*[System[Provider[@Name='Microsoft-Windows-SENSE'] and Level<4 and TimeCreated[timediff(@SystemTime) <= 1800000]]]"
        (get-winevent -ProviderName "Microsoft-Windows-SENSE" -FilterXPath $xpath -ErrorAction:SilentlyContinue -MaxEvents 1) -eq $null
      }
      GetScript = { 
        $xpath = "*[System[Provider[@Name='Microsoft-Windows-SENSE'] and Level<4 and TimeCreated[timediff(@SystemTime) <= 1800000]]]"
        @{ Result = ((get-winevent -ProviderName "Microsoft-Windows-SENSE" -FilterXPath $xpath -ErrorAction:SilentlyContinue -MaxEvents 1) -eq $null)}
      }
    }

    Script SplunkForwarder.Configuration_SecurityLogs
    {
        # What: Ensure the Splunk Forwarder is sending the correct Windows Event Logs
        # How:  Script DSC Resource (New-Item PS cmdlet)
        # Why:  Required to ensure the Splunk Forwarder is sending the correct set of Event Logs based on the server being a domain controller

        SetScript  = {Write-Output "Testing DSC Splunk Security Logs Forwarding"}
        TestScript = {[Bool](Get-Content "C:\Program Files\SplunkUniversalForwarder\var\log\splunk\metrics.log" | Where-Object{$_ -like "*wineventlog:security*"})}
        GetScript  = {@{ Result = [Bool](Get-Content "C:\Program Files\SplunkUniversalForwarder\var\log\splunk\metrics.log" | Where-Object{$_ -like "*wineventlog:security*"})}}
    
    } # End of SplunkForwarder.Configuration_SecurityLogs

    Script SplunkForwarder.Configuration_ServiceHealth
    {
        # What: Ensure the Splunk Forwarder health reports are all Green
        # How:  Script DSC Resource (New-Item PS cmdlet)
        # Why:  Required to ensure the Splunk Forwarder is sending the correct set of Event Logs based on the server being a domain controller

        SetScript  = {Write-Output "Testing Splunk Health Log"}
        TestScript = {[bool]!(Get-Content "C:\Program Files\SplunkUniversalForwarder\var\log\splunk\health.log" -last 13 | Where-Object{$_ -notlike "*color=green*"})}
        GetScript  = {@{ Result = [bool]!(Get-Content "C:\Program Files\SplunkUniversalForwarder\var\log\splunk\health.log" -last 13 | Where-Object{$_ -notlike "*color=green*"})}}
    
    } # End of SplunkForwarder.Configuration_ServiceHealth

    Script SplunkForwarder.Verify_ServiceRunning
    {
        # What: Ensure Splunk Universal Forwarder service is running
        # How:  Script DSC Resource
        # Why:  Required to send DC logs to our Splunk instance

        SetScript = { Write-Output "Start the Windows Defender Service" }
        TestScript = { ((get-service -Name SplunkForwarder).status -eq "Running") -AND (Get-CimInstance Win32Reg_AddRemovePrograms | Where-Object{$_.Displayname -eq "UniversalForwarder"}) }
        GetScript = { @{ Result = $(((get-service -Name SplunkForwarder).status -eq "Running") -AND (Get-CimInstance Win32Reg_AddRemovePrograms | Where-Object{$_.Displayname -eq "UniversalForwarder"}) ) } }
    }

    Script Driver.Verify_SmartCardDriverInstalled
    {
        # What: Ensure the Gemalto Smart Card driver is installed
        # How:  DSC Script resource (No 'SetScript' configuration occurring)
        # Why:  Domain Controllers require smart card drivers to be accessible from the ARES forest

        SetScript  = { Write-Output "Smart card drivers are not installed" }
        TestScript = { [bool](Get-WindowsDriver -Online | Where-Object{$_.ProviderName -eq "Gemalto"}) }
        GetScript  = { @{Result = ([bool](Get-WindowsDriver -Online | Where-Object{$_.ProviderName -eq "Gemalto"}))} }
    }

    Script Configuration.Verify_GlobalCatalogCheck
    {
        # What: Ensure the Domain Controller is a Global Catalog
        # How:  DSC Script resource (No 'SetScript' configuration occurring)
        # Why:  Domain Controllers should all be Global Catalogs

        SetScript  = { Write-Output "Is this DC a Global Catalog?" }
        TestScript = { [Bool](Get-ADDomainController -Server $env:computername).IsGlobalCatalog }
        GetScript  = { @{Result = [Bool](Get-ADDomainController -Server $env:computername).IsGlobalCatalog} }
    }

    Script SCCM-Client.Verify_AgentInstalled
    {
      # What: Ensure Configuration Manager (SCCM) Client is installed
      # How:  Script resource (Default DSC module) -- 'CCMSetup.exe' command
      # Why:  SCCM Agent must be installed to be managed via SCCM

      SetScript = { Write-Output "Install & Configure the SCCM Agent"}
      TestScript = {[Bool](Get-CimInstance Win32Reg_AddRemovePrograms | Where-Object { $_.DisplayName -eq "Configuration Manager Client"})}
      GetScript = { @{ Result = [Bool](Get-CimInstance Win32Reg_AddRemovePrograms | Where-Object { $_.DisplayName -eq "Configuration Manager Client"})} }
    } # End of SCCM-Client.Verify_AgentInstalled

    Script AzureADPasswordProtection.Verify_AgentInstalledandRunning
    {
      # What: Configure Azure AD DC Password Protection Agent
      # How:  Script DSC Resource
      # Why:  The Azure AD DC Password Protection Agent must be configured on all DCs

      SetScript = {Write-Output "Install Azure AD Password Protection DC Agent"}
      TestScript = {(Get-WmiObject -Class Win32Reg_AddRemovePrograms | Where-Object{$_.DisplayName -eq "Azure AD Password Protection DC Agent"}) -AND ((get-service -Name AzureADPasswordProtectionDCAgent).Status -eq "Running")}
      GetScript = { @{ Result = $((Get-WmiObject -Class Win32Reg_AddRemovePrograms | Where-Object{$_.DisplayName -eq "Azure AD Password Protection DC Agent"}) -AND ((get-service -Name AzureADPasswordProtectionDCAgent).Status -eq "Running"))} }
    }
    
    Script Configuration.Verify_ServerOwner
    {
        # What: Ensure computer object owner is set to "Domain Admins" group in the server's AD Domain
        # How:  Script DSC Resource
        # Why:  Security policy for all Domain Controllers require that the object owner be just the Domain Admins group

        SetScript = {Write-Output "Set VM Owner to Domain Admins group"}

        TestScript = {
          $domainName = ((Get-CimInstance -ClassName Win32_Computersystem).Domain).Split(".")[0]
          (get-adcomputer -Identity $env:Computername -Properties ntSecurityDescriptor).ntSecurityDescriptor.Owner -eq "$domainName\Domain Admins"
        }

        GetScript =  {  
          $domainName = ((Get-CimInstance -ClassName Win32_Computersystem).Domain).Split(".")[0]
          @{ Result = (get-adcomputer -Identity $env:Computername -Properties ntSecurityDescriptor).ntSecurityDescriptor.Owner -eq "$domainName\Domain Admins"}
        }
    } # End of Configuration.Verify_ServerOwner

    Script Configuration.Verify_ADComputerDescription
    {
      # What: Ensure the ADComputer description contains "Domain Controller"
      # How:  Script DSC Resource
      # Why:  To have consistent ADComputer descriptions
      
      SetScript = {Write-Output (Get-ADComputer $env:COMPUTERNAME -Properties Description).Description}
      TestScript = {(Get-ADComputer $env:COMPUTERNAME -Properties Description).Description -like '* Domain Controller*'}
      GetScript = { @{ Result = ((Get-ADComputer $env:COMPUTERNAME -Properties Description).Description -like '* Domain Controller*') }}
    }

    Script Configuration.Verify_NetworkTesting
    {
        # What: Ensure the server has updated DNS with the AD-specific SRV records
        # How:  Script DSC Resource
        # Why:  In order for Kerberos & LDAP connectivitry to function in Active Directory, DNS must have Service Specific SRV records created for each domain controller

        SetScript = {Write-Output "DNS and/or DC Connectivity Testing failed"}

        TestScript = {
            $computerName = $env:COMPUTERNAME
            $adSite = (Get-ADDomainController -Identity $computerName).Site
            $serverDNSDomainName = (Get-CimInstance -Namespace root\cimv2 -Class Win32_ComputerSystem).Domain.ToLower()

            # DNS SRV Records that should have been added via Dynamic DNS at DC Promotion time
            $srvRecordsToSearchFor = "_kerberos._tcp.dc._msdcs.$serverDNSDomainName","_ldap._tcp.dc._msdcs.$serverDNSDomainName","_kerberos._tcp.$serverDNSDomainName","_kpasswd._tcp.$serverDNSDomainName","_ldap._tcp.$serverDNSDomainName","_kerberos._udp.$serverDNSDomainName","_kpasswd._udp.$serverDNSDomainName"
            $srvSiteRecords = "_kerberos._tcp.$adSite._sites.dc._msdcs.$serverDNSDomainName","_ldap._tcp.$adSite._sites.dc._msdcs.$serverDNSDomainName","_kerberos._tcp.$adSite._sites.$serverDNSDomainName","_ldap._tcp.$adSite._sites.$serverDNSDomainName"

            # SYSVOL and NetLogon Share access from new DC to the Domain PDC
            New-PSDrive -Name "NetLogonTest" -PSProvider FileSystem -Root "\\$((get-addomain).PDCEmulator)\NetLogon"
            New-PSDrive -Name "SysVolTest" -PSProvider FileSystem -Root "\\$((get-addomain).PDCEmulator)\SysVol"

            ($srvRecordsToSearchFor | ForEach-Object{Resolve-DnsName $_ -Type SRV | Where-Object{$_.NameTarget -eq $computername + "." + $serverDNSDomainName}}) -AND ($srvSiteRecords  | ForEach-Object{Resolve-DnsName $_ -Type SRV | Where-Object{$_.NameTarget -eq $computername + "." + $serverDNSDomainName}}) -AND (get-psdrive -Name "NetLogonTest") -AND (get-psdrive -Name "SysVolTest")

        }

        GetScript =  { @{ Result = "NetworkTesting Complete" } }
    } # End of Configuration.Verify_NetworkTesting

    Script Configuration.Verify_SitesandServices
    {
        # What: Ensure the Domain Controller is in the correct Site by CIDR address
        # How:  Script DSC Resource
        # Why:  In order for the domain locator service to function correctly, the domain controller must be in the correct Site in Sites and Services

        SetScript = {
            Write-Output "Test Sites and Services by CIDR address"
        }

        TestScript = {
            $sitecidrAddress = ((Get-ADReplicationSite -Properties Subnets).Subnets | ForEach-Object{$_.Split(",")[0].Replace("CN=","")})
            $IPAddress = (Get-NetIPAddress -AddressFamily IPV4 | Where-Object{$_.PrefixOrigin -ne "WellKnown"}).IPAddress
            [int]$Address = [System.BitConverter]::ToInt32(([System.Net.IPAddress]::Parse($IPAddress).GetAddressBytes()), 0)
            $SiteCheckResults = $false

            $sitecidrAddress | ForEach-Object{
                [String]$CIDRAddress = $_.Split('/')[0]
                [int]$CIDRBits       = $_.Split('/')[1]
            
                # Address from range and the search address are converted to Int32 and the full mask is calculated from the CIDR notation.
                [int]$BaseAddress    = [System.BitConverter]::ToInt32((([System.Net.IPAddress]::Parse($CIDRAddress)).GetAddressBytes()), 0)
                [int]$Mask           = [System.Net.IPAddress]::HostToNetworkOrder(-1 -shl ( 32 - $CIDRBits))
            
                
                If(($BaseAddress -band $Mask) -eq ($Address -band $Mask)){
                    $SiteCheckResults = $true
                }
            }
            $SiteCheckResults
        }

        GetScript =  { @{ Result = "SitesAndServices Test Complete" } }
    } # End of Configuration.Verify_SitesandServices

} # End Configuration MVPre
