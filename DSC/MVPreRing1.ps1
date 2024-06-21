Configuration MVPreRing1 {

    Import-DSCResource -ModuleName 'PSDscResources'
    # Version 2.1.51

    Script OS.Verify_SMB1ProtocolDisabled
    {
      # What: Disable (and remove) SMB1 protocol
      # How:  DSC Script resource (No 'SetScript' configuration occurring)
      # Why:  Only Lilly Manufacturing DCs use SMB1 protocol

      SetScript = { Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol -Remove }
      TestScript = { (Get-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol").State -in ("Disabled","DisabledWithPayloadRemoved") }
      GetScript = { @{ Result = (Get-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol").State -in ("Disabled","DisabledWithPayloadRemoved")} }
    } # End of OS.Verify_SMB1ProtocolDisabled

    Script Svc.Verify_WinDefend
    {
      # What: Ensure WinDefend service is running (Automatic startup type)
      # How:  DSC Script resource (No 'SetScript' configuration occurring)
      # Why:  The WinDefend service must be running for Defender to function properly

      SetScript = { If((Get-CimInstance -ClassName Win32_Service -Filter "Name = 'windefend'").StartName -eq "LocalSystem"){
        Get-Service -Name "windefend" | Start-Service
      }
     }
      TestScript = { (Get-Service -Name "windefend").status -eq "Running" }
      GetScript = { @{ Result = (Get-Service -Name "windefend").status -eq "Running" } }
    } # End of Svc.Verify_WinDefend

    Script WinDefend.Verify_RealTimeProtection
    {
        # What: Ensure Windows Defender 'RealTimeProtection' feature is enabled 
        # How:  DSC Script resource (No 'SetScript' configuration occurring)
        # Why:  Realtime Protection must be enabled on AD DCs

        SetScript  = { Set-MpPreference -DisableRealtimeMonitoring $false } 
        TestScript = { !([bool](Get-MpPreference).DisableRealtimeMonitoring) }
        GetScript  = { @{Result = !([bool](Get-MpPreference).DisableRealtimeMonitoring)} }
    } # End of WinDefend.Verify_RealTimeProtection

    Script WinDefend.Verify_AntivirusSignatureAge
    {
        # What: Ensure Windows Defender Antivirus Signatures are updated
        # How:  DSC Script resource (No 'SetScript' configuration occurring)
        # Why:  Realtime Protection must be enabled and updating on AD DCs

        SetScript  = { Update-MpSignature }
        TestScript = { (Get-MpComputerStatus).AntivirusSignatureAge -le 1  }
        GetScript  = { @{Result = (Get-MpComputerStatus).AntivirusSignatureAge -le 1} }
    } # End of WinDefend.Verify_AntivirusSignatureAge

    Script WinDefend.Verify_AntispywareSignatureAge
    {
        # What: Ensure Windows Defender Antispyware Signatures are updated
        # How:  DSC Script resource (No 'SetScript' configuration occurring)
        # Why:  Realtime Protection must be enabled and upoating on AD DCs

        SetScript  = { Update-MpSignature }
        TestScript = { (Get-MpComputerStatus).AntispywareSignatureAge -le 1  }
        GetScript  = { @{Result = (Get-MpComputerStatus).AntispywareSignatureAge -le 1} }
    } # End of WinDefend.Verify_AntispywareSignatureAge

    Script MDISensor.Verify_ServiceRunning
    {
      # What: Ensure MDI service is running (ATP Sensor)
      # How:  DSC Script resource (No 'SetScript' configuration occurring)
      # Why:  The MDI Sensor is required on each Domain Controller

      SetScript = {        
        If((Get-CimInstance -ClassName Win32_Service -Filter "Name = 'AATPSensor'").StartName -eq "NT AUTHORITY\LocalService" -AND (Get-ItemPropertyValue -path HKLM:\SOFTWARE\Microsoft\PowerShell -Name MDIService) -eq 5){
        Get-Service -Name "AATPSensor" | Start-Service
        Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\PowerShell -Name MDIService -Value 0
        }
        Else{
          $newCounterSet = [Int]((Get-ItemPropertyValue -path HKLM:\SOFTWARE\Microsoft\PowerShell -Name MDIService)) + 1
          Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\PowerShell -Name MDIService -Value $newCounterSet
          throw "Waiting for 5 Compliance Cycles to execute SetScript"
        }
      }
      TestScript = {
        Try{Get-ItemPropertyValue -path HKLM:\SOFTWARE\Microsoft\PowerShell -Name MDIService}
        Catch{Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\PowerShell -Name MDIService -Value 0}
        
        If((Get-Service -Name AATPSensor).status -eq "Running" -AND (Get-Service -Name AATPSensorUpdater).status -eq "Running" -AND (Get-ItemPropertyValue -path HKLM:\SOFTWARE\Microsoft\PowerShell -Name MDIService) -ne 0){
          Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\PowerShell -Name MDIService -Value 0
        }
        (Get-Service -Name AATPSensor).status -eq "Running" -AND (Get-Service -Name AATPSensorUpdater).status -eq "Running"
      }
      GetScript = { @{ Result = (Get-Service -Name "AATPSensor").status -eq "Running" -AND (Get-Service -Name AATPSensorUpdater).status -eq "Running"} }
    } # End of MDISensor.Verify_ServiceRunning

    Script MDISensor.Verify_OnboardingComplete
    {
      # What: Ensure MDI Service is onboarded correctly to the Azure endpoint (ATP Sensor)
      # How:  DSC Script resource (No 'SetScript' configuration occurring)
      # Why:  The MDI Sensor must be onboarded correctly after installation or updates

      SetScript = { Throw "MDI Onboarding in Failed State"}
      TestScript = {(Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status" -Name "OnboardingState") -eq 1}
      GetScript = { @{ Result = (Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status" -Name "OnboardingState") -eq 1} }
    } # End of MDISensor.Verify_OnboardingComplete

    Script MDISensor.Verify_EndpointAvailable
    {
      # What: Ensure MDI Azure Endpoint is available
      # How:  DSC Script resource (No 'SetScript' configuration occurring)
      # Why:  The MDI Sensor endpoint is required for updates and security reporting to MDI

      SetScript = { Throw "MDI Endpoint Not Available" }
      TestScript = {
        Try{
        (Invoke-WebRequest -Uri "https://elilillysensorapi.atp.azure.com/tri/sensor/api/ping" -Proxy "http://proxy.gtm.lilly.com:9000" -UseBasicParsing | Select-Object -Property StatusCode).StatusCode -eq 200}
        Catch{$false}
      }
      GetScript = { 
        Try{
          @{Result = (Invoke-WebRequest -Uri "https://elilillysensorapi.atp.azure.com/tri/sensor/api/ping" -Proxy "http://proxy.gtm.lilly.com:9000" -UseBasicParsing | Select-Object -Property StatusCode).StatusCode -eq 200}}
          Catch{@{ Result = $false}}
      }
    } # End of MDISensor.Verify_EndpointAvailable

    Script MDE.Verify_NoEventLogAlerts
    {
      # What: Ensure there are no Warning, Error or Critical Alerts in the MDE Event Log over the past 30 minutes 
      # How:  DSC Script resource (No 'SetScript' configuration occurring)
      # Why:  The MDE Sensor is required to be functioning without errors on all Domain Controllers

      SetScript = { Throw "MDE Event Log Search Shows Errors" }

      TestScript = {
        $xpath = "*[System[Provider[@Name='Microsoft-Windows-SENSE'] and Level<4 and TimeCreated[timediff(@SystemTime) <= 1800000]]]"
        (Get-Winevent -ProviderName "Microsoft-Windows-SENSE" -FilterXPath $xpath -ErrorAction:SilentlyContinue -MaxEvents 1) -eq $null
      }
      GetScript = { 
        $xpath = "*[System[Provider[@Name='Microsoft-Windows-SENSE'] and Level<4 and TimeCreated[timediff(@SystemTime) <= 1800000]]]"
        @{ Result = ((Get-Winevent -ProviderName "Microsoft-Windows-SENSE" -FilterXPath $xpath -ErrorAction:SilentlyContinue -MaxEvents 1) -eq $null)}
      }
    } # End of MDE.Verify_NoEventLogAlerts

    Script SplunkForwarder.Configuration_SecurityLogs
    {
        # What: Ensure the Splunk Forwarder is sending the correct Windows Event Logs
        # How:  DSC Script resource (No 'SetScript' configuration occurring)
        # Why:  Required to ensure the Splunk Forwarder is sending the correct set of Event Logs based on the server being a domain controller

        SetScript  = {
          If((Get-CimInstance -ClassName Win32_Service -Filter "Name = 'SplunkForwarder'").StartName -ne "LocalSystem"){
            Get-Service -Name "SplunkForwarder" | Stop-Service -Force
            Get-CimInstance -ClassName win32_service -filter "Name = 'SplunkForwarder'" | Invoke-CimMethod -Name Change -Arguments @{StartName=”LocalSystem”}
            Get-Service -Name "SplunkForwarder" | Start-Service
          }
        }
        TestScript = {[Bool](Get-Content -Path "C:\Program Files\SplunkUniversalForwarder\var\log\splunk\metrics.log" | Where-Object{$_ -like "*wineventlog:security*"})}
        GetScript  = {@{ Result = [Bool](Get-Content -Path "C:\Program Files\SplunkUniversalForwarder\var\log\splunk\metrics.log" | Where-Object{$_ -like "*wineventlog:security*"})}}
    
    } # End of SplunkForwarder.Configuration_SecurityLogs

    Script SplunkForwarder.Configuration_ServiceHealth
    {
        # What: Ensure the Splunk Forwarder health reports are all Green
        # How:  DSC Script resource (No 'SetScript' configuration occurring)
        # Why:  Required to ensure the Splunk Forwarder is sending the correct set of Event Logs based on the server being a domain controller

        SetScript  = {Throw "Splunk Health Log shows service that are not Green"}
        TestScript = {[bool]!(Get-Content -Path "C:\Program Files\SplunkUniversalForwarder\var\log\splunk\health.log" -last 13 | Where-Object{$_ -notlike "*color=green*"})}
        GetScript  = {@{ Result = [bool]!(Get-Content -Path "C:\Program Files\SplunkUniversalForwarder\var\log\splunk\health.log" -last 13 | Where-Object{$_ -notlike "*color=green*"})}}
    
    } # End of SplunkForwarder.Configuration_ServiceHealth

    Script SplunkForwarder.Verify_ServiceRunning
    {
        # What: Ensure Splunk Universal Forwarder service is running
        # How:  DSC Script resource (No 'SetScript' configuration occurring)
        # Why:  Required to send DC logs to our Splunk instance

        SetScript = {
          Get-CimInstance -ClassName win32_service -filter "Name = 'SplunkForwarder'" | Invoke-CimMethod -Name Change -Arguments @{StartName=”LocalSystem”}
          Get-Service -Name "SplunkForwarder" | Start-Service
        }
        TestScript = { ((Get-Service -Name SplunkForwarder).status -eq "Running") -AND (Get-CimInstance -ClassName Win32Reg_AddRemovePrograms | Where-Object{$_.Displayname -eq "UniversalForwarder"}) }
        GetScript = { @{ Result = $(((Get-Service -Name SplunkForwarder).status -eq "Running") -AND (Get-CimInstance -ClassName Win32Reg_AddRemovePrograms | Where-Object{$_.Displayname -eq "UniversalForwarder"}) ) } }
    } # End of SplunkForwarder.Verify_ServiceRunning

    Script Driver.Verify_SmartCardDriverInstalled
    {
        # What: Ensure the Gemalto Smart Card driver is installed
        # How:  DSC Script resource (No 'SetScript' configuration occurring)
        # Why:  Domain Controllers require smart card drivers to be accessible from the ARES forest

        SetScript  = { Throw "Smart card drivers are not installed" }
        TestScript = { [bool](Get-WindowsDriver -Online | Where-Object{$_.ProviderName -eq "Gemalto"}) }
        GetScript  = { @{Result = ([bool](Get-WindowsDriver -Online | Where-Object{$_.ProviderName -eq "Gemalto"}))} }
    } # End of Driver.Verify_SmartCardDriverInstalled

    Script Configuration.Verify_GlobalCatalogEnabledCheck
    {
        # What: Ensure the Domain Controller server object is set as a Global Catalog 
        # How:  DSC Script resource (No 'SetScript' configuration occurring)
        # Why:  Domain Controllers should all have Global Catalog Services Enabled

        SetScript  = {
          Set-ADObject -Identity (get-addomaincontroller -Identity $env:ComputerName).NTDSSettingsObjectDN -replace @{options='1'}
        }

        TestScript = { 
          $computerName = $env:COMPUTERNAME
          [Bool](Get-ADDomainController -Server $computerName).IsGlobalCatalog
        }

        GetScript  = {
          $computerName = $env:COMPUTERNAME
          @{Result = [Bool](Get-ADDomainController -Server $computerName).IsGlobalCatalog}
        }
    } # End of Script Configuration.Verify_GlobalCatalogCheck

    Script Driver.Verify_GlobalCatalogSRVRecordsInDNS
    {
        # What: Ensure the SRV records for Global Catalogs were created in DNS
        # How:  DSC Script resource (No 'SetScript' configuration occurring)
        # Why:  Global Catalog location service relies on 4 correct SRV records regsistered in DNS

        SetScript  = {
            Get-Service -Name "netlogon" | Restart-Service
            Start-Sleep -Seconds 10
            IPConfig.exe /registerdns
        }

        TestScript = {
          $adForest = (Get-ADForest).name
          $computerName = $env:COMPUTERNAME
          $adSite = (Get-ADDomainController -Identity $computerName).Site
          $globalCatalogsrvRecordsToSearchFor = "_ldap._tcp.gc._msdcs.$adForest.","_ldap._tcp.$adSite._sites.gc._msdcs.$adForest.","_gc._tcp.$adForest.","_gc._tcp.$adSite._sites.$adForest."
          ($globalCatalogsrvRecordsToSearchFor | ForEach-Object{Resolve-DnsName $_ -Type SRV | Where-Object{$_.NameTarget -like "*$computername*"}}).Count -eq 4
        }

        GetScript  = {
          $adForest = (Get-ADForest).name
          $computerName = $env:COMPUTERNAME
          $adSite = (Get-ADDomainController -Identity $computerName).Site
          $globalCatalogsrvRecordsToSearchFor = "_ldap._tcp.gc._msdcs.$adForest.","_ldap._tcp.$adSite._sites.gc._msdcs.$adForest.","_gc._tcp.$adForest.","_gc._tcp.$adSite._sites.$adForest."
          @{Result = ($globalCatalogsrvRecordsToSearchFor | ForEach-Object{Resolve-DnsName $_ -Type SRV | Where-Object{$_.NameTarget -like "*$computername*"}}).Count -eq 4 }
        }
    } # End of Driver.Verify_GlobalCatalogSRVRecordsInDNS

    Script SCCM-Client.Verify_AgentInstalled
    {
      # What: Ensure Configuration Manager (SCCM) Client is installed
      # How:  DSC Script resource (No 'SetScript' configuration occurring)
      # Why:  SCCM Agent must be installed to be managed via SCCM

      SetScript = { Throw "The SCCM Agent is not installed"}
      TestScript = {[Bool](Get-CimInstance -ClassName Win32Reg_AddRemovePrograms | Where-Object { $_.DisplayName -eq "Configuration Manager Client"})}
      GetScript = { @{ Result = [Bool](Get-CimInstance -ClassName Win32Reg_AddRemovePrograms | Where-Object { $_.DisplayName -eq "Configuration Manager Client"})} }
    } # End of SCCM-Client.Verify_AgentInstalled

    Script PKI-Certificates_VerifyCertificatesInstalled
    {
      # What: Ensure the PKI and ARES Certificates aere installed correctly
      # How:  DSC Script resource (No 'SetScript' configuration occurring)
      # Why:  PKI and ARES Certificates are critical to Domain Controller Functionality and must be installed in the correct location in the Certificate Store

      SetScript = {  Throw "PKI or ARES Certificates are not present" }
      TestScript = {(Get-ChildItem -Path "Cert:\LocalMachine\Root\"|Where-Object{$_.Subject -like "CN=ARES*"}) -and (Get-ChildItem -Path "Cert:\LocalMachine\My\"|Where-Object{$_.Subject -like "CN=$env:COMPUTERNAME*"})}
      GetScript = {@{ Result = (Get-ChildItem -Path "Cert:\LocalMachine\Root\"|Where-Object{$_.Subject -like "CN=ARES*"}) -and (Get-ChildItem -Path "Cert:\LocalMachine\My\"|Where-Object{$_.Subject -like "CN=$env:COMPUTERNAME*"})}}
    } # End of PKI-Certificates_VerifyCertificatesInstalled

    Script PKI-Certificates_VerifyCertificateExpirationDate
    {
      # What: Ensure the PKI and ARES Certificates will not expire in the next 30 days
      # How:  DSC Script resource (No 'SetScript' configuration occurring)
      # Why:  PKI and ARES Certificates are critical to Domain Controller Functionality and must remain valid
      
      DependsOn = '[Script]PKI-Certificates_VerifyCertificatesInstalled'

      SetScript = {  Throw "The PKI or ARES Certificates will expire within 30 days" }

      TestScript = {
        $dateToCheck = (Get-Date).AddMonths(1)
        (Get-ChildItem -Path "Cert:\LocalMachine\Root\"|Where-Object{$_.Subject -like "CN=ARES*"}).NotAfter -ge $dateToCheck -and (Get-ChildItem -Path "Cert:\LocalMachine\My\"|Where-Object{$_.Subject -like "CN=$env:COMPUTERNAME*"}).NotAfter -ge $dateToCheck
      }
      
      GetScript = {
        $dateToCheck = (Get-Date).AddMonths(1)
        If((Get-ChildItem -Path "Cert:\LocalMachine\Root\"|Where-Object{$_.Subject -like "CN=ARES*"}) -and (Get-ChildItem -Path "Cert:\LocalMachine\My\"|Where-Object{$_.Subject -like "CN=$env:COMPUTERNAME*"})){
          @{ Result = (Get-ChildItem -Path "Cert:\LocalMachine\Root\"|Where-Object{$_.Subject -like "CN=ARES*"}).NotAfter -ge $dateToCheck -and (Get-ChildItem -Path "Cert:\LocalMachine\My\"|Where-Object{$_.Subject -like "CN=$env:COMPUTERNAME*"}).NotAfter -ge $dateToCheck}
        }
        Else{@{Result = $false}}
      }

    } # End of PKI-Certificates_VerifyCertificateExpirationDate

    Script AzureADPasswordProtection.Verify_AgentInstalledandRunning
    {
      # What: Configure Azure AD DC Password Protection Agent
      # How:  DSC Script resource (No 'SetScript' configuration occurring)
      # Why:  The Azure AD DC Password Protection Agent must be configured on all DCs

      SetScript = {Throw "Azure AD Password Protection DC Agent not installed or running"}
      TestScript = {(Get-CimInstance -ClassName Win32Reg_AddRemovePrograms | Where-Object{$_.DisplayName -eq "Azure AD Password Protection DC Agent"}) -AND ((Get-Service -Name "AzureADPasswordProtectionDCAgent").Status -eq "Running")}
      GetScript = { @{ Result = $((Get-CimInstance -ClassName Win32Reg_AddRemovePrograms | Where-Object{$_.DisplayName -eq "Azure AD Password Protection DC Agent"}) -AND ((Get-Service -Name "AzureADPasswordProtectionDCAgent").Status -eq "Running"))} }
    } # End of AzureADPasswordProtection.Verify_AgentInstalledandRunning
    
    Script Configuration.Verify_ServerOwner
    {
      # What: Ensure computer object owner is set to "Domain Admins" group in the server's AD Domain
      # How:  DSC Script resource (No 'SetScript' configuration occurring)
      # Why:  Security policy for all Domain Controllers require that the object owner be just the Domain Admins group

      SetScript = {
        $domainName = ((Get-CimInstance -ClassName Win32_Computersystem).Domain).Split(".")[0]
        $comp = Get-ADComputer $env:Computername
        $comppath = "AD:$($comp.DistinguishedName.ToString())"
        $acl = Get-Acl -Path $comppath
        $objUser = New-Object System.Security.Principal.NTAccount($domainName, "Domain Admins")
        $acl.SetOwner($objUser)
        Set-Acl -Path $comppath -AclObject $acl
      }

      TestScript = {
        $domainName = ((Get-CimInstance -ClassName Win32_Computersystem).Domain).Split(".")[0]
        $comp = Get-ADComputer $env:Computername
        $comppath = "AD:$($comp.DistinguishedName.ToString())"
        $acl = Get-Acl -Path $comppath
        $acl.Owner -eq "$domainName\Domain Admins"
      }

      GetScript =  {  
        $domainName = ((Get-CimInstance -ClassName Win32_Computersystem).Domain).Split(".")[0]
        $comp = Get-ADComputer $env:Computername
        $comppath = "AD:$($comp.DistinguishedName.ToString())"
        $acl = Get-Acl -Path $comppath
        @{ Result = $acl.Owner -eq "$domainName\Domain Admins"}
      }
    } # End of Configuration.Verify_ServerOwner

    Script Configuration.Verify_ADComputerDescription
    {
      # What: Ensure the ADComputer description contains "Domain Controller"
      # How:  DSC Script resource (No 'SetScript' configuration occurring)
      # Why:  To have consistent ADComputer descriptions
      
      SetScript = {
        $DomainControllerDescription = (Get-ADReplicationSite).Name + " Domain Controller"
        $domainControllerServerName = $env:Computername
        Set-ADComputer -Identity $domainControllerServerName -Description $DomainControllerDescription
      }
      TestScript = {(Get-ADComputer -Identity $env:COMPUTERNAME -Properties Description).Description -like '* Domain Controller*'}
      GetScript = { @{ Result = ((Get-ADComputer -Identity $env:COMPUTERNAME -Properties Description).Description -like '* Domain Controller*')}}
    } # End of Configuration.Verify_ADComputerDescription

    Script Configuration.Verify_DNSSRVRecordsExist
    {
      # What: Ensure the server has updated DNS with the AD-specific SRV records
      # How:  DSC Script resource (No 'SetScript' configuration occurring)
      # Why:  In order for Kerberos & LDAP connectivitry to function in Active Directory, DNS must have Service Specific SRV records created for each domain controller

      SetScript = {
        Get-Service -Name "netlogon" | Restart-Service
        Start-Sleep -Seconds 10
        IPConfig.exe /registerdns
      }

      TestScript = {
        $computerName = $env:COMPUTERNAME
        $adSite = (Get-ADDomainController -Identity $computerName).Site
        $serverDNSDomainName = (Get-CimInstance -Namespace root\cimv2 -Class Win32_ComputerSystem).Domain.ToLower()

        # DNS SRV Records that should have been added via Dynamic DNS at DC Promotion time
        $srvRecordsToSearchFor = "_kerberos._tcp.dc._msdcs.$serverDNSDomainName","_ldap._tcp.dc._msdcs.$serverDNSDomainName","_kerberos._tcp.$serverDNSDomainName","_kpasswd._tcp.$serverDNSDomainName","_ldap._tcp.$serverDNSDomainName","_kerberos._udp.$serverDNSDomainName","_kpasswd._udp.$serverDNSDomainName"
        $srvSiteRecords = "_kerberos._tcp.$adSite._sites.dc._msdcs.$serverDNSDomainName","_ldap._tcp.$adSite._sites.dc._msdcs.$serverDNSDomainName","_kerberos._tcp.$adSite._sites.$serverDNSDomainName","_ldap._tcp.$adSite._sites.$serverDNSDomainName"

        ($srvRecordsToSearchFor | ForEach-Object{Resolve-DnsName $_ -Type SRV | Where-Object{$_.NameTarget -eq $computername + "." + $serverDNSDomainName}}) -AND ($srvSiteRecords  | ForEach-Object{Resolve-DnsName $_ -Type SRV | Where-Object{$_.NameTarget -eq $computername + "." + $serverDNSDomainName}})
      }

      GetScript =  {
        $computerName = $env:COMPUTERNAME
        $adSite = (Get-ADDomainController -Identity $computerName).Site
        $serverDNSDomainName = (Get-CimInstance -Namespace root\cimv2 -Class Win32_ComputerSystem).Domain.ToLower()

        # DNS SRV Records that should have been added via Dynamic DNS at DC Promotion time
        $srvRecordsToSearchFor = "_kerberos._tcp.dc._msdcs.$serverDNSDomainName","_ldap._tcp.dc._msdcs.$serverDNSDomainName","_kerberos._tcp.$serverDNSDomainName","_kpasswd._tcp.$serverDNSDomainName","_ldap._tcp.$serverDNSDomainName","_kerberos._udp.$serverDNSDomainName","_kpasswd._udp.$serverDNSDomainName"
        $srvSiteRecords = "_kerberos._tcp.$adSite._sites.dc._msdcs.$serverDNSDomainName","_ldap._tcp.$adSite._sites.dc._msdcs.$serverDNSDomainName","_kerberos._tcp.$adSite._sites.$serverDNSDomainName","_ldap._tcp.$adSite._sites.$serverDNSDomainName"

        @{ Result = ($srvRecordsToSearchFor | ForEach-Object{Resolve-DnsName $_ -Type SRV | Where-Object{$_.NameTarget -eq $computername + "." + $serverDNSDomainName}}) -AND ($srvSiteRecords  | ForEach-Object{Resolve-DnsName $_ -Type SRV | Where-Object{$_.NameTarget -eq $computername + "." + $serverDNSDomainName}}) }
      }
    } # End of Configuration.Verify_NetworkTesting

    Script Configuration.Verify_PDCShareAccess
    {
      # What: Ensure the Domain Controller can access the default AD Shares on the Domain PDC
      # How:  DSC Script resource (No 'SetScript' configuration occurring)
      # Why:  In order for file replication to function, each Domain Controller requires access to the Default AD Shares on the Domain PDC
      
      SetScript = {Throw "PDC Share Access Failed"}

      TestScript = {
          # SYSVOL and NetLogon Share access from new DC to the Domain PDC
          New-PSDrive -Name "NetLogonTest" -PSProvider FileSystem -Root "\\$((get-addomain).PDCEmulator)\NetLogon"
          New-PSDrive -Name "SysVolTest" -PSProvider FileSystem -Root "\\$((get-addomain).PDCEmulator)\SysVol"
          (get-psdrive -Name "NetLogonTest" -ErrorAction:SilentlyContinue) -AND (get-psdrive -Name "SysVolTest" -ErrorAction:SilentlyContinue)
      }
      
      GetScript =  {
        $psDriveResult = $false
        $null = New-PSDrive -Name "NetLogonTest" -PSProvider FileSystem -Root "\\$((get-addomain).PDCEmulator)\NetLogon"
        $null = New-PSDrive -Name "SysVolTest" -PSProvider FileSystem -Root "\\$((get-addomain).PDCEmulator)\SysVol"
        $psDriveResult = (get-psdrive -Name "NetLogonTest" -ErrorAction:SilentlyContinue) -AND (get-psdrive -Name "SysVolTest" -ErrorAction:SilentlyContinue)
        @{ Result = $psDriveResult }
      }

    } # End of Configuration.Verify_PDCShareAccess


    Script Configuration.Verify_DCInCorrectSite
    {
        # What: Ensure the Domain Controller is in the correct Site by CIDR address
        # How:  DSC Script resource (No 'SetScript' configuration occurring)
        # Why:  In order for the domain locator service to function correctly, the domain controller must be in the correct Site in Sites and Services

        SetScript = {
            Throw "Domain Controller is not in the correct AD Site"
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

        GetScript =  { @{ Result = $true } }
    } # End of Configuration.Verify_SitesandServices

    Script Configuration.Verify_KerberosAuthentication
    {
      # What: Ensure the Domain Controller is processing Kerberos Logins
      # How:  DSC Script resource (No 'SetScript' configuration occurring)
      # Why:  A primary function of AD Domain Controllers is to process Kerberos authentications
      
      SetScript = {Throw "Domain Controller has no Kerberos Logins in the last 30 Minutes"}

      TestScript = {
        $filterDate = (Get-Date).AddMinutes(-30)
        $SecurityLogFilter = @{
          LogName='Security'
          StartTime=$filterDate
          Id='4624'
        }
        [Bool](Get-WinEvent -FilterHashtable $SecurityLogFilter -MaxEvents 1 -ErrorAction:SilentlyContinue).properties.Value -eq "Kerberos"
      }

      GetScript = {
        $filterDate = (Get-Date).AddMinutes(-30)
        $SecurityLogFilter = @{
          LogName='Security'
          StartTime=$filterDate
          Id='4624'
        }
        @{ Result = ([Bool](Get-WinEvent -FilterHashtable $SecurityLogFilter -MaxEvents 1 -ErrorAction:SilentlyContinue).properties.Value -eq "Kerberos") }
      }
    } # End of Configuration.Verify_KerberosAuthentication

    Script Configuration.Verify_NoADReplicationErrors
    {
      # What: Ensure the Domain Controller replicating AD Data correctly
      # How:  DSC Script resource (No 'SetScript' configuration occurring)
      # Why:  A primary function of AD Domain Controllers is to replicate changed AD data to other domain controllers
      
      SetScript = {Throw "Domain Controller has thrown Alert 5002 in the last 30 Minutes"}

      TestScript = {
        $filterDate = (Get-Date).AddMinutes(-30)
        $DFSLogFilter = @{
          LogName='DFS Replication'
          StartTime=$filterDate
          Id='5002'
        }
        [Bool]!(Get-WinEvent -FilterHashtable $DFSLogFilter -MaxEvents 1 -ErrorAction:SilentlyContinue)
      }

      GetScript = {
        $filterDate = (Get-Date).AddMinutes(-30)
        $DFSLogFilter = @{
          LogName='DFS Replication'
          StartTime=$filterDate
          Id='5002'
        }
        @{ Result = [Bool]!(Get-WinEvent -FilterHashtable $DFSLogFilter -MaxEvents 1 -ErrorAction:SilentlyContinue) }
      }
    } # End of Configuration.Verify_NoADReplicationErrors

} # End Configuration MVPreRing1
