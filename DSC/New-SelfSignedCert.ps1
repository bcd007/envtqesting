<#	.Description
    ** This function requires running PowerShell as a Admin **

	Function will accept pipeline input and create a self-signed cert that can be added to an Azure Application Registration for authentication use
    The function will create the certificate and export both .cer and .pfx versions of the cert to the destination folder parameter.
    The function will create a helper file (filename.info) that contains the pw and thumbprint for usage in the 'Connect-GraphAPIFromCert' function

    Note:  Once created, you must import the pfx certificate into the personal cert store of the user that requires authentication.

	.Example
	New-GraphSelfSignedCert [-tenantdnsName] <string> [-certfolderPath] <string> [-certfileName] <string>

    .Example
    New-GraphSelfSignedCert -tenantdnsName contoso.microsoftonline.com -certfolderPath "C:\Temp" -certfileName GraphAPICertForUserRead
#>
function GeneratePassword {
    param(
        [ValidateRange(12, 256)]
        [int] 
        $length = 20
    )
	
	$symbols = '!@#$%^&*'.ToCharArray()
	$characterList = 'a'..'z' + 'A'..'Z' + '0'..'9' + $symbols

    do {
        $password = -join (0..$length | ForEach-Object { $characterList | Get-Random })
        [int]$hasLowerChar = $password -cmatch '[a-z]'
        [int]$hasUpperChar = $password -cmatch '[A-Z]'
        [int]$hasDigit = $password -match '[0-9]'
        [int]$hasSymbol = $password.IndexOfAny($symbols) -ne -1

    }
    until (($hasLowerChar + $hasUpperChar + $hasDigit + $hasSymbol) -ge 3)

    $password
}

Function New-GraphSelfSignedCert {
    [CmdletBinding()]
    param(
        [parameter(ValueFromPipelineByPropertyName,Mandatory)][ArgumentCompletions('iuhealthtest.org', 'iuhealth.org')][string]$tenantdnsName,
        [parameter(ValueFromPipelineByPropertyName,Mandatory)][ArgumentCompletions('C:\Temp\')][string]$certfolderPath,
        [parameter(ValueFromPipelineByPropertyName,Mandatory)][string]$certfileName
    )

    #$tenantdnsName = "iuhealth.org" # Your DNS name
    #$certfolderPath = "C:\temp" # Where do you want the files to get saved to? The folder needs to exist.
    #$certfileName = "RoryAppTest" # What do you want to call the cert files? without the file extension

    $password = GeneratePassword # Certificate password
    $yearsValid = 10 # Number of years until you need to renew the certificate

    $certStoreLocation = "Cert:\LocalMachine\My"
    $expirationDate = (Get-Date).AddYears($yearsValid)
        
    $certificate = New-SelfSignedCertificate -DnsName $tenantdnsName -CertStoreLocation $certStoreLocation -NotAfter $expirationDate -KeyExportPolicy Exportable -KeySpec Signature
        
    $certificatePath = $certStoreLocation + '\' + $certificate.Thumbprint
    $filePath = $certfolderPath + '\' + $certfileName
    $securePassword = ConvertTo-SecureString -String $password -Force -AsPlainText
    Export-Certificate -Cert $certificatePath -FilePath ($filePath + '.cer')
    Export-PfxCertificate -Cert $certificatePath -FilePath ($filePath + '.pfx') -Password $securePassword
    Add-Content "C:\Temp\$certfileName.info" $password
    Add-Content "C:\Temp\$certfileName.info" "$($certificate.Thumbprint)"
}
