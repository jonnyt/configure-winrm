<#
Ref:  https://technet.microsoft.com/en-us/library/cc782312(v=ws.10).aspx
#>

[cmdletbinding(SupportsShouldProcess=$True)]
Param(
    [Parameter(Mandatory=$false)][switch]$AllowSelfSigned=[switch]$false,
    [Parameter(Mandatory=$false)][string]$CertTemplate='UCB.Computer.Authentication.V2'
)

Import-Module servermanager

# Get our FQDN
$tcpipParms = Get-Item -Path HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters
$fqdn = "$($tcpipParms.GetValue("Hostname")).$($tcpipParms.GetValue("NV Domain"))"

# Install WinRM if not already there
if(!(Get-WindowsFeature -Name 'WinRM-IIS-Ext').Installed)
{
    Add-WindowsFeature WinRm-IIS-Ext -WhatIf:$WhatIfPreference
}

# Do enable-psremoting first.... then run through other settings?

# Set some basic WinRM config for security
Set-WSManInstance WinRM/Config/Service/Auth -ValueSet @{Certificate = $true}
Set-WSManInstance WinRM/Config/Service/Auth -ValueSet @{Basic = $false}
Set-WSManInstance WinRM/Config/Service/Auth -ValueSet @{Kerberos = $true}
Set-WSManInstance WinRM/Config/Service -ValueSet @{AllowUnencrypted = $false}
Set-WSManInstance WinRM/Config/Service -ValueSet @{MaxConcurrentOperationsPerUser="100"}
Set-WSManInstance WinRM/Config/WinRS -ValueSet @{MaxMemoryPerShellMB = 1024}
Set-WSManInstance WinRM/Config/Client -ValueSet @{TrustedHosts="*"}
Set-WSManInstance WinRM/Config -ValueSet @{MaxTimeoutms="300000"} # 5 minutes


# Check for our certificate using the given template name
Function Get-SignedCertByNameAndTempate($fqdn,$template)
{
    $allCerts = Get-Childitem -path cert:\LocalMachine\My | ? {$_.Subject -eq "cn=$fqdn"}

    foreach($cert in $allCerts)
    {
        $temp = $prints[0].Extensions | ? {$_.Oid.Value -eq "1.3.6.1.4.1.311.20.2"}
        if($temp -eq $null)
        {
            $temp = $prints[0].Extensions | ? {$_.Oid.Value -eq "1.3.6.1.4.1.311.21.7"}
        }
        if($temp -ne $null)
        {
            $template = $temp.Format(1)
            if($template.Contains($CertTemplate))
            {
                return $cert
            }
        }
    }
}

Function Create-SelfSignedCertificate($fqdn)
{
    # From: http://blogs.technet.com/b/vishalagarwal/archive/2009/08/22/generating-a-certificate-self-signed-using-powershell-and-certenroll-interfaces.aspx
    $name = new-object -com "X509Enrollment.CX500DistinguishedName.1"
    $name.Encode("CN=$hostname", 0)

    $key = new-object -com "X509Enrollment.CX509PrivateKey.1"
    $key.ProviderName = "Microsoft RSA SChannel Cryptographic Provider"
    $key.KeySpec = 1
    $key.Length = 1024
    $key.SecurityDescriptor = "D:PAI(A;;0xd01f01ff;;;SY)(A;;0xd01f01ff;;;BA)(A;;0x80120089;;;NS)"
    $key.MachineContext = 1
    $key.Create()

    $serverauthoid = new-object -com "X509Enrollment.CObjectId.1"
    $serverauthoid.InitializeFromValue("1.3.6.1.5.5.7.3.1")
    $ekuoids = new-object -com "X509Enrollment.CObjectIds.1"
    $ekuoids.add($serverauthoid)
    $ekuext = new-object -com "X509Enrollment.CX509ExtensionEnhancedKeyUsage.1"
    $ekuext.InitializeEncode($ekuoids)

    $cert = new-object -com "X509Enrollment.CX509CertificateRequestCertificate.1"
    $cert.InitializeFromPrivateKey(2, $key, "")
    $cert.Subject = $name
    $cert.Issuer = $cert.Subject
    $cert.NotBefore = get-date
    $cert.NotAfter = $cert.NotBefore.AddDays(90)
    $cert.X509Extensions.Add($ekuext)
    $cert.Encode()

    $enrollment = new-object -com "X509Enrollment.CX509Enrollment.1"
    $enrollment.InitializeFromRequest($cert)
    $certdata = $enrollment.CreateRequest(0)
    $enrollment.InstallResponse(2, $certdata, 0, "")
}

# Get an appropriate certificate
$myCert = Get-SignedCertByNameAndTempate -fqdn $fqdn -template $CertTemplate
if($myCert -eq $null -and $AllowSelfSigned)
{
    $myCert = Create-SelfSignedCertificate -fqdn $fqdn
}

# Get our cert thumbprint
$thumbprint = $myCert.Thumbprint

# Create an HTTPS listener with the cert thumbprint
if(!$WhatIfPreference)
{
    New-WSManInstance WinRM/Config/Listener -SelectorSet @{Address = "*"; Transport = "HTTPS"} -ValueSet @{Hostname = $fqdn; CertificateThumbprint = $thumbprint}
}
else
{
    Write-Output "WhatIf: WinRM/Config/Listener -SelectorSet @{Address = `"*`"; Transport = `"HTTPS`"} -ValueSet @{Hostname = $fqdn; CertificateThumbprint = $thumbprint}"
}