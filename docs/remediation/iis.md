# IIS

Examples are for IIS 10. Settings that need IIS 10.0 version 1709 (Windows Server 2019, Windows 10 1709) or later are marked.

## Redirect and HSTS (IIS 10.0 1709+)

IIS has native HSTS per site, which also redirects plain HTTP:

```powershell
Import-Module IISAdministration
Reset-IISServerManager -Confirm:$false
Start-IISCommitDelay
$sites = Get-IISConfigSection -SectionPath "system.applicationHost/sites" | Get-IISConfigCollection
$site = Get-IISConfigCollectionElement -ConfigCollection $sites -ConfigAttribute @{"name" = "Default Web Site"}
$hsts = Get-IISConfigElement -ConfigElement $site -ChildElementName "hsts"
Set-IISConfigAttributeValue -ConfigElement $hsts -AttributeName "enabled" -AttributeValue $true
Set-IISConfigAttributeValue -ConfigElement $hsts -AttributeName "max-age" -AttributeValue 31536000
Set-IISConfigAttributeValue -ConfigElement $hsts -AttributeName "includeSubDomains" -AttributeValue $true
Set-IISConfigAttributeValue -ConfigElement $hsts -AttributeName "redirectHttpToHttps" -AttributeValue $true
Stop-IISCommitDelay
```

## Response headers (web.config)

```xml
<configuration>
  <system.webServer>
    <httpProtocol>
      <customHeaders>
        <remove name="X-Powered-By" />
        <add name="Content-Security-Policy"
             value="default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'" />
        <add name="X-Content-Type-Options" value="nosniff" />
        <add name="Referrer-Policy" value="strict-origin-when-cross-origin" />
        <add name="Permissions-Policy" value="camera=(), microphone=(), geolocation=()" />
      </customHeaders>
    </httpProtocol>
    <security>
      <requestFiltering removeServerHeader="true">     <!-- IIS 10.0 1709+: info-disclosure -->
        <verbs>
          <add verb="TRACE" allowed="false" />           <!-- trace-enabled -->
        </verbs>
      </requestFiltering>
    </security>
    <directoryBrowse enabled="false" />                  <!-- directory-listing -->
  </system.webServer>
  <system.web>
    <httpRuntime enableVersionHeader="false" />          <!-- X-AspNet-Version -->
    <httpCookies requireSSL="true" httpOnlyCookies="true" sameSite="Lax" />
  </system.web>
</configuration>
```

`X-AspNetMvc-Version` is removed in code: `MvcHandler.DisableMvcResponseHeader = true;` in `Application_Start`. `sameSite` on `httpCookies` needs .NET Framework 4.7.2 or later.

## Lab: make IIS fail, then pass

The original version of this project was built against an IIS lab target. These commands reproduce it on a disposable Windows VM (replace the IP with your lab address):

```powershell
dism /online /enable-feature /featurename:IIS-WebServer /all /norestart
Import-Module WebAdministration
New-WebBinding -Name "Default Web Site" -Protocol https -IPAddress 10.20.30.31 -Port 443
$cert = New-SelfSignedCertificate -DnsName "target2.lab" -CertStoreLocation Cert:\LocalMachine\My
New-Item "IIS:\SslBindings\10.20.30.31!443" -Thumbprint $cert.Thumbprint -SSLFlags 0 | Out-Null
```

Scan it as-is to see `hsts-missing`, `csp-missing` and `framing-missing`. Then add headers server-wide and scan again:

```powershell
$headers = @{
  'Strict-Transport-Security' = 'max-age=31536000; includeSubDomains'
  'Content-Security-Policy'   = "default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
  'X-Content-Type-Options'    = 'nosniff'
}
foreach ($h in $headers.GetEnumerator()) {
  Add-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' `
    -Filter 'system.webServer/httpProtocol/customHeaders' -Name '.' -Value @{name = $h.Key; value = $h.Value}
}
```

Remove them again with `Remove-WebConfigurationProperty ... -AtElement @{name = '<header>'}`. A custom HSTS header is sent on plain HTTP too; the script reports that as `hsts-over-http` (INFO) and still asks for a redirect, which the native HSTS setting above provides.
