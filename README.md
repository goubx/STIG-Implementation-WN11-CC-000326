# STIG-Implementation-WN11-CC-000326

##Intial Scan Results 

The results from the intial scan show that over 147 audits failed out of 263.

The failed audit I will be remediating is:

> WN11-CC-000326 - PowerShell script block logging must be enabled on Windows 11.

This is important because, by enabling this, any logs submitted through PowerShell, regardless of whether or not they are obfuscated, can be logged and viewed for forensic analysis.

## Research on the stig ID

After doing some research on the STIG ID, I found the results on stigaview.com

[image]

I also found the correct manual remediation path.

First, I must check for it in the registry editor by:

```
Check
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\

Value Name: EnableScriptBlockLogging

Value Type: REG_DWORD
Value: 1
```

Then, to implement this, I must:

```
Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Windows PowerShell >> "Turn on PowerShell Script Block Logging" to "Enabled".
```

## Manual remediation

First Im going to check out the registry editor and see if the path exists

[image]

As you can see above, the registry path does not exist, which confirms the vulnerability.

Now I will go into the group policy and make the configurations stated above.

[image]

As you can see above, I have now enabled 'Turn on PowerShell Script Block Logging'. I will confirm the correct path is established by rechecking the Registry Editor.

[image]

After enabling the settings within the group policy, the Registry Editor now shows the correct path to remediate the failed audit.

## Manual Remediation Scan results

I will now run another scan to confirm whether or not the manual remediation was successful.











[image]

As you can see above, the manual remediation was successful in passing the audit.

I will now remove the manual remediation and confirm this was sucessful but rerunning the scan.

## Post manual remediation scan results 

[image]

As you can see, the removal of the manual remediation was successful and now i can begin the pragmatic remediation.

## Pragmatic Remediation 

Below is a PowerShell script I developed with Claude to successfully pass the audit.

```powershell
# STIG WN11-CC-000326: PowerShell script block logging must be enabled
$RegPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
$Name    = 'EnableScriptBlockLogging'
$Desired = 1   # 1 = Enabled (log all PowerShell script block execution)

# Create the registry path if it does not exist
if (-not (Test-Path $RegPath)) {
    New-Item -Path $RegPath -Force | Out-Null
    Write-Host "Created registry path: $RegPath"
}

# Apply the EnableScriptBlockLogging value
Set-ItemProperty -Path $RegPath -Name $Name -Value $Desired -Type DWord -Force
Write-Host "Set $Name to $Desired in $RegPath"

# Verify
$Current = (Get-ItemProperty -Path $RegPath -Name $Name).$Name
if ($Current -eq $Desired) {
    Write-Host "Compliant: $Name = $Current"
} else {
    Write-Warning "Non-compliant: $Name = $Current, expected $Desired"
}
```
I will now run this on PowerShell and rescan the machine to see if the audit successfully passes.

## Post pragmatic remediation scan 

[image]

As you can see above the powershell script was successful in passing the audit, proving it was efficent.

