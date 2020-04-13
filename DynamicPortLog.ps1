
#Script for detecting dynamic port exhaustion writing to event log and emailing app owners
#define root dir
$RunDir = Split-Path -Parent $MyInvocation.MyCommand.Definition

#Define path for zip file
$ZipPath = "$RunDir\netstat.zip"

#Create tempdir if not exist
$TempDir = "$RunDir\temp"
$TempDirTest = test-path $TempDir

if(!$TempDirTest){
    $Null = New-item -ItemType Directory $TempDir
}

#Define Log Dir
$log = "$RunDir\lastrun.log"

#Load zipfiles module
function ZipFiles( [string]$sourcedir = "", [string]$zipFullPath = "" ) {
   $boolAlreadyCompleted = Test-Path $zipFullPath
   if ($boolAlreadyCompleted) {return $false}
   Add-Type -Assembly System.IO.Compression.FileSystem
   $compressionLevel = [System.IO.Compression.CompressionLevel]::Optimal
   [System.IO.Compression.ZipFile]::CreateFromDirectory($sourcedir,
      $zipFullPath, $compressionLevel, $false)
   return Test-Path $zipFullPath
}

function WriteToEventLog( [string]$logName = "", [string]$provider = "", [string]$message = "", [string]$entrytype = "" ) {
    #Check if provider exists
    $testProvider = Get-WinEvent -ListProvider $provider -ErrorAction SilentlyContinue
    #Create provider if provider does not exist.
    if(!$testprovider){
        New-EventLog -LogName System -Source $provider -Verbose
    }
    #Write to event log commandlet
    $WriteEventParams = @{
        LogName = $logName
        Source = $provider
        EventID = 9999
        Message = $message
        EntryType = $entrytype
    }
    Write-EventLog @WriteEventParams
}

function DynamicPortsByProc ($netstat) {
    $cols = @(
        @{
            N="AppPool";
            E={(Get-WmiObject Win32_Process -Filter "ProcessID=$($_.Name)").GetOwner().User}
        },
        @{
            N="PID";
            E={$_.Name}
        },
        "Count"
    )
    
    $result = $netstat | Where-Object {
        $_.LocalPort -ge 49152
    } | Group-Object -NoElement -Property OwningProcess | Sort-Object Count -Descending | Select-Object $cols -First 5

    return $result
}


#Start Logging
Try{Stop-Transcript -ErrorAction SilentlyContinue}Catch{}
Try{Start-Transcript $log -ErrorAction continue -Force}Catch{}

#load config
$Config = (Get-Content $Rundir\config.json) -join "`n" | ConvertFrom-Json

$DynamicSetting = Get-NetUDPSetting

Write-Host "$(Get-Date -format u) | Getting NetStat Data"
#Get NetStat data
$NetStat = Get-NetTCPConnection

$DynamicPorts = $NetStat.LocalPort | Sort-Object | Get-Unique | Where-Object {
    $_ -ge $DynamicSetting.DynamicPortRangeStartPort
}

$DynamicRemain = $DynamicSetting.DynamicPortRangeNumberOfPorts - $DynamicPorts.Count

#get port count by pid
$DynamicPortProcs = DynamicPortsByProc -netstat $NetStat

#evaluate against threshold
Write-Host "$(Get-Date -format u) | $($DynamicRemain) / $($DynamicSetting.DynamicPortRangeNumberOfPorts) Remaining" -NoNewline

if($DynamicRemain -le $Config.CritThreshold){
    Write-Host -ForegroundColor Red " - above Critical threshold (Threshold = $($Config.CritThreshold))"

    $Null = Get-ChildItem $TempDir | Remove-Item -Force -Confirm:$false
    $null = Get-ChildItem $RunDir -filter netstat.zip | Remove-Item -Force -Confirm:$false
    
    $NetStat | Select-Object * | Export-Csv "$TempDir\netstat.csv" -NoTypeInformation -Force

    ZipFiles -sourcedir $TempDir -zipFullPath "$RunDir\netstat.zip"

    $Message = "Server: $($ENV:COMPUTERNAME) Exceeded Dynamic Port Critical Thresholds - $($DynamicRemain) / $($DynamicSetting.DynamicPortRangeNumberOfPorts) Dynamic Ports Remaining: Threshold : { $($Config.CritThreshold) }`n$($DynamicPortProcs | ConvertTo-Json -Compress)"

    $MailParams = @{
        Subject = "Server: $($ENV:COMPUTERNAME) Exceeded Dynamic Port Critical Thresholds : Reboot Enabled : $($Config.RebootEnabled.ToString())"
        Body = $Message
        SmtpServer = $Config.SMTP.Server
        From = $Config.SMTP.From
        To = $Config.SMTP.To
        Attachments = $ZipPath
    }
    Send-MailMessage @MailParams

    #Write to Event Log
    WriteToEventLog -logName $Config.LogName -provider $Config.Provider -message $Message -entrytype "Error"

    #Stop logging
    Try{Stop-Transcript -ErrorAction SilentlyContinue}Catch{}

    #Reboot
    if($Config.RebootEnabled){
        Restart-Computer -Force -Confirm:$false -Verbose
    }

}elseif($DynamicRemain -le $Config.WarnThreshold){
    Write-Host -ForegroundColor Green " - above Warning threshold (Threshold = $($Config.WarnThreshold))"

    $Null = Get-ChildItem $TempDir | Remove-Item -Force -Confirm:$false
    $null = Get-ChildItem $RunDir -filter netstat.zip | Remove-Item -Force -Confirm:$false
    
    $NetStat | Select-Object * | Export-Csv "$TempDir\netstat.csv" -NoTypeInformation -Force

    ZipFiles -sourcedir $TempDir -zipFullPath "$RunDir\netstat.zip"

    $Message = "Server: $($ENV:COMPUTERNAME) Exceeded Dynamic Port Warning Thresholds - $($DynamicRemain) / $($DynamicSetting.DynamicPortRangeNumberOfPorts) Dynamic Ports Remaining: Threshold : { $($Config.WarnThreshold) }`n$($DynamicPortProcs | ConvertTo-Json -Compress)"

    $MailParams = @{
        Subject = "Server: $($ENV:COMPUTERNAME) Exceeded Dynamic Port Warning Thresholds"
        Body = $Message
        SmtpServer = $Config.SMTP.Server
        From = $Config.SMTP.From
        To = $Config.SMTP.To
        Attachments = $ZipPath
    }
    Send-MailMessage @MailParams

    #Write to Event Log
    WriteToEventLog -logName $Config.LogName -provider $Config.Provider -message $Message -entrytype "Warning"

    #Stop logging
    Try{Stop-Transcript -ErrorAction SilentlyContinue}Catch{}

}elseif($DynamicRemain -le $Config.InfoThreshold){
    Write-Host -ForegroundColor Green " - above Info threshold (Threshold = $($Config.InfoThreshold))"

    $Message = "Server: $($ENV:COMPUTERNAME) Exceeded Dynamic Port Info Thresholds - $($DynamicRemain) / $($DynamicSetting.DynamicPortRangeNumberOfPorts) Dynamic Ports Remaining: Threshold : { $($Config.InfoThreshold) }`n$($DynamicPortProcs | ConvertTo-Json -Compress)"

    #Write to Event Log
    WriteToEventLog -logName $Config.LogName -provider $Config.Provider -message $Message -entrytype "Information"
    
    #Stop logging
    Try{Stop-Transcript -ErrorAction SilentlyContinue}Catch{}

}else{
    Write-Host -ForegroundColor Green " - below threshold (Threshold = $($Config.InfoThreshold)) - no action taken"
    
    #Stop logging
    Try{Stop-Transcript -ErrorAction SilentlyContinue}Catch{}
}




