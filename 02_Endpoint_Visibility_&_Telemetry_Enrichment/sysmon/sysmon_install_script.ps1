
# Define network share path
$sysmon_folder = "\\path\to\Sysmon"
$sysmon_Exe = "$sysmon_folder\Sysmon64.exe"
$sysmon_config = "$sysmon_folder\sysmon_config.xml"
$sysmon_log_path = "\\path\to\sysmon_logs.txt"
 
# Check if sysmon is already installed
$sysmon_service = Get-Service -Name Sysmon64 -ErrorAction SilentlyContinue
if ($null -eq $sysmon_service) {
 
   # Test installer and config path
   if (!(Test-Path $sysmon_Exe) -or !(Test-Path $sysmon_config)) {
      "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - Network path not found" >> $sysmon_log_path
      exit
   }
   try {
       # Install Sysmon with configuration
       $process = Start-Process -FilePath $sysmon_Exe -ArgumentList @(
       "-accepteula",
       "-i",
       "$sysmon_config"
       ) -Wait -PassThru -ErrorAction Stop

       if ($process.ExitCode -ne 0) {
          "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - sysmon installation failed on endpoint $env:computername" >> $sysmon_log_path
          exit
       }      
       "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - sysmon succesfully installed  on endpoint $env:computername" >> $sysmon_log_path
      }
      catch { 
             "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - sysmon deployment error on endpoint $env:computername - $($_.Exception.Message)" >> $sysmon_log_path
      }
}
