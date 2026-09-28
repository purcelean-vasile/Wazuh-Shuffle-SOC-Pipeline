# Define network share path
$wazuh_installer_file = "\\path\to\wazuh-agent.msi"
$log_path = "\\path\to\wazuh-agent_install_logs.txt"

#Check if wazuh is already installed
$wazuh_service = Get-Service -Name "Wazuh" -ErrorAction SilentlyContinue 
if ($null -eq $wazuh_service) {

   #Test installer path
   if (!(Test-Path $wazuh_installer_file)) {
      "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - Network path not found" >>  $log_path
      exit 
   }
   try {
        # Install wazuh-agent
        $process = Start-Process msiexec.exe -ArgumentList @(
        "/i",
        $wazuh_installer_file,
        "/q",
        "WAZUH_MANAGER=<MANAGER-IP>",
        "WAZUH_AGENT_NAME=$env:computername"
        ) -Wait -PassThru

        if ($process.ExitCode -ne 0) {
            "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - wazuh-agent installation failed on endpoint $env:computername" >>  $log_path
           exit
        }

        "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - wazuh-agent successfully installed  on endpoint $env:computername" >>  $log_path
    
        # Wait for the service to register.
        do {
            Start-Sleep -Seconds 2
            $wazuh_service = Get-Service -Name "Wazuh" -ErrorAction SilentlyContinue
        } until ($wazuh_service)

        # Start the service
        Start-Service -Name "Wazuh" -ErrorAction Stop
        "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - wazuh-agent service started on endpoint $env:computername" >> $log_path
   }

   catch {
          "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - wazuh-agent deployment error on endpoint $env:computername - $($_.Exception.Message)" >> $log_path
   }
 
}