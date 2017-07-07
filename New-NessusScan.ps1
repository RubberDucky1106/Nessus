Function Load_Acunetix
{

	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='Low')]
	param(
		[Parameter(ParameterSetName="p0",
		Mandatory=$true,
		ValueFromPipeline=$True,
		ValueFromPipelineByPropertyName=$True,
		Position=0)]
		$group,
		
		[Parameter(ParameterSetName="p0",
		Mandatory=$true,
		ValueFromPipeline=$True,
		ValueFromPipelineByPropertyName=$True,
		Position=0)]
		$Server)
	

	$sKey = "0123456789abcdefghijklmnopqrstuvwxyz"
	$targets = Get-Content -Path "Scan_Files\$group\*.txt" | Where-Object {$_.trim() -ne "" }
	
	$count = 0
	foreach ($line in $targets)
	{
        $count++
        Write-Progress -Activity 'Loading Scanner' -Status "Processing $($count) of $($targets.count) targets" -PercentComplete (($count/$targets.count) * 100)
		
		#build custom object for the postdata/body in below web request
		$hash = @{
			address = "$line"
			description = "scanning"
			criticality = "10"
		}
		#convert the hash object to JSON
		$body = ConvertTo-Json -InputObject $hash

		Try{Invoke-WebRequest -Uri "https://$($server):3443/api/v1/targets" -Method "POST" -ContentType "application/json" -Headers @{"X-Auth"="$apiKey"} -Body $body}
		
		Catch [Exception]
		{
			If ($_.Exception.Message -like "*utf8*")
			{
				#Powershell doesnt handle UTF8 responses. Ignore errors about it.
			}
			Else
			{
				Write-Host "Unknown Exception:`n$_.Exception.Message" -ForegroundColor "Red"
			}
		} 
	}#	 end $line in $targets
	
	#extract all targets loaded on scanner
	$targets = $webclient.DownloadString("https://$($server):3443/api/v1/targets") | ConvertFrom-Json	
	#extract all scan profiles from scanner
	$scanProfiles = $webclient.DownloadString("https://$($server):3443/api/v1/scanning_profiles") | ConvertFrom-Json
	#save the "full scan" scan profile as a var
	$fullScanProfile = $scanProfiles.scanning_profiles | where {$_.name -eq "Full Scan"}
	#extract all report templates from the scanner
	$report_templates = $webclient.DownloadString("https://$($server):3443/api/v1/report_templates") | ConvertFrom-Json
	#save the "developer" report template as a var
	$developerReport = $report_templates.templates | where {$_.name -eq "Developer"}
	$count = 0
	#iterate through each target from targets var
	foreach ($target in $($targets.targets.target_id))
	{	
		$count++
        Write-Progress -Activity 'Scheduling Scans' -Status "Processing $($count) of $($targets.targets.target_id.count) scans" -PercentComplete (($count/$($targets.targets.target_id.count)) * 100)
		#	Acunetix has a max of 100 scans concurrent

		$hash = [ordered]@{
					#full scan profile uuid
					profile_id = $($fullScanProfile.profile_id)
					#developer report template uuid
					report_template_id = $($developerReport.template_id)
					#schedule nested object
					schedule = [ordered]@{
						#enable the schedule
						disable = $False
						#set the history to zero, don't need to maintain historical data on targets
						history_limit = 0
						#schedule the scan for 1630L the day of. !!!!Need set to local prior to next daylight savingstime change, otherwise itll shift scan an hour
						start_date = (Get-Date -Format "yyyy-MM-ddT20:30:00Z")
						#time sensitive allows scanner to give a specific time
						time_sensitive = $True
					}
					target_id = $target
				}
		$body = ConvertTo-Json -InputObject $hash
		Try{Invoke-WebRequest -Uri "https://$($server):3443/api/v1/scans" -Method "POST" -ContentType "application/json" -Headers @{"X-Auth"="$apikey"} -Body $body}
			
		Catch [Exception]
		{
			If ($_.Exception.Message -like "*utf8*")
			{
				#Powershell doesnt handle UTF8 responses. Ignore errors about it.
			}
			Else
			{
				Write-Host "Unknown Exception:`n$_.Exception.Message" -ForegroundColor "Red"
			}
		} 
	}#	end $target in $($targets.targets.target_id)
}