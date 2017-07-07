Function Nessus_ScanGeneration
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
		[ValidateSet("JAN","FEB","MAR","APR","MAY","JUN","JUL","AUG","SEP","OCT","NOV","DEC")]
		$mmm,
		
		[Parameter(ParameterSetName="p0",
		Mandatory=$true,
		ValueFromPipeline=$True,
		ValueFromPipelineByPropertyName=$True,
		Position=0)]
		[ValidatePattern("[0-9]{4}")] 
		$yyyy,
		
		[Parameter(ParameterSetName="p0",
		Mandatory=$true,
		ValueFromPipeline=$True,
		ValueFromPipelineByPropertyName=$True,
		Position=0)]
		$Server)
		)
	
	Write-Progress -Id 0 -Activity 'Loading Scanners' -Status "Processing $($Servcount) of $($NessusServers.count) Servers" -CurrentOperation "$Server" -PercentComplete (($Servcount/$($NessusServers.count)) * 100)
	$sKey = "0123456789abcdefghijklmnopqrstuvwxyz"
	$aKey = "0123456789abcdefghijklmnopqrstuvwxyz"

	#RESTful API Nessus request to pull all policies
	$PolicyObjects = Invoke-RestMethod -Method "Get" -URI  "https://$($server):8834/policies"  -Headers @{'X-ApiKeys' = "accessKey=$($aKey); secretKey=$($sKey)"}
	#Select main dated policy
	$MainPolicy = $PolicyObjects.policies | Where-Object {$_.name -match "\d{1,2}\d{1,2}\d{4}"}
	#pull folders and get the My Scans Folder to extract scans from.
	$Folders = Invoke-RestMethod -Method "Get" -URI  "https://$($server):8834/folders"  -Headers @{'X-ApiKeys' = "accessKey=$($aKey); secretKey=$($sKey)"}
	$MyScansFolder = $folders.folders | Where-Object {$_.name -eq "My Scans"}
	$Files = Get-ChildItem -Path "\ScanDirectory\*.txt"
	
	#iterate through target files to load based on obj.Hash built earlier
	$fileCount = 0
	Foreach ($targetFile in $Files)
	{
		$fileCount++
		Write-Progress -Id 1 -ParentId 0 -Activity 'Loading Scanners' -Status "Processing $($fileCount) of $($($objHash.$server).count) Files" -CurrentOperation "$targetFile" -PercentComplete (($fileCount/$($($objHash.$server).count)) * 100)																																																																												
		#read the file and add a comma between each IP
		$Targets = Get-Content -Path $($targetfile)
		$target = $targets -join ","
		$sequenceNumber = $($targetFile.split("\")[-1].split("-")[-1].split(".")[0].remove(0,3))
		$scanName =$sequenceNumber + "_" + $MMM + $YYYY
		#put params together
		$ScanTime = $date.tostring("yyyyMMdd") + "T163000"#Thhmmss
		$RestMethodParams = [ordered]@{
			'uuid' = $($MainPolicy.template_uuid)
			'settings' = @{
				'name' = $scanName
				'policy_id' = $($MainPolicy.id)
				'folder_id' = $($MyScansFolder.id)
				'enabled' = "True"
				'launch' = 'ONETIME'
				'starttime' = $ScanTime
				'rrules' = 'FREQ=ONETIME'
				'timezone' = "Central Standard Time"
				'text_targets' = $target
			}	
		}	
		#convert param object to JSON
		$hash = ConvertTo-Json -InputObject $RestMethodParams
		#make API call
		$TokenResponse = Invoke-RestMethod -Uri "https://$($server):8834/scans" -Method "POST"  -Body $hash  -Headers @{'X-ApiKeys' = "accessKey=$($aKey); secretKey=$($sKey)"} -ContentType "application/json"
		Write-Host "$scanName was loaded to $server" -ForeGroundcolor "Cyan"
	}

}
