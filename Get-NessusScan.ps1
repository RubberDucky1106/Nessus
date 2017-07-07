Function Get-NessusScan
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

	

		write-host "`nChecking scans on: $Server" 
		$sKey = "0123456789abcdefghijklmnopqrstuvwxyz"
		$aKey = "0123456789abcdefghijklmnopqrstuvwxyz"
	
		#pull folders and get the My Scans Folder to extract scans from.
		$Folders = Invoke-RestMethod -Method "Get" -URI  "https://$($server):8834/folders"  -Headers @{'X-ApiKeys' = "accessKey=$($aKey); secretKey=$($sKey)"}
		$MyScansFolder = $folders.folders | Where-Object {$_.name -eq "My Scans"}
		$AllScans = Invoke-RestMethod -Method "GET" -URI  "https://$($server):8834/scans"  -Headers @{'X-ApiKeys' = "accessKey=$($aKey); secretKey=$($sKey)"} 
		#extract scans contained in my scans folder
		$Scans = $AllScans.scans | where {$($_.folder_id) -eq $($MyScansFolder.id)}
		
		$count = 0
		$exitFlag = $False
		Write-Host "Checking to see if scans are completed..." -ForegroundColor "Magenta"
		Foreach ($Scan in $Scans)
		{	
			$count++
			#RESTful API request to Nessus to extract scan info
			$scanInfo = Invoke-RestMethod -Method "GET" -URI  "https://$($server):8834/scans/$($scan.id)"  -Headers @{'X-ApiKeys' = "accessKey=$($aKey); secretKey=$($sKey)"}
			#check to see if scan is completed. if so, print that it is.
			if ($($scanInfo.info.status) -eq "completed")
			{
				write-host "$($scanInfo.info.name) is $($scanInfo.info.status)" -ForegroundColor "Cyan"
			}
			#if not completed, set exit flag to true.
			else
			{
				write-host "$($scanInfo.info.name) is $($scanInfo.info.status)" -ForegroundColor "Yellow"
				$exitFlag = $True
			}
			#if exit flag is true and every scan has been looked at, notify operator and exit script
			if (($count -eq $($Scans.count)) -and ($exitFlag -eq $True))
			{
				Write-Host "Script cannot be completed. Please wait for all scans to complete and re-execute.`n" -ForegroundColor "Yellow"
				exit
			}
		}# end checking if scans are completed.
	

		write-host "`nPulling reports from: $Server" 

	
		#pull folders and get the My Scans Folder to extract scans from.
		$Folders = Invoke-RestMethod -Method "Get" -URI  "https://$($server):8834/folders"  -Headers @{'X-ApiKeys' = "accessKey=$($aKey); secretKey=$($sKey)"}
		$MyScansFolder = $folders.folders | Where-Object {$_.name -eq "My Scans"}
		$AllScans = Invoke-RestMethod -Method "GET" -URI  "https://$($server):8834/scans"  -Headers @{'X-ApiKeys' = "accessKey=$($aKey); secretKey=$($sKey)"} 
		#extract scans contained in my scans folder
		$Scans = $AllScans.scans | where {$($_.folder_id) -eq $($MyScansFolder.id)}
		
		$count = 1
		#iterate through all scans in my scan folder
		Foreach ($Scan in $Scans)
		{
			Write-Progress -Activity 'Extracting Scan Files' -Status "Processing $($count) of $($Scans.name.count) Scans" -PercentComplete (($count/$($Scans.name.count)) * 100)
			$count++
			#RESTful API request to Nessus to extract scan info
			$scanInfo = Invoke-RestMethod -Method "GET" -URI  "https://$($server):8834/scans/$($scan.id)"  -Headers @{'X-ApiKeys' = "accessKey=$($aKey); secretKey=$($sKey)"}
			#Split the scan name to extract the majcom (first string before first underscore)
			$majcom = $($scan.name).split("_")[0]
			#RESTful API request to Nessus to extract csv. takes  a few seconds to generate
			$CsvExport = Invoke-RestMethod -Method "Post" -URI "https://$($server):8834/scans/$($scan.id)/export" -Body @{'format' = 'csv'}  -Headers @{'X-ApiKeys' = "accessKey=$($aKey); secretKey=$($sKey)"}
			#null status var to hold status of download
			$CsvDownloadStatus = $null
			#while download is not equal to ready status, check status and wait 1 second.
			while ($($CsvDownloadStatus.status) -ne 'ready')
			{
				try
				{
					$CsvDownloadStatus = Invoke-RestMethod -Method "Get" -URI "https://$($server):8834/scans/$($scan.id)/export/$($CsvExport.file)/status"  -Headers @{'X-ApiKeys' = "accessKey=$($aKey); secretKey=$($sKey)"} 
				}
				catch
				{
					#need error catches
				}
				Start-Sleep -Seconds 1
			}
			#once download status is equal to ready, 	RESTful API request to Nessus download csv to correct directory in out-file param
			if ($($CsvDownloadStatus.status) -eq 'ready')
			{
				$CsvDownload = Invoke-RestMethod -Method "Get" -URI "https://$($server):8834/scans/$($scan.id)/export/$($CsvExport.file)/download"  -Headers @{'X-ApiKeys' = "accessKey=$($aKey); secretKey=$($sKey)"} -OutFile "$SinProgISS\Scan Saves\$group\$($scan.name).csv"
			}
			#if scan info contains any lows/meds/highs, RESTful API request to Nessus to download PDF.
			if (($($scanInfo.hosts.low) -gt 0) -or ($($scanInfo.hosts.medium) -gt 0) -or ($($scanInfo.hosts.high) -gt 0))
			{
				#RESTful API request to Nessus to extract pdf. takes  a few seconds to generate
				$PdfExport = Invoke-RestMethod -Method "Post" -URI "https://$($server):8834/scans/$($scan.id)/export" -Body  @{'format' = 'pdf'; 'chapters' = 'vuln_hosts_summary;vuln_by_host'}  -Headers @{'X-ApiKeys' = "accessKey=$($aKey); secretKey=$($sKey)"}
				#null status var to hold status of download
				$PdfDownloadStatus = $null
				#while download is not equal to ready status, check status and wait 1 second.
				while ($($PdfDownloadStatus.status) -ne 'ready')
				{
					try
					{
						$PdfDownloadStatus = Invoke-RestMethod -Method "Get" -URI "https://$($server):8834/scans/$($scan.id)/export/$($PdfExport.file)/status"  -Headers @{'X-ApiKeys' = "accessKey=$($aKey); secretKey=$($sKey)"} 
					}
					catch
					{
						#need error catches
					}
					Start-Sleep -Seconds 1
				}
				#once download status is equal to ready, 	RESTful API request to Nessus download pdf to correct directory in out-file param
				if ($($PdfDownloadStatus.status) -eq 'ready')
				{
					$PdfDownload = Invoke-RestMethod -Method "Get" -URI "https://$($server):8834/scans/$($scan.id)/export/$($PdfExport.file)/download"  -Headers @{'X-ApiKeys' = "accessKey=$($aKey); secretKey=$($sKey)"} -OutFile "$SinProgISS\Reports\$group\$($scan.name).pdf"
				}
			}
			#check to see if a MMMYYYY folder already exists in Nessus. if not, RESTful API request to Nessus to generate the folder based on user defined MMM and YYYY
			if ($($folders.folders.name) -notcontains "$MMM$YYYY")
			{
				Invoke-RestMethod -Method "Post" -URI "https://$($server):8834/folders" -Body  @{'name' = "$($MMM)$($YYYY)"}  -Headers @{'X-ApiKeys' = "accessKey=$($aKey); secretKey=$($sKey)"}
				Write-Host "Creating $MMM$YYYY folder on Nessus" -ForegroundColor "Cyan"
				Start-Sleep -Seconds 2
			}
			#RESTful API request to Nessus to check folders again to get the ID of the MMMYYYY folder id
			$Folders = Invoke-RestMethod -Method "Get" -URI  "https://$($server):8834/folders"  -Headers @{'X-ApiKeys' = "accessKey=$($aKey); secretKey=$($sKey)"}
			$MonYearFolder = $folders.folders | Where-Object {$_.name -eq "$MMM$YYYY"}
			#RESTful API requests to copy each scan to the MMMYYYY folder and delete the original copy.
			Invoke-RestMethod -Method "Post" -URI "https://$($server):8834/scans/$($scan.id)/copy" -Body  @{"folder_id" = $($MonYearFolder.id); "history" = $True; "name" = $($scan.name)}  -Headers @{'X-ApiKeys' = "accessKey=$($aKey); secretKey=$($sKey)"}
			Invoke-RestMethod -Method "Delete" -URI "https://$($server):8834/scans/$($scan.id)"  -Headers @{'X-ApiKeys' = "accessKey=$($aKey); secretKey=$($sKey)"}
		}#end of scan pulling
		Start-Sleep -Seconds 2 # breathing room for web requests

}
