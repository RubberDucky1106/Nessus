Function Nessus-UpdatePolicy
{
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='Low')]
	param(
		[Parameter(ParameterSetName="p0",
		Mandatory=$true,
		ValueFromPipeline=$True,
		ValueFromPipelineByPropertyName=$True,
		Position=0)]
		$pServer)
		
		#$pServer is FQDN of the Nessus Scanner

		$sKey = "0123456789abcdefghijklmnopqrstuvwxyz"
		$aKey = "0123456789abcdefghijklmnopqrstuvwxyz"

		
		#RESTful API Nessus request to pull all policies
		$PolicyObjects = Invoke-RestMethod -Method "Get" -URI  "https://$($server):8834/policies"  -Headers @{'X-ApiKeys' = "accessKey=$($aKey); secretKey=$($sKey)"}
		#Select policy with the word matching policy name standard ("MMMddyyyy policy")
		$MainPolicy = $PolicyObjects.policies | Where-Object {$_.name -match "\d{1,2}\d{1,2}\d{4}"}
		#Set up PUT RESTful API params which is just settings>name and uuid.
		$RestMethodParams = [ordered]@{
			'settings' = @{
				'name' = $(get-date).ToString("MMMddyyyy")+ " policy"
			}
		}
		# convert params to JSON
		$hash = ConvertTo-Json -InputObject $RestMethodParams
		#RESTful API Nessus request to update the name of the policy
		Invoke-RestMethod -Method "PUT" -URI  "https://$($server):8834/policies/$($MainPolicy.id)"  -Headers @{'X-ApiKeys' = "accessKey=$($aKey); secretKey=$($sKey)"} -ContentType "application/json" -Body $hash
		Write-Host "$Server is done updating policy" -ForegroundColor "Cyan"
}