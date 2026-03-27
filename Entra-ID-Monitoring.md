Entra ID Monitoring

List all failed sign-in attempts<BR>
index="task-2" sourcetype="azure:aad:signin" "status.errorCode"!=0 conditionalAccessStatus!=success
| table _time, userPrincipalName, appDisplayName, ipAddress, location.countryOrRegion, status.errorCode, status.failureReason
| sort - _time

The query below can reveal which IP address has the most failure attempts and how many accounts were targeted:<BR>
index="task-2" sourcetype="azure:aad:signin" "status.errorCode"!=0 conditionalAccessStatus!=success
| stats dc(userPrincipalName) as targeted_accounts, count as failures by ipAddress
| sort - failures


A good starting point is to check whether any authentication has been successful using the 
queries below by just replacing the placeholders <TARGET-USER> and <SUSPICIOUS_IP> with the user and IP address you want to investigate.
List successful logins by user:<BR>
index="task-2" sourcetype="azure:aad:signin" "status.errorCode"=0
| where userPrincipalName="<TARGET_USER>"
| stats count by userPrincipalName, status.errorCode, ipAddress
| sort status.errorCode

List successful logins by IP address:<BR>
index="task-2" sourcetype="azure:aad:signin" "status.errorCode"=0
| where ipAddress="<SUSPICIOUS_IP>"
| stats count by userPrincipalName, status.errorCode
| sort status.errorCode



