# O365 Account Takeover Detection
Requirements: Logging O365 user audit data and Microsoft graph security alerting.
### In the majority of successful phishing events, an attacker will establish pesistence by leveraging email rules to hide their activity while weaponizing the account and moving externally or laterally. This search is based around that post compomise behavior. 

## SPL Code
index=$your-index-here$ sourcetype="o365\:management\:activity"</br>
| eval src=mvindex(split(src,":"), 0)</br>
| eval failed_login_attempts=if(Operation="UserLoginFailed", "1", "0")</br>
| eval successful_logins=if(Operation="UserLoggedIn", "1", "0")</br>
| eval mail_rule_changes=if(Operation="New-InboxRule" OR Operation="Set-InboxRule", "1", "0")</br>
| eval delete_message_action_count=if(_raw="\*DeleteMessage\\", \\"Value\\": \\"True\*", "1", "0")</br>
| stats sum(failed_login_attempts) as failed_login_attempts sum(successful_logins) as successful_logins sum(mail_rule_changes) as mail_rule_changes sum(delete_message_action_count) as delete_message_action_count dc(Operation) as count_of_unique_operations values(Operation) as user_operations values(src) as src values(Workload) as app values(action) as action count as count_of_all_user_activity by UserId</br>
| search \[|search index=$your-index-here$ sourcetype="GraphSecurityAlert" NOT title="Suspicious inbox manipulation rule" earliest=-8h@h latest=-5m@m | rename "userStates{}.userPrincipalName" as UserId | fields UserId\]</br>
| eval severity=if(delete_message_action_count=0, "2", "1")</br>
| where mail_rule_changes>0

### Concept
With the identified behavior of Threat Actors in a post account compromise scenario, I have leveraged Splunk eval if statment to build out what some would call *risk scoring* to be run regularly. user can normally do this during their day to day, so I add in the behaior risk analystics of the security data provided by Microsoft via their Graph API Security alerting. For the subsearch on the Graph alerts, I look back a relative 8 hours from when the saerch is run to detect anything that might've happened outside the SIEM search window.
