# Unusual Addition of Credentials to an OAuth Application

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1098.001 | Account Manipulation: Additional Cloud Credentials | https://attack.mitre.org/techniques/T1098/001/ |

#### Description
Detects unusual additions of credentials to an OAuth application. The query identifies the actor, affected application, and permissions assigned to the new credential.

#### Risk
An attacker who adds a credential to an OAuth application can retain persistent access and use the application's permissions to access cloud resources.

#### References
- https://learn.microsoft.com/en-us/defender-cloud-apps/investigate-anomaly-alerts
- https://learn.microsoft.com/en-us/entra/identity-platform/app-objects-and-service-principals

## Sentinel
```KQL
BehaviorInfo
| where ActionType == "UnusualAdditionOfCredentialsToAnOauthApp"
| project TimeGenerated, ActionType, BehaviorId, AccountObjectId, AccountUpn
| join kind=inner (BehaviorEntities | where EntityType == "OAuthApplication" and EntityRole == "Related") on BehaviorId
| extend AppPermissions = parse_json(AdditionalFields).Permissions
| project-rename Actor = AccountUpn, ActorObjectId = AccountObjectId, ImpactedApplication = Application, ImpactedApplicationId = ApplicationId
| project-reorder TimeGenerated, ActionType, Actor, ActorObjectId, ImpactedApplication, ImpactedApplicationId, AppPermissions
```
