# System Security Plan (SSP) Control Implementation

## IA-11 Re-authentication

**Control Requirement**  
The information system requires users to re-authenticate under the conditions defined by the organization’s session management and authentication policy.

**Implementation Summary**  
The system enforces re-authentication through centralized identity services and application session controls. Re-authentication is required after inactivity, after session lifetime expiration, and when users perform privileged or security-sensitive actions. Administrative and privileged actions require fresh authentication and, where applicable, multifactor authentication.

**Enforcement Details**  
- Inactivity timeout: **15 minutes**
- Maximum interactive session duration: **12 hours**
- Privileged action re-authentication: **Required**
- Session invalidation on logout, credential change, or token expiration: **Enabled**

**AWS GovCloud Implementation**  
AWS IAM Identity Center permission set session duration is used to control the duration of federated sessions, and IAM role maximum session duration is used where applicable. CloudTrail records console sign-in activity, including federated sign-in events, for audit review.

**Azure Government Implementation**  
Microsoft Entra Conditional Access sign-in frequency is used to require reauthentication at defined intervals. Conditional Access policy objects and sign-in logs are retrieved through Microsoft Graph for evidence collection and review.

**Logging and Monitoring**  
Authentication events, session expiration events, and reauthentication prompts are centrally logged. Logs are retained and reviewed in accordance with audit and accountability requirements.

**Evidence Referenced**  
- Configuration exports for AWS IAM Identity Center and IAM roles
- CloudTrail lookup results for sign-in and session events
- Microsoft Graph export of Conditional Access policies
- Microsoft Graph export of sign-in logs
- Screenshot or recording showing forced reauthentication after timeout

**Assessment Objective**  
Demonstrate that users are required to reauthenticate according to policy and that the configured controls operate as intended.
