## Description

These scripts are designed to get information for all **Azure AD** **App Registrations** and **Enterprise Applications** with expiring certificates and client secrets, to assist with application management.

There is one script using the legacy **AzureAD** module, and one script using the **Microsoft.Graph** module. The results are nearly identical other than the **Microsoft.Graph** output including the `DisplayName` property for the `KeyCredentials` and `PasswordCredentials` objects.

Results are exported as a CSV file to the location determined in the script parameters.

## Example Output

| ApplicationName | ApplicationId | ObjectType | Owners | OwnerIds | CredentialType | CredentialDescription | CredentialId | Expired | StartDate | EndDate | DaysToExpire | CertificateUsage |
| - | - |  - |  - |  - |  - |  - |  - |  - |  - |  - |  - |  - | 
| Foo | 78ef88fa-b91e-469f-a41c-fadde9a80f53 | Application | John.Smith@company.com | 30b592d2-a167-4e07-a7ee-80bcca5decbf | ClientSecret | Generated by App Service | c539c3f2-f091-4383-949f-55446bb4fc50 | FALSE | 01/01/2022 00:00 | 12/31/2022 11:59 | 365 | |
| Bar | 2e3d5e85-3a0f-483b-a8d6-1b3b527f4978 | ServicePrincipal | John.Smith@company.com;Jane.Smith@company.com | 8a3cdeaa-c1ac-489c-9fb0-6b72c1604b60 | Certificate | CN=Company CA | 1e10564b-f2a1-4d3f-8ee9-ab8ee5806aff | TRUE | 01/01/2022 00:00 | 01/31/2022 11:59 | -30 | Verify |
