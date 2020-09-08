# AzureKeyVaultKeyRingRepository

The purpose is to demonstrate and show how to store the <a href="https://docs.microsoft.com/en-us/aspnet/core/security/data-protection/introduction" target="_blank">ASP.NET Core Data Protection</a> API key-ring in <a href="https://azure.microsoft.com/en-us/services/key-vault/" target="_blank">Azure Key Vault.</a> The key-ring is stored as a base64 encoded XML document. 

See the blog post XXXXXXXXXXXXXXXXXXXX for more details about this project.


## How to get started

### 1. Azure Key Vault
Create a new Azure Key Vault and in the vault create a new key (RSA/2048) named **dataprotectionkey**. Do take notice of the key identifier url that you pass in as the EncryptionKeyUrl below.

### 2. Credentials
Add the following configuration data via your **appsettings.json** or **user secrets** file. You get the credentials by creating an Azure application in Azure Active Directory. Make sure it has permissions to access your Azure Key Vault.

The **Url** is the full Url to your Vault. The **KeyRingName** is the name of the secret that will contain your key-ring. The key ring is stored as a base64 string. 


```json
{
  "Vault": {
    "Url": "https://myvault.vault.azure.net/",
    "ClientId": "11111111-1234-5678-9012-abcdefabcdef",
    "TenantId": "22222222-1234-5678-9012-abcdefabcdef",
    "Secret": "Your secret"
  },
  "DataProtection": {
    "KeyRingName": "MyKeyRing",
    "EncryptionKeyUrl": "https://myvault.vault.azure.net/keys/dataprotectionkey"
  }
}
```

### 3. Run the project
Start the project and if everyting works, a new secret is created in your Azure Key Vault and via the buttons in the application you can create and revoke keys.


## Feedback wanted!
Feel free to get in touch with issues, feedback, suggestions, questions.


## About Edument
<a href="https://www.edument.se" target="_blank">Edument</a> is a tech/knowledge based company founded in 2010, based in Helsingborg, Sweden. With our specialist knowledge of different technologies, 
we help both international enterprises and local startups with complex IT projects, system developer training and developing/realising 
business ideas through our Techhub.
