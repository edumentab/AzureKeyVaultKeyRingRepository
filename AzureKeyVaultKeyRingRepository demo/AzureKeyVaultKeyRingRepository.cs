using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Xml.Linq;
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using Microsoft.AspNetCore.DataProtection.Repositories;
using Microsoft.Extensions.Logging;

namespace AzureKeyVaultKeyRingRepository_demo
{
    /// <summary>
    /// AzureKeyVaultKeyRingRepository
    /// ==============================
    /// 
    /// Implementation of IXmlRepository that will store the keys and revocations in Azure Key Vault.
    /// In Azure Key Vault we can store about 12 keys (without key ring encryption)
    ///
    /// Created by Tore Nestenius, 2020-09-03
    ///
    /// Reference source code
    /// FileSystemXmlRepository
    /// https://github.com/dotnet/aspnetcore/blob/master/src/DataProtection/DataProtection/src/Repositories/FileSystemXmlRepository.cs
    ///
    /// Quickstart: Azure Key Vault client library for .NET (SDK v4)
    /// https://docs.microsoft.com/en-us/azure/key-vault/secrets/quick-create-net 
    /// 
    /// Things to improve and investigate:
    /// * KeyVault GetSecretAsync never returns (Is this still an issue?)
    ///   https://stackoverflow.com/questions/33134579/keyvault-getsecretasync-never-returns 
    /// 
    /// </summary>
    public class AzureKeyVaultKeyRingRepository : IXmlRepository
    {
        private readonly ILogger _logger;

        private readonly string _keyRingName;
        private readonly string _vaultUrl;
        
        private readonly string _clientId;
        private readonly string _tenantId;
        private readonly string _secret;

        /// <summary>
        /// According to https://social.technet.microsoft.com/wiki/contents/articles/52480.azure-key-vault-overview.aspx the max
        /// secret size in AKV is 25K, that represents about 12-13 keys and that should be more than enough
        /// </summary>
        private const int AzureKeyVaultSecretMaxLength = 25000;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="keyRingName">The name of the secret that will hold the key-ring</param>
        /// <param name="vaultUrl">The URL to your Azure Key Vault</param>
        /// <param name="clientId">The azure clientId</param>
        /// <param name="tenantId">The azure tenantId</param>
        /// <param name="secret">The azure client secret</param>
        /// <param name="loggerFactory">The <see cref="ILoggerFactory"/>.</param>
        public AzureKeyVaultKeyRingRepository(string keyRingName,
                                              string vaultUrl,
                                              string clientId,
                                              string tenantId,
                                              string secret,
                                              ILoggerFactory loggerFactory)
        {
            _logger = loggerFactory.CreateLogger<AzureKeyVaultKeyRingRepository>();

            _keyRingName = keyRingName;
            _vaultUrl = vaultUrl;
            _clientId = clientId;
            _tenantId = tenantId;
            _secret = secret;
        }

        /// <summary>
        /// Gets all top-level XML elements from Azure Key Vault
        /// </summary>
        /// <returns></returns>
        public IReadOnlyCollection<XElement> GetAllElements()
        {
            _logger.LogInformation("Loading Data Protection Key Ring from Azure Key Vault");

            var credentials = new ClientSecretCredential(tenantId: _tenantId, clientId: _clientId, clientSecret: _secret);
            var client = new SecretClient(new Uri(_vaultUrl), credentials);

            try
            {
                KeyVaultSecret kvSecret = client.GetSecret(_keyRingName);

                string encoded = kvSecret.Value;

                _logger.LogInformation("Key Ring size in Key Vault is {size}", encoded.Length);

                //The data stored in key vault is base64 encoded
                string decoded = Encoding.UTF8.GetString(Convert.FromBase64String(encoded));

                XDocument doc = XDocument.Parse(decoded);

                var entries = new List<XElement>();
                foreach (XElement node in doc.Root.Elements())
                {
                    switch (node.Name.ToString())
                    {
                        case "key":
                            string keyId = node.Attribute("id")?.Value ?? "";

                            var created = DateTime.Parse(node.Element("creationDate").Value);
                            var keyAge = DateTime.Now.Subtract(created).Days;

                            //To keep the key-ring small, we remove items older than 180 days
                            if (keyAge <= 180)
                            {
                                _logger.LogInformation("Loaded key {keyid}", keyId);
                                entries.Add(node);
                            }
                            else
                            {
                                _logger.LogCritical("Ignored old key {keyid}", keyId);
                            }
                            break;
                        case "revocation":
                            //Revocation entries are added to the key-ring if we decide to revoke existing keys
                            var revDate = DateTime.Parse(node.Element("revocationDate").Value);

                            var revAge = DateTime.Now.Subtract(revDate).Days;
                            if (revAge <= 180)
                            {
                                _logger.LogInformation("Loaded revocation entry dated {revocationDate}", revDate);
                                entries.Add(node);
                            }
                            break;
                        default:
                            entries.Add(node);
                            break;
                    }
                }

                _logger.LogInformation("Loaded {keycount} Key Ring items from Azure Key Vault", entries.Count);
                return entries;
            }
            catch (Exception exc)
            {
                _logger.LogInformation("Failed to load secret '{secretname}' from Azure Key Vault, a new Key Ring will be created.", _keyRingName, exc.Message);
                return new List<XElement>();
            }
        }

        /// <summary>
        /// Add a new key to the Key Ring in Azure Key Vault
        /// </summary>
        /// <param name="element">The element to add</param>
        /// <param name="friendlyName">An optional name to be associated with the XML element.</param>
        public void StoreElement(XElement element, string friendlyName)
        {
            _logger.LogInformation("Adding key {key} to Data Protection Key Ring", friendlyName);

            //First get a copy of existing keys in Azure Key Vault
            var existingKeys = GetAllElements().ToList();

            existingKeys.Add(element);

            SaveKeyRingToAzureKeyVault(existingKeys);
        }

        /// <summary>
        /// Save all the keys in the key ring to Azure Key Vault
        /// </summary>
        private void SaveKeyRingToAzureKeyVault(List<XElement> elements)
        {
            //Convert the list of XElement to a XDocument
            XDocument doc = new XDocument();
            var root = new XElement("root");
            doc.Add(root);
            foreach (var key in elements)
            {
                root.Add(key);
            }

            //Base 64 the XDocument for easier storage
            string encodedStr = Convert.ToBase64String(Encoding.UTF8.GetBytes(doc.ToString()));

            StoreSecret(encodedStr);

        }

        /// <summary>
        /// Store the secret in Azure Key Vault
        /// </summary>
        /// <param name="encodedStr"></param>
        private void StoreSecret(string encodedStr)
        {
            var credentials = new ClientSecretCredential(tenantId: _tenantId, clientId: _clientId, clientSecret: _secret);
            var client = new SecretClient(new Uri(_vaultUrl), credentials);

            //Secrets properties documentation https://docs.microsoft.com/en-us/dotnet/api/azure.security.keyvault.secrets.secretproperties?view=azure-dotnet-preview
            var newSecret = new KeyVaultSecret(name: _keyRingName, value: encodedStr)
            {
                Properties =
                {
                    ContentType = "text/plain",
                }
            };

            client.SetSecret(newSecret);

            _logger.LogInformation("Key Ring Size in Azure KeyVault is {size}", encodedStr.Length);

            //Notify in the log, if the keyring size grows over 20Kb in size
            if (encodedStr.Length > (AzureKeyVaultSecretMaxLength - 5000))
                _logger.LogCritical("Key Ring Size is getting to big, current size is {size}, max size is 25Kb", encodedStr.Length);

        }
    }

}
