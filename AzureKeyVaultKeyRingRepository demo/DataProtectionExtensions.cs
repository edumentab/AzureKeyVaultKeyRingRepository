using System;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.AspNetCore.DataProtection.XmlEncryption;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace AzureKeyVaultKeyRingRepository_demo
{
    public static class DataProtectionExtensions
    {
        /// <summary>
        /// Configures the data protection system to persist the key-ring as a secret in Azure Key Vault
        /// </summary>
        /// <param name="builder">The <see cref="IDataProtectionBuilder"/>.</param>
        /// <param name="keyRingName">The name of the secret that will hold the key-ring</param>
        /// <param name="vaultUrl">The base URL to your Azure Key Vault</param>
        /// <param name="clientId">The azure clientId</param>
        /// <param name="tenantId">The azure tenantId</param>
        /// <param name="secret">The azure client secret</param>
        /// <returns>A reference to the <see cref="IDataProtectionBuilder" /> after this operation has completed.</returns>
        public static IDataProtectionBuilder PersistKeysToAzureKeyVault(this IDataProtectionBuilder builder, 
                                                                        string keyRingName,
                                                                        string vaultUrl,
                                                                        string clientId, 
                                                                        string tenantId, 
                                                                        string secret)
        {
            if (string.IsNullOrEmpty(keyRingName))
                throw new ArgumentNullException(nameof(keyRingName));
            if (string.IsNullOrEmpty(vaultUrl))
                throw new ArgumentNullException(nameof(vaultUrl));
            if (string.IsNullOrEmpty(clientId))
                throw new ArgumentNullException(nameof(clientId));
            if (string.IsNullOrEmpty(tenantId))
                throw new ArgumentNullException(nameof(tenantId));
            if (string.IsNullOrEmpty(secret))
                throw new ArgumentNullException(nameof(secret));

            builder.Services.AddSingleton<IConfigureOptions<KeyManagementOptions>>(services =>
            {
                return new ConfigureOptions<KeyManagementOptions>(options =>
                {
                    var loggerFactory = services.GetService<ILoggerFactory>() ?? NullLoggerFactory.Instance;

                    options.XmlRepository = new AzureKeyVaultKeyRingRepository(keyRingName, vaultUrl, clientId, tenantId, secret, loggerFactory);
                });
            });

            return builder;
        }

        /// <summary>
        /// Protect the key ring with no protection at all
        ///
        /// This extra extension method can be used if you for some reason don't w 
        /// </summary>
        /// <param name="builder">The <see cref="IDataProtectionBuilder"/>.</param>
        /// <returns>A reference to the <see cref="IDataProtectionBuilder" /> after this operation has completed.</returns>
        public static IDataProtectionBuilder ProtectKeysWithNoEncryption(this IDataProtectionBuilder builder)
        {
            builder.Services.Configure<KeyManagementOptions>(options =>
            {
                options.XmlEncryptor = new NullXmlEncryptor();
            });

            return builder;
        }
    }
}
