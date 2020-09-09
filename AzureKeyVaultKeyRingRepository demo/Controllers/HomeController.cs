using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Linq;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using AzureKeyVaultKeyRingRepository_demo.Models;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.AspNetCore.DataProtection.Repositories;
using Microsoft.Extensions.Configuration;

namespace AzureKeyVaultKeyRingRepository_demo.Controllers
{
    public class HomeController : Controller
    {
        private readonly IKeyManager _keyManager;
        private readonly IXmlRepository _keyring;


        public HomeController(IKeyManager keyManager, IConfiguration configuration, ILoggerFactory loggerFactory)
        {
            _keyring = new AzureKeyVaultKeyRingRepository(
                keyRingName: configuration["DataProtection:KeyRingName"],
                vaultUrl: configuration["Vault:Url"],
                clientId: configuration["Vault:ClientId"],
                tenantId: configuration["Vault:TenantId"],
                secret: configuration["Vault:Secret"],
                loggerFactory: loggerFactory);
            
            _keyManager = keyManager;

        }


        /// <summary>
        /// Load the key ring from Azure Key Vault and render it on screen
        /// </summary>
        /// <returns></returns>
        public IActionResult Index()
        {
            var keys = new Dictionary<string, string>();

            int counter = 1;
            foreach (var entry in _keyring.GetAllElements())
            {
                string str = PrettyXml(entry);
                keys.Add("Entry" + counter, str);
                counter++;
            }

            return View(keys);
        }

        public IActionResult Privacy()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }


        /// <summary>
        /// Ask the Data Protection API to issue a new key and add it to the key ring
        /// </summary>
        /// <returns></returns>
        [HttpPost]
        public IActionResult CreateNewKey()
        {
            //Create a new key that will be valid for 30 days
            _keyManager.CreateNewKey(
                activationDate: DateTimeOffset.Now,
                expirationDate: DateTimeOffset.Now.AddSeconds(30));

            return RedirectToAction("Index");
        }



        /// <summary>
        /// Ask the Data Protection API to
        /// the keys in the key ring. A new key will then be issued.
        /// </summary>
        /// <returns></returns>
        [HttpPost]
        public IActionResult RevokeAllKeys()
        {
            //All keys with a creation date before this value will be revoked.
            _keyManager.RevokeAllKeys(DateTimeOffset.Now, "We got hacked!!!");

            return RedirectToAction("Index");
        }


        /// <summary>
        /// Helper method to pretty format XML 
        /// </summary>
        /// <param name="element"></param>
        /// <returns></returns>
        private string PrettyXml(XElement element)
        {
            var stringBuilder = new StringBuilder();

            var settings = new XmlWriterSettings();
            settings.OmitXmlDeclaration = true;
            settings.Indent = true;
            settings.NewLineOnAttributes = true;
            settings.NewLineChars = "\r\n";

            using (var xmlWriter = XmlWriter.Create(stringBuilder, settings))
            {
                element.Save(xmlWriter);
            }

            return stringBuilder.ToString();
        }
    }
}
