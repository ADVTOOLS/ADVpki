/*
 * This file is part of ADVpki
 * Copyright (c) 2011 - ADVTOOLS SARL
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using NDesk.Options;

namespace Advtools.ADVpki
{
    internal class ProgramOptions
    {
        public string AuthorityName { get; private set; }
        public string CertificateName { get; private set; }
        public CertificatesAuthority.Usage Usage { get; private set; }
        public bool MachineStore { get; private set; }
        public string Pkcs10File { get; private set; }
        public bool Help { get; private set; }

        private readonly OptionSet options_ = null;
        
        public ProgramOptions()
        {
            Usage = CertificatesAuthority.Usage.Server;
            MachineStore = false;
            Help = false;

            // Definition of the command-line arguments and how to set the related configuration data
            options_ = new OptionSet()
            {
                { "a|authority=", "Name of the certificate authority (CA)", (string o) => AuthorityName = o },
                { "n|name=", "Name of the certificate (can also be a Distinguished Name)", (string o) => CertificateName = o },
                { "u|usage=", "Usage of the certificate (Server, Client, Code, Authority)", (CertificatesAuthority.Usage o) => Usage = o },
                { "m|machine", "Store certificates in the machine store", o => MachineStore = o != null },
                { "s|sign=", "Sign a PKCS#10 request and generate the certificate", (string o) => Pkcs10File = o },
                { "h|?|help", "Show this message", o => Help = o != null }
            };
        }

        /// <summary>
        /// Parse the command-line arguments
        /// </summary>
        /// <param name="args">Command-line arguments</param>
        /// <returns>Return true if the application can continue, false if it has to stop there</returns>
        public bool ParseCommandLine(string[] args)
        {
            try
            {
                // Parse the command-line arguments (thanks NDesk!)
                List<string> extra = options_.Parse(args);
                // If there are some arguments not parsed, no name of pipe or an invalid port number, show the help
                if(extra.Count > 0)
                {
                    Console.WriteLine("Unknow parameter: {0}", extra[0]);
                    Console.WriteLine();
                    ShowUsage();
                    return false; // Do not continue the application
                }
            }
            catch(OptionException e)
            {
                // Something wrong with the arguments
                Console.WriteLine(e.Message);
                Console.WriteLine("Try 'ADVpki --help' for more information.");
                return false;
            }

            // Show the help?
            if(Help)
            {
                ShowUsage();
                return false;
            }

            // Continue the application
            return true;
        }

        /// <summary>
        /// Display some help about this application
        /// </summary>
        /// <param name="options"></param>
        public void ShowUsage()
        {
            Console.WriteLine("Usage: ADVpki[OPTIONS]");
            Console.WriteLine();
            Console.WriteLine("Options:");
            options_.WriteOptionDescriptions(Console.Out);
        }
    }
}
