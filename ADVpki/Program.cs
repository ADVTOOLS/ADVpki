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
using System.Security.Cryptography.X509Certificates;

namespace Advtools.ADVpki
{
    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                ShowInformation();
                ProgramOptions options = ParseCommandLine(args);
                if(options == null)
                    return;

                StoreLocation store = options.MachineStore ? StoreLocation.LocalMachine : StoreLocation.CurrentUser;

                CertificatesAuthority ca = new CertificatesAuthority(options.AuthorityName, store);
                ca.GetCertificate(options.CertificateName, options.Usage, 0);
            }
            catch(Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
        }

        private static ProgramOptions ParseCommandLine(string[] args)
        {
            ProgramOptions options = new ProgramOptions();
            if(!options.ParseCommandLine(args))
                return null;

            if(string.IsNullOrWhiteSpace(options.AuthorityName))
            {
                Console.WriteLine("Invalid name of the certificate authority");
                Console.WriteLine();
                options.ShowUsage();
                return null;
            }

            if(string.IsNullOrWhiteSpace(options.CertificateName))
            {
                Console.WriteLine("Invalid name of the certificate");
                Console.WriteLine();
                options.ShowUsage();
                return null;
            } 
            
            return options;
        }

        private static void ShowInformation()
        {
            Console.WriteLine("ADVpki version 1.0");
            Console.WriteLine("Copyright (c) 2011 ADVTOOLS - www.advtools.com");
            Console.WriteLine();
        }
    }
}
