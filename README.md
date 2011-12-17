# What is ADVpki?

ADVpki is a small utility used to generate X509v3 digital certificates and certificate authority (CA). It is released under GPLv3.


# How to use ADVpki?

To create a new SSL certificate "www.example.org" from a CA named "My Test CA":

`advpki -a="My Test CA" -n="www.example.org" -u=Server`

If the CA does not yet exist, it is created before creating the certificate. By default, certificate are stored in the Windows store of the current user but you can also store them in the Machine store with the -m option:

`advpki -a="My Test CA" -n="www.example.org" -u=Server -m`

You can create certificate for servers (SSL/TLS), for clients (SSL/TLS client authentication) and for signing code.


# What are the command line options?

- -a or --autority=<ca> Name of the certificate authority (CA). It is created if it does not yet exist.
- -n or --name=<name> Name (subject) of the certificate
- -u or --usage=<usage> Usage of the certificate (Server, Client or Code)
- -m or --machine To store certificate in the machine store instead of the store of the current user (you need administrative rights)
- -h or -? or --help To get some help about this tool


# How to build ADVpki

In order to build ADVpki, you need to have Visual Studio 2010 or 2011 Developer Preview. The current project is created with Visual Studio 2011. Open the solution ADVpki.sln and build it.


# Copyright and license

Copyright (c) 2011 - [ADVTOOLS SARL](http://www.advtools.com)
 
This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program.  If not, see <http://www.gnu.org/licenses/>.
