#!/usr/bin/python
#
# Manipulate file NT ACLs
#
# Copyright Matthieu Patou 2010 <mat@matws.net>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#


import samba.getopt as options
from samba.dcerpc import security
from samba.ntacls import setntacl, getntacl
import ldb

from samba.auth import system_session
from samba.netcmd import (
    Command,
	SuperCommand,
    CommandError,
    Option,
    )

class cmd_acl_set(Command):
    """Set ACLs on a file"""
    synopsis = "%prog set <acl> <file> [--xattr-backend=native|tdb] [--eadb-file=file] [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "versionopts": options.VersionOptions,
        }

    takes_options = [
        Option("--quiet", help="Be quiet", action="store_true"),
        Option("--xattr-backend", type="choice", help="xattr backend type (native fs or tdb)",
               choices=["native","tdb"]),
        Option("--eadb-file", help="Name of the tdb file where attributes are stored", type="string"),
		]

    takes_args = ["acl","file"]

    def run(self, acl, file, quiet=False,xattr_backend=None,eadb_file=None,
            credopts=None, sambaopts=None, versionopts=None):
        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp)
       	setntacl(lp,file,acl,xattr_backend,eadb_file) 

class cmd_acl_get(Command):
    """Set ACLs on a file"""
    synopsis = "%prog get <file> [--as-sddl] [--xattr-backend=native|tdb] [--eadb-file=file] [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "versionopts": options.VersionOptions,
        }

    takes_options = [
        Option("--as-sddl", help="Output ACL in the SDDL format", action="store_true"),
        Option("--xattr-backend", type="choice", help="xattr backend type (native fs or tdb)",
               choices=["native","tdb"]),
        Option("--eadb-file", help="Name of the tdb file where attributes are stored", type="string"),
        ]

    takes_args = ["file"]

    def run(self, file, as_sddl=False,xattr_backend=None,eadb_file=None,
            credopts=None, sambaopts=None, versionopts=None):
        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp)
       	acl = getntacl(lp,file,xattr_backend,eadb_file) 
        if as_sddl:     
            anysid=security.dom_sid(security.SID_NT_SELF)
            print acl.info.as_sddl(anysid)
        else:
            acl.dump()
            

class cmd_acl(SuperCommand):
    """NT ACLs manipulation"""
	
    subcommands = {}
    subcommands["set"] = cmd_acl_set()
    subcommands["get"] = cmd_acl_get()

