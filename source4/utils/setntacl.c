/* 
	 Unix SMB/CIFS implementation.

	 Get NT ACLs from UNIX files.

	 Copyright (C) Tim Potter <tpot@samba.org> 2005
	 
	 This program is free software; you can redistribute it and/or modify
	 it under the terms of the GNU General Public License as published by
	 the Free Software Foundation; either version 3 of the License, or
	 (at your option) any later version.
	 
	 This program is distributed in the hope that it will be useful,
	 but WITHOUT ANY WARRANTY; without even the implied warranty of
	 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	See the
	 GNU General Public License for more details.
	 
	 You should have received a copy of the GNU General Public License
	 along with this program.	If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "libcli/security/security.h"
#include "librpc/gen_ndr/ndr_xattr.h"
#include "param/param.h"
#include "lib/cmdline/popt_common.h"
#include "param/param.h"
#include "param/loadparm.h"

static NTSTATUS build_acl(TALLOC_CTX *mem_ctx, char* acls,  struct xattr_NTACL **ntacl)
{
	struct xattr_NTACL *acl = talloc(mem_ctx, struct xattr_NTACL);
	struct security_descriptor *sd;
	NTSTATUS status;
	sd = sddl_decode(mem_ctx,acls,NULL);
	if( !sd ) 
	{
		return NT_STATUS_INTERNAL_ERROR;
	}

	acl->version = 1;
	acl->info.sd = sd;
	
	*ntacl = acl;
	return NT_STATUS_OK;
}

static NTSTATUS set_ntacl(TALLOC_CTX *mem_ctx,
				char *filename,
				void *ntacl)
{
	enum ndr_err_code ndr_err;
	int ret;
	DATA_BLOB blob;

	ndr_err = ndr_push_struct_blob(&blob, mem_ctx, lp_iconv_convenience(NULL), ntacl ,(ndr_push_flags_fn_t)ndr_push_xattr_NTACL);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_map_error2ntstatus(ndr_err);
	}
	ret = wrap_setxattr(filename, XATTR_NTACL_NAME, blob.data,blob.length, 0);

	if (ret !=	0) {
		fprintf(stderr, "set_ntacl: %s\n", strerror(errno));
		return NT_STATUS_INTERNAL_ERROR;
	}
	return NT_STATUS_OK;
}

int main(int argc, const char *argv[])
{
	NTSTATUS status;
	char *acl = NULL;
	char *writtenfile = NULL;
	struct xattr_NTACL *ntacl;
	poptContext pc;
	struct loadparm_context *lp_ctx;
	struct poptOption long_options[] = {
		POPT_AUTOHELP
		POPT_COMMON_SAMBA
		POPT_COMMON_VERSION
		{ NULL }
	};

	setup_logging(NULL, DEBUG_STDERR);

	pc = poptGetContext(NULL, argc, argv, long_options, 
			    POPT_CONTEXT_KEEP_FIRST);
	poptSetOtherOptionHelp(pc, "[OPTION(S)...] acl file\nacl must be in SDDL format check documentation for more information");

	while(poptGetNextOpt(pc) != -1);
	// Skip program name
	poptGetArg(pc);
	if(poptPeekArg(pc)) {
		acl = strdup(poptGetArg(pc)); 
	}

	if(poptPeekArg(pc)) {
		writtenfile = strdup(poptGetArg(pc)); 
	}

	if ( !acl || !writtenfile ) {
	  fprintf(stderr,"ACL and/or file to be written are missing !\nThese parameters are mandatory\n");
	  exit(1);
	}

	lp_ctx = cmdline_lp_ctx;

	status = build_acl(NULL, acl, &ntacl);
	if (!NT_STATUS_IS_OK(status)) {
		fprintf(stderr, "build_acl failed: %s\n", nt_errstr(status));
		return 1;
	}
	status = set_ntacl(NULL, writtenfile, ntacl);
	if (!NT_STATUS_IS_OK(status)) {
		fprintf(stderr, "set_ntacl failed: %s\n", nt_errstr(status));
		return 1;
	}

	talloc_free(ntacl);

	return 0;
}
