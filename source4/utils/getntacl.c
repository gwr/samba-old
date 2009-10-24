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
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "libcli/security/security.h"
#include "system/filesys.h"
#include "librpc/gen_ndr/ndr_xattr.h"
#include "lib/cmdline/popt_common.h"
#include "param/param.h"
#include "param/loadparm.h"


static void ntacl_print_debug_helper(struct ndr_print *ndr, const char *format, ...) PRINTF_ATTRIBUTE(2,3);

static void ntacl_print_debug_helper(struct ndr_print *ndr, const char *format, ...)
{
	va_list ap;
	char *s = NULL;
	int i;

	va_start(ap, format);
	vasprintf(&s, format, ap);
	va_end(ap);

	for (i=0;i<ndr->depth;i++) {
		printf("    ");
	}

	printf("%s\n", s);
	free(s);
}

static NTSTATUS get_ntacl(TALLOC_CTX *mem_ctx,
			  char *filename,
			  struct xattr_NTACL **ntacl, 
			  ssize_t *ntacl_len)
{
	DATA_BLOB blob;
	ssize_t size;
	enum ndr_err_code ndr_err;
	struct ndr_pull *ndr;

	*ntacl = talloc(mem_ctx, struct xattr_NTACL);

	size = wrap_getxattr(filename, XATTR_NTACL_NAME, NULL, 0);

	if (size < 0) {
		fprintf(stderr, "get_ntacl: %s\n", strerror(errno));
		return NT_STATUS_INTERNAL_ERROR;
	}

	blob.data = talloc_array(*ntacl, uint8_t, size);
	size = wrap_getxattr(filename, XATTR_NTACL_NAME, blob.data, size);
	if (size < 0) {
		fprintf(stderr, "get_ntacl: %s\n", strerror(errno));
		return NT_STATUS_INTERNAL_ERROR;
	}
	blob.length = size;

	ndr = ndr_pull_init_blob(&blob, NULL, NULL);

	ndr_err = ndr_pull_xattr_NTACL(ndr, NDR_SCALARS|NDR_BUFFERS, *ntacl);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_map_error2ntstatus(ndr_err);
	}

	return NT_STATUS_OK;
}

static void print_ntacl_sddl(TALLOC_CTX *mem_ctx,
			struct xattr_NTACL *ntacl)
{
	const char *sddl;
	sddl = sddl_encode(mem_ctx,ntacl->info.sd,NULL);
	printf("%s\n",sddl);
}
static void print_ntacl(TALLOC_CTX *mem_ctx,
			const char *fname,
			struct xattr_NTACL *ntacl)
{
	struct ndr_print *pr;

	pr = talloc_zero(mem_ctx, struct ndr_print);
	if (!pr) return;
	pr->print = ntacl_print_debug_helper;

	ndr_print_xattr_NTACL(pr, fname, ntacl);
	talloc_free(pr);
}

int main(int argc, const char *argv[])
{
	int ret = 0;
 	NTSTATUS status;
	struct xattr_NTACL *ntacl;
	ssize_t ntacl_len;
	int print_as_sddl = 0;
	char *readfile = NULL;
	poptContext pc;
	struct loadparm_context *lp_ctx;
	struct poptOption long_options[] = {
		POPT_AUTOHELP
		{"as-sddl", '\0', POPT_ARG_NONE, &print_as_sddl, true, "Print NT ACL as SDDL"},
		POPT_COMMON_SAMBA
		POPT_COMMON_VERSION
		{ NULL }
	};

	setup_logging(NULL, DEBUG_STDERR);

	pc = poptGetContext(NULL, argc, argv, long_options, 
			    POPT_CONTEXT_KEEP_FIRST);
	poptSetOtherOptionHelp(pc, "[OPTION(S)...] file");

	while(poptGetNextOpt(pc) != -1);
	// Skip programe name
	poptGetArg(pc); 
	if(poptPeekArg(pc)) {
		readfile = strdup(poptGetArg(pc)); 
	}


	lp_ctx = cmdline_lp_ctx;

	status = get_ntacl(NULL, readfile, &ntacl, &ntacl_len);
	
	if (!NT_STATUS_IS_OK(status)) {
		fprintf(stderr, "get_ntacl failed: %s\n", nt_errstr(status));
		return 1;
	}
	
	if( print_as_sddl ) {
		print_ntacl_sddl(ntacl,  ntacl);
	} else {
		print_ntacl(ntacl, readfile, ntacl);
	}

	talloc_free(ntacl);

	return 0;
}
