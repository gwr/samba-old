/*
   Unix SMB/CIFS implementation.
   test suite for various Domain DFS
   Copyright (C) Matthieu Patou 2010

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
#include "librpc/gen_ndr/security.h"
#include "libcli/smb2/smb2.h"
#include "libcli/smb2/smb2_calls.h"
#include "libcli/libcli.h"
#include "torture/util.h"
#include "torture/smb2/proto.h"
#include "../libcli/smb/smbXcli_base.h"
#include "librpc/gen_ndr/ndr_ioctl.h"
#include "librpc/gen_ndr/ndr_dfsblobs.h"
#include "librpc/ndr/libndr.h"
#include "param/param.h"
#include "torture/torture.h"
#include "torture/dfs/proto.h"

static NTSTATUS
smb2_dfs_cli_call(struct smb2_tree *tree, struct dfs_GetDFSReferral *ref)
{
	uint8_t buf[1024];
	NTSTATUS status;
	enum ndr_err_code ndr_err;
	union smb_ioctl ioctl;
	TALLOC_CTX *tmp_ctx = talloc_new(tree);

	ZERO_ARRAY(buf);

	ZERO_STRUCT(ioctl);
	ioctl.smb2.level = RAW_IOCTL_SMB2;
	ioctl.smb2.in.file.handle.data[0] = 0xffffffffffffffffLL;
	ioctl.smb2.in.file.handle.data[1] = 0xffffffffffffffffLL;
	ioctl.smb2.in.function = FSCTL_DFS_GET_REFERRALS;
	ioctl.smb2.in.max_response_size = sizeof (buf);
	ioctl.smb2.in.flags = SMB2_IOCTL_FLAG_IS_FSCTL;

	// See: ndr_push_dfs_GetDFSReferral
	// ndr_push_dfs_GetDFSReferral_in
	// ndr_pull_dfs_referral_resp

	ndr_err = ndr_push_struct_blob(&ioctl.smb2.in.out, tree,
			&ref->in.req,
			(ndr_push_flags_fn_t)ndr_push_dfs_GetDFSReferral_in);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	status = smb2_ioctl(tree, tmp_ctx, &ioctl.smb2);

	if (!NT_STATUS_IS_OK(status))
		return status;

	ndr_err = ndr_pull_struct_blob(&ioctl.smb2.out.out, tree,
			ref->out.resp,
			(ndr_pull_flags_fn_t)ndr_pull_dfs_referral_resp);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return NT_STATUS_INVALID_NETWORK_RESPONSE;
	}

	return NT_STATUS_OK;
}

static bool test_get_root_referral(struct torture_context *tctx,
			       struct smb2_tree *tree)
{
	struct dfs_GetDFSReferral r;
	struct dfs_referral_resp resp;
	char *unc;

	/* XXX: Until I figure out how to use a cli option... */
	unc = getenv("UNC");
	if (unc == NULL)
		unc = "\\localhost\\test";

	ZERO_STRUCT(r);
	r.in.req.max_referral_level = 4;
	r.in.req.servername = unc;
	r.out.resp = &resp;

	torture_assert_ntstatus_ok(tctx,
		   smb2_dfs_cli_call(tree, &r),
		   "Get Domain referral failed");

	torture_assert_int_equal(tctx, resp.path_consumed, 0,
				 "Path consumed not equal to 0");
	torture_assert_int_equal(tctx, resp.nb_referrals != 0, 1,
				 "0 domains referrals returned");
	torture_assert_int_equal(tctx, resp.header_flags, 0,
				 "Header flag different it's not a referral server");
	torture_assert_int_equal(tctx, resp.referral_entries[1].version, 3,
				 talloc_asprintf(tctx,
					"Not expected version for referral entry 1 got %d expected 3",
					resp.referral_entries[1].version));
	torture_assert_int_equal(tctx, resp.referral_entries[0].version, 3,
				 talloc_asprintf(tctx,
					"Not expected version for referral entry 0 got %d expected 3",
					resp.referral_entries[0].version));
	torture_assert_int_equal(tctx, resp.referral_entries[0].referral.v3.server_type,
				 DFS_SERVER_NON_ROOT,
				 talloc_asprintf(tctx,
					"Wrong server type, expected non root server and got %d",
					resp.referral_entries[0].referral.v3.server_type));
	torture_assert_int_equal(tctx, resp.referral_entries[0].referral.v3.entry_flags,
				 DFS_FLAG_REFERRAL_DOMAIN_RESP,
				 talloc_asprintf(tctx,
					"Wrong entry flag expected to have a domain response and got %d",
					resp.referral_entries[0].referral.v3.entry_flags));
	torture_assert_int_equal(tctx, strlen(
				 resp.referral_entries[0].referral.v3.referrals.r2.special_name) > 0,
				 1,
				 "Length of domain is 0 or less");
	torture_assert_int_equal(tctx,
				 resp.referral_entries[0].referral.v3.referrals.r2.special_name[0] == '\\',
				 1,
				 "domain didn't start with a \\");
	return true;
}

static NTSTATUS
smb2_dfs_cli_call_ex(struct smb2_tree *tree, struct dfs_GetDFSReferralEx *ref)
{
	uint8_t buf[1024];
	NTSTATUS status;
	enum ndr_err_code ndr_err;
	union smb_ioctl ioctl;
	TALLOC_CTX *tmp_ctx = talloc_new(tree);

	ZERO_ARRAY(buf);

	ZERO_STRUCT(ioctl);
	ioctl.smb2.level = RAW_IOCTL_SMB2;
	ioctl.smb2.in.file.handle.data[0] = 0xffffffffffffffffLL;
	ioctl.smb2.in.file.handle.data[1] = 0xffffffffffffffffLL;
	ioctl.smb2.in.function = FSCTL_DFS_GET_REFERRALS_EX;
	ioctl.smb2.in.max_response_size = sizeof (buf);
	ioctl.smb2.in.flags = SMB2_IOCTL_FLAG_IS_FSCTL;

	// See: ndr_push_dfs_GetDFSReferralEx
	// ndr_push_dfs_GetDFSReferralEx_in
	// ndr_pull_dfs_referral_resp

	ndr_err = ndr_push_struct_blob(&ioctl.smb2.in.out, tree,
			&ref->in.req,
			(ndr_push_flags_fn_t)ndr_push_dfs_GetDFSReferralEx_in);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	status = smb2_ioctl(tree, tmp_ctx, &ioctl.smb2);

	if (!NT_STATUS_IS_OK(status))
		return status;

	ndr_err = ndr_pull_struct_blob(&ioctl.smb2.out.out, tree,
			ref->out.resp,
			(ndr_pull_flags_fn_t)ndr_pull_dfs_referral_resp);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return NT_STATUS_INVALID_NETWORK_RESPONSE;
	}

	return NT_STATUS_OK;
}

static bool test_get_root_referral_ex(struct torture_context *tctx,
			       struct smb2_tree *tree)
{
	struct dfs_GetDFSReferralEx r;
	struct dfs_referral_resp resp;
	char *unc;

	/* XXX: Until I figure out how to use a cli option... */
	unc = getenv("UNC");
	if (unc == NULL)
		unc = "\\localhost\\test";

	ZERO_STRUCT(r);
	r.in.req.max_referral_level = 4;
	r.in.req.strings.file.string = unc;
	r.out.resp = &resp;

	torture_assert_ntstatus_ok(tctx,
		   smb2_dfs_cli_call_ex(tree, &r),
		   "Get Domain referral failed");

	torture_assert_int_equal(tctx, resp.path_consumed, 0,
				 "Path consumed not equal to 0");
	torture_assert_int_equal(tctx, resp.nb_referrals != 0, 1,
				 "0 domains referrals returned");
	torture_assert_int_equal(tctx, resp.header_flags, 0,
				 "Header flag different it's not a referral server");
	torture_assert_int_equal(tctx, resp.referral_entries[1].version, 3,
				 talloc_asprintf(tctx,
					"Not expected version for referral entry 1 got %d expected 3",
					resp.referral_entries[1].version));
	torture_assert_int_equal(tctx, resp.referral_entries[0].version, 3,
				 talloc_asprintf(tctx,
					"Not expected version for referral entry 0 got %d expected 3",
					resp.referral_entries[0].version));
	torture_assert_int_equal(tctx, resp.referral_entries[0].referral.v3.server_type,
				 DFS_SERVER_NON_ROOT,
				 talloc_asprintf(tctx,
					"Wrong server type, expected non root server and got %d",
					resp.referral_entries[0].referral.v3.server_type));
	torture_assert_int_equal(tctx, resp.referral_entries[0].referral.v3.entry_flags,
				 DFS_FLAG_REFERRAL_DOMAIN_RESP,
				 talloc_asprintf(tctx,
					"Wrong entry flag expected to have a domain response and got %d",
					resp.referral_entries[0].referral.v3.entry_flags));
	torture_assert_int_equal(tctx, strlen(
				 resp.referral_entries[0].referral.v3.referrals.r2.special_name) > 0,
				 1,
				 "Length of domain is 0 or less");
	torture_assert_int_equal(tctx,
				 resp.referral_entries[0].referral.v3.referrals.r2.special_name[0] == '\\',
				 1,
				 "domain didn't start with a \\");
	return true;
}



/*
 * testing of SMB2 DFS
 */
struct torture_suite *torture_smb2_dfs_init(TALLOC_CTX *ctx)
{
	struct torture_suite *suite = torture_suite_create(ctx, "dfs");

	torture_suite_add_1smb2_test(suite, "get_root_referral",
				     test_get_root_referral);
	torture_suite_add_1smb2_test(suite, "get_root_referral_ex",
				     test_get_root_referral_ex);

	suite->description = talloc_strdup(suite, "SMB2-DFS tests");

	return suite;
}
