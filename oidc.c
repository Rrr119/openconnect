/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2008-2015 Microsoft Corp
 *
 * Author: Alan Jowett <alan.jowett@microsoft.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * version 2.1, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 */

#include <config.h>

#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "openconnect-internal.h"

/* Strip leading and trailing ASCII whitespace in place by advancing the
   start pointer and NUL-terminating the end. Returns a pointer into the
   original buffer, or NULL if the result is the empty string. */
static char *oidc_trim(char *str)
{
	char *end;

	if (!str)
		return NULL;

	while (*str && isspace((int)(unsigned char)*str))
		str++;

	if (!*str)
		return NULL;

	end = str + strlen(str);
	while (end > str && isspace((int)(unsigned char)end[-1]))
		end--;
	*end = 0;

	return str;
}

int set_oidc_token(struct openconnect_info *vpninfo, const char *token_str)
{
	int ret;
	char *file_token = NULL;
	char *token = NULL;

	if (!token_str) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("No OIDC bearer token was provided\n"));
		return -ENOENT;
	}

	/* Replace any token configured by an earlier call instead of leaking it. */
	free(vpninfo->bearer_token);
	vpninfo->bearer_token = NULL;

	if (token_str[0] == '@' || token_str[0] == '/') {
		const char *fname = token_str;

		if (token_str[0] == '@')
			fname = token_str + 1;

		ret = openconnect_read_file(vpninfo, fname, &file_token);
		if (ret < 0) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to read OIDC token from file '%s'\n"),
				     fname);
			return ret;
		}
		token = oidc_trim(file_token);
		if (!token) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("OIDC token file '%s' is empty or contains only whitespace\n"),
				     fname);
			free(file_token);
			return -EINVAL;
		}
		vpninfo->bearer_token = strdup(token);
		free(file_token);
	} else {
		char *copy = strdup(token_str);

		if (!copy) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to allocate memory for OIDC token\n"));
			return -ENOMEM;
		}
		token = oidc_trim(copy);
		if (!token) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("The provided OIDC bearer token is empty\n"));
			free(copy);
			return -EINVAL;
		}
		vpninfo->bearer_token = strdup(token);
		free(copy);
	}

	if (!vpninfo->bearer_token) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to allocate memory for OIDC token\n"));
		return -ENOMEM;
	}

	vpninfo->token_mode = OC_TOKEN_MODE_OIDC;
	vpn_progress(vpninfo, PRG_INFO,
		     _("Loaded OIDC bearer token (%d bytes) for HTTP Bearer authentication\n"),
		     (int)strlen(vpninfo->bearer_token));
	return 0;
}


