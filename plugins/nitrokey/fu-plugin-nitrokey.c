/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*-
 *
 * Copyright (C) 2017 Richard Hughes <richard@hughsie.com>
 *
 * Licensed under the GNU General Public License Version 2
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <appstream-glib.h>
#include <string.h>

#include "fu-plugin.h"
#include "fu-plugin-vfuncs.h"

#define NITROKEY_TRANSACTION_TIMEOUT		1000 /* ms */

#define GET_DEVICE_STATUS			(0x20 + 14)

typedef struct __attribute__((packed)) {
	guint8		command;
	guint8		payload[59];
	guint32		crc;
} NitrokeyHidRequest;

typedef struct __attribute__((packed)) {
	guint8		_padding; /* always zero */
	guint8		device_status;
	guint32		last_command_crc;
	guint8		last_command_status;
	guint8		payload[53];
	guint32		crc;
} NitrokeyHidResponse;

/* based from libnitrokey/stick20_commands.h */
typedef struct __attribute__((packed)) {
	guint8		_padding[24];
	guint8		SendCounter;
	guint8		SendDataType;
	guint8		FollowBytesFlag;
	guint8		SendSize;
	guint16		MagicNumber_StickConfig;
	guint8		ReadWriteFlagUncryptedVolume;
	guint8		ReadWriteFlagCryptedVolume;
	guint8		VersionReserved1;
	guint8		VersionMinor;
	guint8		VersionReserved2;
	guint8		VersionMajor;
	guint8		ReadWriteFlagHiddenVolume;
	guint8		FirmwareLocked;
	guint8		NewSDCardFound;
	guint8		SDFillWithRandomChars;
	guint32		ActiveSD_CardID;
	guint8		VolumeActiceFlag;
	guint8		NewSmartCardFound;
	guint8		UserPwRetryCount;
	guint8		AdminPwRetryCount;
	guint32		ActiveSmartCardID;
	guint8		StickKeysNotInitiated;
} NitrokeyGetDeviceStatusPayload;

static guint32
_stm_crc32_mutate (guint32 crc, guint32 data)
{
	crc = crc ^ data;
	for (guint i = 0; i < 32; i++) {
		if (crc & 0x80000000) {
			/* polynomial used in STM32 */
			crc = (crc << 1) ^ 0x04C11DB7;
		} else {
			crc = (crc << 1);
		}
	}
	return crc;
}

static guint32
_stm_crc32 (const guint8 *data, gsize size)
{
	guint32 crc = 0xffffffff;
	const guint32 *pend = (const guint32 *) (data + size);
	for (const guint32 *p = (const guint32 *) data; p < pend; p++)
		crc = _stm_crc32_mutate (crc, *p);
	return crc;
}

static void
_dump_to_console (const gchar *title, const guint8 *buf, gsize buf_sz)
{
	g_debug ("%s", title);
	for (guint i = 0; i < 64; i++)
		g_debug ("%u=0x%02x", i, buf[i]);
}

static gboolean
nitrokey_execute_cmd (GUsbDevice *usb_device, guint8 command,
		      const guint8 *buf_in, gsize buf_in_sz,
		      guint8 *buf_out, gsize buf_out_sz,
		      GError **error)
{
	NitrokeyHidRequest req;
	NitrokeyHidResponse res;
	gboolean ret;
	gsize actual_len = 0;
	guint32 crc_tmp;

	g_return_val_if_fail (buf_in_sz <= 59, FALSE);
	g_return_val_if_fail (buf_out_sz <= 54, FALSE);

	memset (&req, 0x00, sizeof(req));
	req.command = command;
	crc_tmp = _stm_crc32 ((const guint8 *) &req, sizeof(req) - 4);
	req.crc = GUINT32_TO_LE (crc_tmp);
	if (buf_in != NULL)
		memcpy (&req.payload, buf_in, buf_in_sz);

	/* send request */
	_dump_to_console ("request", (const guint8 *) &req, sizeof(req));
	ret = g_usb_device_control_transfer (usb_device,
					     G_USB_DEVICE_DIRECTION_HOST_TO_DEVICE,
					     G_USB_DEVICE_REQUEST_TYPE_CLASS,
					     G_USB_DEVICE_RECIPIENT_INTERFACE,
					     0x09,
					     0x0300,
					     0x0002,
					     (const guint8 *) &req,
					     sizeof(req),
					     &actual_len,
					     NITROKEY_TRANSACTION_TIMEOUT,
					     NULL,
					     error);
	if (!ret) {
		g_prefix_error (error, "failed to do HOST_TO_DEVICE: ");
		return FALSE;
	}
	if (actual_len != sizeof(req)) {
		g_set_error (error,
			     G_IO_ERROR,
			     G_IO_ERROR_FAILED,
			     "only wrote %" G_GSIZE_FORMAT "bytes", actual_len);
		return FALSE;
	}

	/* get response */
	memset (&res, 0x00, sizeof(res));
	ret = g_usb_device_control_transfer (usb_device,
					     G_USB_DEVICE_DIRECTION_DEVICE_TO_HOST,
					     G_USB_DEVICE_REQUEST_TYPE_CLASS,
					     G_USB_DEVICE_RECIPIENT_INTERFACE,
					     0x01,
					     0x0300,
					     0x0002,
					     (const guint8 *) &res,
					     sizeof(res),
					     &actual_len,
					     NITROKEY_TRANSACTION_TIMEOUT,
					     NULL,
					     error);
	if (!ret) {
		g_prefix_error (error, "failed to do DEVICE_TO_HOST: ");
		return FALSE;
	}
	if (actual_len != sizeof(res)) {
		g_set_error (error,
			     G_IO_ERROR,
			     G_IO_ERROR_FAILED,
			     "only wrote %" G_GSIZE_FORMAT "bytes", actual_len);
		return FALSE;
	}
	_dump_to_console ("response", (const guint8 *) &res, sizeof(res));

	/* verify this is the answer to the question we asked */
	if (GUINT32_FROM_LE (res.last_command_crc) != crc_tmp) {
		g_set_error (error,
			     G_IO_ERROR,
			     G_IO_ERROR_FAILED,
			     "got response CRC %x, expected %x",
			     GUINT32_FROM_LE (res.last_command_crc), crc_tmp);
		return FALSE;
	}

	/* verify the response checksum */
	crc_tmp = _stm_crc32 ((const guint8 *) &res, sizeof(res) - 4);
	if (GUINT32_FROM_LE (res.crc) != crc_tmp) {
		g_set_error (error,
			     G_IO_ERROR,
			     G_IO_ERROR_FAILED,
			     "got packet CRC %x, expected %x",
			     GUINT32_FROM_LE (res.crc), crc_tmp);
		return FALSE;
	}

	/* copy out the payload */
	if (buf_out != NULL)
		memcpy (buf_out, &res.payload, buf_out_sz);

	/* success */
	return TRUE;
}

static void
fu_plugin_nitrokey_device_added_cb (GUsbContext *ctx,
				    GUsbDevice *usb_device,
				    FuPlugin *plugin)
{
	NitrokeyGetDeviceStatusPayload payload;
	const gchar *platform_id = NULL;
	g_autofree gchar *devid1 = NULL;
	g_autofree gchar *version = NULL;
	g_autoptr(AsProfile) profile = as_profile_new ();
	g_autoptr(AsProfileTask) ptask = NULL;
	g_autoptr(FuDevice) dev = NULL;
	g_autoptr(FuDeviceLocker) locker = NULL;
	g_autoptr(GError) error_local = NULL;

	/* not the right kind of device */
	if (g_usb_device_get_vid (usb_device) != 0x20a0)
		return;
	if (g_usb_device_get_pid (usb_device) != 0x4109)
		return;

	/* profile */
	ptask = as_profile_start (profile, "FuPluginNitrokey:added{%04x:%04x}",
				  g_usb_device_get_vid (usb_device),
				  g_usb_device_get_pid (usb_device));
	g_assert (ptask != NULL);

	/* is already in database */
	platform_id = g_usb_device_get_platform_id (usb_device);
	dev = fu_plugin_cache_lookup (plugin, platform_id);
	if (dev != NULL) {
		g_debug ("ignoring duplicate %s", platform_id);
		return;
	}

	/* get exclusive access */
	locker = fu_device_locker_new (usb_device, &error_local);
	if (locker == NULL) {
		g_warning ("failed to open device: %s", error_local->message);
		return;
	}
	if (!g_usb_device_claim_interface (usb_device, 0x02,
					   G_USB_DEVICE_CLAIM_INTERFACE_BIND_KERNEL_DRIVER,
					   &error_local)) {
		g_warning ("failed to claim interface: %s", error_local->message);
		return;
	}

	/* get firmware version */
	if (!nitrokey_execute_cmd (usb_device, GET_DEVICE_STATUS,
				   NULL, 0,
				   (const guint8 *) &payload, sizeof(payload),
				   &error_local)) {
		g_warning ("failed to do get firmware version: %s",
			   error_local->message);
		return;
	}
	_dump_to_console ("payload", (const guint8 *) &payload, sizeof(payload));

	/* insert to hash if valid */
	dev = fu_device_new ();
	fu_device_set_id (dev, platform_id);
	fu_device_set_name (dev, "Nitrokey Storage");
	fu_device_set_vendor (dev, "Nitrokey");
	fu_device_set_summary (dev, "A secure memory stick");
	fu_device_add_icon (dev, "media-removable");
	version = g_strdup_printf ("%u.%u", payload.VersionMinor, payload.VersionMajor);
	fu_device_set_version (dev, version);

	/* use the USB VID:PID hash */
	devid1 = g_strdup_printf ("USB\\VID_%04X&PID_%04X",
				  g_usb_device_get_vid (usb_device),
				  g_usb_device_get_pid (usb_device));
	fu_device_add_guid (dev, devid1);

	/* we're done here */
	if (!g_usb_device_release_interface (usb_device, 0x02,
					     G_USB_DEVICE_CLAIM_INTERFACE_BIND_KERNEL_DRIVER,
					     &error_local)) {
		g_warning ("failed to release interface: %s", error_local->message);
		return;
	}
	fu_plugin_device_add (plugin, dev);
	fu_plugin_cache_add (plugin, platform_id, dev);
}

static void
fu_plugin_nitrokey_device_removed_cb (GUsbContext *ctx,
				      GUsbDevice *device,
				      FuPlugin *plugin)
{
	FuDevice *dev;
	const gchar *platform_id = NULL;

	/* already in database */
	platform_id = g_usb_device_get_platform_id (device);
	dev = fu_plugin_cache_lookup (plugin, platform_id);
	if (dev == NULL)
		return;

	fu_plugin_device_remove (plugin, dev);
	fu_plugin_cache_remove (plugin, platform_id);
}

gboolean
fu_plugin_startup (FuPlugin *plugin, GError **error)
{
	GUsbContext *usb_ctx = fu_plugin_get_usb_context (plugin);
	g_signal_connect (usb_ctx, "device-added",
			  G_CALLBACK (fu_plugin_nitrokey_device_added_cb),
			  plugin);
	g_signal_connect (usb_ctx, "device-removed",
			  G_CALLBACK (fu_plugin_nitrokey_device_removed_cb),
			  plugin);
	return TRUE;
}
