/*
 * Copyright © 2023 GNOME Foundation, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library. If not, see <http://www.gnu.org/licenses/>.
 *
 * Authors:
 *       Georges Basile Stavracas Neto <georges.stavracas@gmail.com>
 */

#pragma once

#include <gio/gio.h>

G_BEGIN_DECLS

#define XDP_TYPE_DEVICES_FILTER (xdp_devices_filter_get_type())
G_DECLARE_FINAL_TYPE (XdpDevicesFilter, xdp_devices_filter, XDP, DEVICES_FILTER, GObject)

XdpDevicesFilter *xdp_devices_filter_new (GFile   *file,
                                          GError **error);

GPtrArray *xdp_devices_filter_get_all_for_app_id (const char *app_id);

gboolean xdp_devices_filter_match_device (XdpDevicesFilter *self,
                                          gpointer          gudev_device);

char * xdp_devices_filter_to_string (XdpDevicesFilter *self);

G_END_DECLS
