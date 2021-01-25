/*
 * Copyright © 2023 GNOME Foundation Inc.
 *             2020 Endless OS Foundation LLC
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
 *       Ryan Gonzalez <rymg19+github@gmail.com>
 */

#include "config.h"

#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <glib-unix.h>
#include <glib/gi18n.h>
#include <gio/gio.h>
#include <gio/gunixfdlist.h>
#include <gio/gdesktopappinfo.h>

#include <gudev/gudev.h>

#include "usb.h"
#include "request.h"
#include "permissions.h"
#include "session.h"
#include "xdp-dbus.h"
#include "xdp-impl-dbus.h"
#include "xdp-utils.h"

#define PERMISSION_TABLE "usb"
#define PERMISSION_ID "usb"

#define UDEV_PROPERTY_INPUT_JOYSTICK "ID_INPUT_JOYSTICK"
#define UDEV_PROPERTY_PRODUCT_ID "ID_MODEL_ID"
#define UDEV_PROPERTY_PRODUCT_NAME "ID_MODEL_ENC"
#define UDEV_PROPERTY_SERIAL "ID_SERIAL"
#define UDEV_PROPERTY_SERIAL_SHORT "ID_SERIAL_SHORT"
#define UDEV_PROPERTY_TYPE "ID_TYPE"
#define UDEV_PROPERTY_VENDOR_ID "ID_VENDOR_ID"
#define UDEV_PROPERTY_VENDOR_NAME "ID_VENDOR_ENC"

/*
 * TODO:
 *
 * General
 *  - Extend to other device types?
 *
 * Permission
 *  - Monitor permission store for permission changes
 *
 * AccessDevices()
 *  - Check if backend is returning appropriate device ids
 *  - Check if backend is not increasing permissions
 *  - Rename to AcquireDevices()
 *  - Save allowed devices in the permission store
 *
 * ReleaseDevices()
 *  - Implement
 */

typedef struct _Usb
{
  XdpDbusUsbSkeleton parent_instance;

  GHashTable *ids_to_devices;
  GHashTable *syspaths_to_ids;
  GHashTable *sessions;

  GUdevClient *gudev_client;
} Usb;

typedef struct _UsbClass
{
  XdpDbusUsbSkeletonClass parent_class;
} UsbClass;

static XdpDbusImplUsb *usb_impl;
static Usb *usb;

GType usb_get_type (void) G_GNUC_CONST;
static void usb_iface_init (XdpDbusUsbIface *iface);

G_DEFINE_TYPE_WITH_CODE (Usb, usb, XDP_DBUS_TYPE_USB_SKELETON,
                         G_IMPLEMENT_INTERFACE (XDP_DBUS_TYPE_USB, usb_iface_init));

static gboolean
hex_to_uint16 (const char *property,
               uint16_t   *out_n)
{
  long n;

  g_assert (property != NULL);
  g_assert (out_n != NULL);

  n = strtol (property, NULL, 16);

  if (n < 0 || n > UINT16_MAX)
    return FALSE;

  *out_n = (uint16_t) n;
  return TRUE;
}


/* UsbDeviceCandidate */

typedef struct
{
  uint16_t vendor_id;
  uint16_t product_id;
} UsbDeviceCandidate;

static void
usb_device_candidate_free (gpointer data)
{
  UsbDeviceCandidate *candidate = (UsbDeviceCandidate *) data;

  if (!data)
    return;

  g_clear_pointer (&candidate, g_free);
}

G_DEFINE_AUTOPTR_CLEANUP_FUNC (UsbDeviceCandidate, usb_device_candidate_free)

static GPtrArray *
usb_device_candidates_from_variant (GVariant *variant)
{
  g_autoptr(GPtrArray) candidates = NULL;
  GVariantIter iter;
  GVariant *device;
  size_t n_candidates;

  g_assert (variant != NULL);
  g_assert (g_variant_check_format_string (variant, "aa{sv}", FALSE));

  g_variant_iter_init (&iter, variant);

  n_candidates = g_variant_iter_n_children (&iter);
  g_assert (n_candidates > 0);

  g_message ("%lu candidate(s):", n_candidates);

  candidates = g_ptr_array_new_full (n_candidates, usb_device_candidate_free);

  while ((device = g_variant_iter_next_value (&iter)) != NULL)
    {
      g_autoptr(UsbDeviceCandidate) candidate = NULL;

      g_assert (g_variant_check_format_string (device, "a{sv}", TRUE));

      candidate = g_new0 (UsbDeviceCandidate, 1);
      g_variant_lookup (device, "vendor_id", "q", &candidate->vendor_id);
      g_variant_lookup (device, "product_id", "q", &candidate->product_id);

      g_message ("    product: %u, vendor: %u", (uint32_t) candidate->product_id, (uint32_t) candidate->vendor_id);

      g_ptr_array_add (candidates, g_steal_pointer (&candidate));

      g_clear_pointer (&device, g_variant_unref);
    }

  return g_steal_pointer (&candidates);
}

static GVariant *
usb_device_candidates_to_variant (GPtrArray *candidates)
{
  GVariantBuilder builder;

  g_assert (candidates != NULL);

  g_variant_builder_init (&builder, G_VARIANT_TYPE ("aa{sv}"));

  for (size_t i = 0; i < candidates->len; i++)
    {
      UsbDeviceCandidate *candidate = g_ptr_array_index (candidates, i);

      g_assert (candidate != NULL);

      g_variant_builder_open (&builder, G_VARIANT_TYPE ("a{sv}"));
      g_variant_builder_add (&builder, "{sv}", "vendor_id", g_variant_new_uint16 (candidate->vendor_id));
      g_variant_builder_add (&builder, "{sv}", "product_id", g_variant_new_uint16 (candidate->product_id));
      g_variant_builder_close (&builder);
    }

  return g_variant_builder_end (&builder);
}

static GPtrArray *
get_usb_device_candidates_from_options (GVariantDict *options)
{
  g_autoptr(GVariantIter) devices_variant_iter = NULL;
  g_autoptr(GPtrArray) candidates = NULL;
  GVariant *device;
  size_t n_devices;

  if (!g_variant_dict_lookup (options, "devices", "aa{sv}", &devices_variant_iter))
    return NULL;

  n_devices = g_variant_iter_n_children (devices_variant_iter);
  g_assert (n_devices > 0);

  candidates = g_ptr_array_new_full (n_devices, usb_device_candidate_free);

  while ((device = g_variant_iter_next_value (devices_variant_iter)) != NULL)
    {
      g_autoptr(UsbDeviceCandidate) usb_device = NULL;
      g_auto(GVariantDict) dict;

      g_assert (g_variant_check_format_string (device, "a{sv}", TRUE));

      g_variant_dict_init (&dict, device);
      g_assert (g_variant_dict_contains (&dict, "vendor_id"));
      g_assert (g_variant_dict_contains (&dict, "product_id"));

      usb_device = g_new0 (UsbDeviceCandidate, 1);
      g_variant_dict_lookup (&dict, "vendor_id", "q", &usb_device->vendor_id);
      g_variant_dict_lookup (&dict, "product_id", "q", &usb_device->product_id);

      g_ptr_array_add (candidates, g_steal_pointer (&usb_device));

      g_clear_pointer (&device, g_variant_unref);
    }

  return g_steal_pointer (&candidates);
}


/* UsbAccessMode */

typedef enum
{
  USB_ACCESS_MODE_LISTED_DEVICES,
  USB_ACCESS_MODE_ALL,
} UsbAccessMode;

static const char * const usb_access_mode_string_map[] = {
  [USB_ACCESS_MODE_LISTED_DEVICES] = "listed-devices",
  [USB_ACCESS_MODE_ALL] = "all",
};

static gboolean
str_to_access_mode (const char    *permission,
                    UsbAccessMode *out_access_mode)
{
  for (size_t i = 0; i < G_N_ELEMENTS (usb_access_mode_string_map); i++)
    {
      if (g_strcmp0 (permission, usb_access_mode_string_map[i]) == 0)
        {
          if (out_access_mode)
            *out_access_mode = (UsbAccessMode) i;
          return TRUE;
        }
    }

  return FALSE;
}

const char *
access_mode_to_str (UsbAccessMode access_mode)
{
  g_assert (access_mode >= USB_ACCESS_MODE_LISTED_DEVICES);
  g_assert (access_mode <= USB_ACCESS_MODE_ALL);

  return usb_access_mode_string_map[access_mode];
}


/* UsbPermission */

typedef struct
{
  Permission permission;
  UsbAccessMode access_mode;
  GPtrArray *candidates;
} UsbPermission;

static void
usb_permission_free (gpointer data)
{
  UsbPermission *usb_permission = (UsbPermission *) data;

  if (!data)
    return;

  g_clear_pointer (&usb_permission->candidates, g_ptr_array_unref);
  g_clear_pointer (&usb_permission, g_free);
}

G_DEFINE_AUTOPTR_CLEANUP_FUNC (UsbPermission, usb_permission_free)

static UsbPermission *
strv_to_usb_permission (char **permissions)
{
  g_autoptr(UsbPermission) usb_permission = NULL;
  g_autoptr(GVariant) candidates = NULL;
  g_autoptr(GVariant) data = NULL;
  UsbAccessMode access_mode;
  Permission permission;

  if (g_strv_length ((char **)permissions) != 3 ||
      !str_to_permission (permissions[0], &permission) ||
      !str_to_access_mode (permissions[1], &access_mode) ||
      (data = g_variant_parse (G_VARIANT_TYPE_VARDICT, permissions[2], NULL, NULL, NULL)) == NULL)
    {
      g_autofree char *a = g_strjoinv (" ", (char **)permissions);
      g_warning ("Wrong USB permission format, ignoring (%s)", a);
      return FALSE;
    }

  usb_permission = g_new (UsbPermission, 1);
  usb_permission->permission = permission;
  usb_permission->access_mode = access_mode;

  g_message ("Stored data: %s", g_variant_print (data, TRUE));

  if (g_variant_lookup (data, "candidates", "@aa{sv}", &candidates))
    usb_permission->candidates = usb_device_candidates_from_variant (candidates);

  /* TODO: allowed devices */

  return g_steal_pointer (&usb_permission);
}

static UsbPermission *
get_usb_permission_sync (const char *app_id)
{
  g_auto(GStrv) permissions = NULL;

  permissions = get_permissions_sync (app_id, PERMISSION_TABLE, PERMISSION_ID);
  if (!permissions)
    return NULL;

  return strv_to_usb_permission (permissions);
}

static void
set_usb_permission_sync (const char    *app_id,
                         UsbPermission *usb_permission)
{
  g_autoptr(GPtrArray) strv = NULL;
  g_autoptr(GVariant) candidates_variant = NULL;
  g_autoptr(GVariant) data = NULL;
  GVariantDict data_dict;

  candidates_variant = usb_device_candidates_to_variant (usb_permission->candidates);
  g_assert (candidates_variant != NULL);

  g_variant_dict_init (&data_dict, NULL);
  g_variant_dict_insert (&data_dict, "candidates", "@aa{sv}", g_steal_pointer (&candidates_variant));
  data = g_variant_dict_end (&data_dict);
  g_assert (data != NULL);

  strv = g_ptr_array_new_full (4, g_free);
  g_ptr_array_add (strv, g_strdup (permissions_to_str (usb_permission->permission)));
  g_ptr_array_add (strv, g_strdup (access_mode_to_str (usb_permission->access_mode)));
  g_ptr_array_add (strv, g_variant_print (data, TRUE));
  g_ptr_array_add (strv, NULL);

  set_permissions_sync (app_id,
                        PERMISSION_TABLE,
                        PERMISSION_ID,
                        (const char * const *) strv->pdata);
}

static UsbPermission *
usb_permission_new (Permission     permission,
                    UsbAccessMode  access_mode,
                    GPtrArray     *candidates)
{
  g_autoptr(UsbPermission) usb_permission = NULL;

  g_assert (access_mode != USB_ACCESS_MODE_LISTED_DEVICES || candidates != NULL);

  usb_permission = g_new (UsbPermission, 1);
  usb_permission->permission = permission;
  usb_permission->access_mode = access_mode;
  usb_permission->candidates = g_ptr_array_ref (candidates);

  return g_steal_pointer (&usb_permission);
}


/* UsbDeviceAccessData */

typedef struct
{
  char *device_id;
  gboolean writable;
} UsbDeviceAccessData;

static void
usb_device_access_data_free (gpointer data)
{
  UsbDeviceAccessData *access_data = (UsbDeviceAccessData *) data;

  if (!access_data)
    return;

  g_clear_pointer (&access_data->device_id, g_free);
  g_clear_pointer (&access_data, g_free);
}

G_DEFINE_AUTOPTR_CLEANUP_FUNC (UsbDeviceAccessData, usb_device_access_data_free)


/* UsbSession */

typedef enum
{
  USB_SESSION_STATE_DEFAULT,
  USB_SESSION_STATE_ACCESSING_DEVICES,
} UsbSessionState;

typedef struct _UsbSession
{
  Session parent;

  gboolean has_all_devices;
  GHashTable *available_devices;

  UsbAccessMode access_mode;
  GPtrArray *device_candidates;

  UsbSessionState session_state;
  GPtrArray *accessing_devices;
} UsbSession;

typedef struct _UsbSessionClass
{
  SessionClass parent_class;
} UsbSessionClass;

GType usb_session_get_type (void);

G_DEFINE_TYPE (UsbSession, usb_session, session_get_type ())

static void
usb_session_init (UsbSession *session)
{
}

static void
usb_session_close (Session *session)
{
  g_debug ("USB session '%s' closed", session->id);

  g_assert (g_hash_table_contains (usb->sessions, session));
  g_hash_table_remove (usb->sessions, session);
}

static void
usb_session_dispose (GObject *object)
{
  UsbSession *usb_session = (UsbSession *) object;

  g_clear_pointer (&usb_session->device_candidates, g_ptr_array_unref);
  g_clear_pointer (&usb_session->available_devices, g_hash_table_destroy);
}

static void
usb_session_class_init (UsbSessionClass *klass)
{
  GObjectClass *object_class = (GObjectClass *) klass;
  SessionClass *session_class = (SessionClass *) klass;

  object_class->dispose = usb_session_dispose;

  session_class->close = usb_session_close;
}

static UsbAccessMode
get_access_mode_from_options (GVariantDict *options)
{
  UsbAccessMode access_mode;
  const char *string = NULL;

  g_assert (g_variant_dict_contains (options, "access_mode"));
  g_variant_dict_lookup (options, "access_mode", "&s", &string);

  if (!str_to_access_mode (string, &access_mode))
    g_assert_not_reached ();

  return access_mode;
}

static UsbSession *
usb_session_new (GDBusConnection  *connection,
                 Request          *request,
                 GVariant         *options,
                 GError          **error)
{
  GVariantDict options_dict;
  UsbSession *usb_session;
  Session *session = NULL;

  session = g_initable_new (usb_session_get_type (),
                            NULL, error,
                            "connection", connection,
                            "sender", request->sender,
                            "app-id", xdp_app_info_get_id (request->app_info),
                            "token", lookup_session_token (options),
                            NULL);
  if (!session)
    return NULL;

  g_variant_dict_init (&options_dict, options);

  usb_session = (UsbSession *) session;
  usb_session->access_mode = get_access_mode_from_options (&options_dict);
  usb_session->has_all_devices = xdp_app_info_has_all_devices (request->app_info);
  usb_session->device_candidates = get_usb_device_candidates_from_options (&options_dict);
  usb_session->available_devices = g_hash_table_new_full (g_str_hash, g_str_equal,
                                                          g_free, NULL);
  usb_session->session_state = USB_SESSION_STATE_DEFAULT;

  g_variant_dict_clear (&options_dict);

  g_debug ("[usb] USB session '%s' created", session->id);

  return (UsbSession *)session;
}

static gboolean
usb_session_match_device (UsbSession  *usb_session,
                          GUdevDevice *device)
{
  const char *product_id_str = NULL;
  const char *vendor_id_str = NULL;
  uint16_t product_id;
  uint16_t vendor_id;

  g_assert (usb_session != NULL);
  g_assert (G_UDEV_IS_DEVICE (device));

  if (usb_session->has_all_devices || usb_session->access_mode == USB_ACCESS_MODE_ALL)
    return TRUE;

  vendor_id_str = g_udev_device_get_property (device, UDEV_PROPERTY_VENDOR_ID);
  if (vendor_id_str == NULL || !hex_to_uint16 (vendor_id_str, &vendor_id))
    return FALSE;

  product_id_str = g_udev_device_get_property (device, UDEV_PROPERTY_PRODUCT_ID);
  if (product_id_str == NULL || !hex_to_uint16 (product_id_str, &product_id))
    return FALSE;

  for (unsigned int i = 0; i < usb_session->device_candidates->len; i++)
    {
      UsbDeviceCandidate *usb_device = g_ptr_array_index (usb_session->device_candidates, i);

      if (vendor_id == usb_device->vendor_id &&
          product_id == usb_device->product_id)
        return TRUE;
    }

  return FALSE;
}

#if 0

static const char *
get_device_permissions_key (GUdevDevice *device)
{
  const char *serial = g_udev_device_get_property (device, UDEV_PROPERTY_SERIAL);
  g_return_val_if_fail (serial != NULL, NULL);
  return serial;
}

static char *
get_device_permissions_description (GUdevDevice *device)
{
  const char *vendor_name = g_udev_device_get_property (device, UDEV_PROPERTY_VENDOR_NAME);
  const char *vendor_id = g_udev_device_get_property (device, UDEV_PROPERTY_VENDOR_ID);
  const char *product_name = g_udev_device_get_property (device, UDEV_PROPERTY_PRODUCT_NAME);
  const char *product_id = g_udev_device_get_property (device, UDEV_PROPERTY_PRODUCT_ID);
  g_autofree char *base_description = NULL;

  g_return_val_if_fail (vendor_id != NULL && product_id != NULL, NULL);

  if (vendor_name != NULL && product_name != NULL)
    base_description = g_strdup_printf (_("%s by %s"), product_name, vendor_name);
  else if (vendor_name != NULL)
    base_description = g_strdup_printf (_("Device by %s"), vendor_name);
  else if (product_name != NULL)
    base_description = g_strdup (product_name);

  if (base_description != NULL)
    {
      const char *description = base_description;
      g_autofree char *decoded_description = decode_udev_name (description);

      if (decoded_description == NULL)
        g_warning ("Failed to decode %s", base_description);
      else
        description = decoded_description;

      return g_strdup_printf ("%s (%s:%s)", description, vendor_id, product_id);
    }
  else
    return g_strdup_printf ("%s:%s", vendor_id, product_id);
}

#endif

/* Auxiliary functions */

static gboolean
decode_udev_name_eval_callback (const GMatchInfo *match,
                                GString          *result,
                                gpointer          user_data)
{
  g_autofree char *digits = NULL;
  char *ep = NULL;
  gint64 value;

  digits = g_match_info_fetch (match, 1);
  g_return_val_if_fail (digits != NULL, TRUE);

  value = g_ascii_strtoll (digits, &ep, 16);
  if (*ep != '\0' || value > UCHAR_MAX || value < 0 || !isprint (value))
    {
      g_warning ("Invalid hex digits %s in %s", digits, g_match_info_get_string (match));
      value = '?';
    }

  g_string_append_c (result, value);
  return FALSE;
}

static char *
decode_udev_name (const char *name)
{
  g_autoptr(GRegex) decode_regex = NULL;
  g_autofree char *decoded = NULL;

  g_return_val_if_fail (g_utf8_validate (name, -1, NULL), NULL);

  decode_regex = g_regex_new ("\\\\x(\\d\\d)", 0, 0, NULL);
  g_return_val_if_fail (decode_regex != NULL, NULL);

  decoded = g_regex_replace_eval (decode_regex, name, -1, 0, 0,
                                  decode_udev_name_eval_callback, NULL, NULL);
  g_return_val_if_fail (decoded != NULL, NULL);

  return g_steal_pointer (&decoded);
}

static void
decode_and_insert (GVariantDict *dict,
                   const char   *key,
                   const char   *value)
{
  g_autofree char *decoded = decode_udev_name (value);

  if (decoded == NULL)
    {
      g_warning ("Failed to decode udev name (%s): %s", key, value);
      g_variant_dict_insert (dict, key, "s", value);
    }
  else
    {
      g_variant_dict_insert (dict, key, "s", decoded);
    }
}

static GVariant *
gudev_device_to_variant (Usb         *self,
                         UsbSession  *usb_session,
                         GUdevDevice *device)
{
  g_auto(GVariantDict) device_variant_dict = G_VARIANT_DICT_INIT (NULL);
  g_autoptr(GUdevDevice) parent = NULL;
  const char *device_file = NULL;
  const char *product_id = NULL;
  const char *product_name = NULL;
  const char *vendor_id = NULL;
  const char *vendor_name = NULL;
  const char *serial = NULL;
  const char *subsystem = NULL;
  const char *type = NULL;
  uint16_t number;

  parent = g_udev_device_get_parent (device);
  if (parent != NULL && usb_session_match_device (usb_session, parent))
    {
      const char *parent_syspath = NULL;
      const char *parent_id = NULL;

      parent_syspath = g_udev_device_get_sysfs_path (parent);
      if (parent_syspath != NULL)
        {
          parent_id = g_hash_table_lookup (self->syspaths_to_ids, parent_syspath);
          if (parent_id != NULL)
            g_variant_dict_insert (&device_variant_dict, "parent", "s", parent_id);
        }
    }

  device_file = g_udev_device_get_device_file (device);
  if (device_file != NULL)
    {
      if (access (device_file, R_OK) != -1)
        g_variant_dict_insert (&device_variant_dict, "readable", "b", TRUE);
      if (access (device_file, W_OK) != -1)
        g_variant_dict_insert (&device_variant_dict, "writable", "b", TRUE);

      g_variant_dict_insert (&device_variant_dict, "device_file", "s", device_file);
    }

  product_id = g_udev_device_get_property (device, UDEV_PROPERTY_PRODUCT_ID);
  if (product_id != NULL && hex_to_uint16 (product_id, &number))
    g_variant_dict_insert (&device_variant_dict, "product_id", "q", number);

  vendor_id = g_udev_device_get_property (device, UDEV_PROPERTY_VENDOR_ID);
  if (vendor_id != NULL && hex_to_uint16 (vendor_id, &number))
    g_variant_dict_insert (&device_variant_dict, "vendor_id", "q", number);

  product_name = g_udev_device_get_property (device, UDEV_PROPERTY_PRODUCT_NAME);
  if (product_name != NULL)
    decode_and_insert (&device_variant_dict, "product_name", product_name);

  vendor_name = g_udev_device_get_property (device, UDEV_PROPERTY_VENDOR_NAME);
  if (vendor_name != NULL)
    decode_and_insert (&device_variant_dict, "vendor_name", vendor_name);

  serial = g_udev_device_get_property (device, UDEV_PROPERTY_SERIAL_SHORT);
  if (serial != NULL)
    g_variant_dict_insert (&device_variant_dict, "serial", "s", serial);

  subsystem = g_udev_device_get_subsystem (device);
  if (subsystem != NULL)
    g_variant_dict_insert (&device_variant_dict, "subsystem", "s", subsystem);

  type = g_udev_device_get_property (device, UDEV_PROPERTY_TYPE);
  if (type != NULL)
    g_variant_dict_insert (&device_variant_dict, "type", "s", type);

  return g_variant_dict_end (&device_variant_dict);
}

static gboolean
create_unique_usb_id (Usb          *self,
                      GUdevDevice  *device,
                      char        **out_new_id)
{
  g_autofree char *id = NULL;
  const char *syspath;

  syspath = g_udev_device_get_sysfs_path (device);
  g_assert (syspath != NULL);

  do
    {
      g_clear_pointer (&id, g_free);
      id = g_uuid_string_random ();
    }
  while (g_hash_table_contains (self->ids_to_devices, id));

  g_debug ("Assigned unique ID %s to USB device %s", id, syspath);

  g_hash_table_insert (self->ids_to_devices, g_strdup (id), g_object_ref (device));
  g_hash_table_insert (self->syspaths_to_ids, g_strdup (syspath), g_strdup (id));

  if (out_new_id)
    *out_new_id = g_steal_pointer (&id);

  return TRUE;
}

/* Callbacks */

static void
on_gudev_client_uevent_cb (GUdevClient *client,
                           const char  *action,
                           GUdevDevice *device,
                           Usb         *self)
{
  static const char *supported_actions[] = {
    "add",
    "change",
    "remove",
    NULL,
  };

  g_autofree char *id = NULL;
  GHashTableIter iter;
  UsbSession *usb_session;
  const char *syspath = NULL;
  gboolean removing;

  if (!g_strv_contains (supported_actions, action))
    return;

  removing = g_str_equal (action, "remove");

  if (g_str_equal (action, "add"))
    {
      create_unique_usb_id (self, device, &id);
    }
  else
    {
      syspath = g_udev_device_get_sysfs_path (device);

      g_assert (syspath != NULL);
      id = g_strdup (g_hash_table_lookup (self->syspaths_to_ids, syspath));
    }

  g_assert (id != NULL);

  /* Send event to all sessions that are allowed to handle it */
  g_hash_table_iter_init (&iter, self->sessions);
  while (g_hash_table_iter_next (&iter, (gpointer *) &usb_session, NULL))
    {
      g_autoptr(GVariant) device_variant = NULL;
      GVariantBuilder devices_builder;
      Session *session;

      g_assert (G_UDEV_IS_DEVICE (device));
      g_assert (g_strcmp0 (g_udev_device_get_subsystem (device), "usb") == 0);

      /* We can't use usb_session_match_device() when a device is being
       * removed because, on removal, the only property the GUdevDevice has
       * is its sysfs path. Check if this device was previously available to
       * the USB session instead. */
      if ((!removing && !usb_session_match_device (usb_session, device)) ||
          (removing && !g_hash_table_contains (usb_session->available_devices, id)))
        continue;

      g_variant_builder_init (&devices_builder, G_VARIANT_TYPE ("a(ssa{sv})"));

      device_variant = gudev_device_to_variant (self, usb_session, device);
      g_variant_builder_add (&devices_builder, "(ss@a{sv})", action, id, g_steal_pointer (&device_variant));

      session = (Session *) usb_session;
      g_dbus_connection_emit_signal (session->connection,
                                     session->sender,
                                     "/org/freedesktop/portal/desktop",
                                     "org.freedesktop.portal.Usb",
                                     "DeviceEvents",
                                     g_variant_new ("(o@a(ssa{sv}))",
                                                    session->id,
                                                    g_variant_builder_end (&devices_builder)),
                                     NULL);

      if (removing)
        g_hash_table_remove (usb_session->available_devices, id);
      else
        g_hash_table_add (usb_session->available_devices, g_strdup (id));
    }

  if (removing)
    {
      g_assert (syspath != NULL);

      g_debug ("Removing %s -> %s", id, syspath);

      /* The value of id is owned by syspaths_to_ids, so that must be removed *after*
         the id is used for removal from ids_to_devices. */
      if (!g_hash_table_remove (self->ids_to_devices, id))
        g_critical ("Error removing USB device from ids_to_devices table");

      if (!g_hash_table_remove (self->syspaths_to_ids, syspath))
        g_critical ("Error removing USB device from syspaths_to_ids table");
    }
}

/* CreateSession */

typedef enum {
  USB_SESSION_RESPONSE_DENY,
  USB_SESSION_RESPONSE_ALLOW,
  USB_SESSION_RESPONSE_IGNORE,
} UsbSessionResponse;

static void
usb_session_created_cb (GObject      *source_object,
                        GAsyncResult *result,
                        gpointer      data)
{
  g_autoptr(UsbPermission) usb_permission_to_store = NULL;
  XdgDesktopPortalResponseEnum response;
  g_auto(GVariantBuilder) results_builder;
  g_autoptr (GVariant) results = NULL;
  g_autoptr(Request) request = data;
  g_autoptr(GError) error = NULL;
  UsbSessionResponse session_response;
  UsbSession *usb_session;
  gboolean close_session;
  Session *session;

  REQUEST_AUTOLOCK (request);

  response = XDG_DESKTOP_PORTAL_RESPONSE_OTHER;
  session = (Session *) g_object_get_data (G_OBJECT (request), "usb_session");
  usb_session = (UsbSession *) session;
  close_session = TRUE;

  g_variant_builder_init (&results_builder, G_VARIANT_TYPE_VARDICT);

  xdp_dbus_impl_usb_call_create_session_finish (usb_impl,
                                                &response,
                                                &results,
                                                result,
                                                &error);
  if (error)
    {
      g_dbus_error_strip_remote_error (error);
      goto out;
    }

  if (!request->exported || response != XDG_DESKTOP_PORTAL_RESPONSE_SUCCESS)
    goto out;

  if (!session_export (session, &error))
    {
      g_warning ("Failed to export session: %s", error->message);
      response = XDG_DESKTOP_PORTAL_RESPONSE_OTHER;
      goto out;
    }

  if (!g_variant_lookup (results, "result", "u", &session_response))
    session_response = USB_SESSION_RESPONSE_DENY;

  switch (session_response)
    {
    case USB_SESSION_RESPONSE_DENY:
      usb_permission_to_store = usb_permission_new (PERMISSION_NO,
                                                    usb_session->access_mode,
                                                    usb_session->device_candidates);
      response = XDG_DESKTOP_PORTAL_RESPONSE_CANCELLED;
      break;

    case USB_SESSION_RESPONSE_ALLOW:
      usb_permission_to_store = usb_permission_new (PERMISSION_YES,
                                                    usb_session->access_mode,
                                                    usb_session->device_candidates);
      response = XDG_DESKTOP_PORTAL_RESPONSE_SUCCESS;
      break;

    case USB_SESSION_RESPONSE_IGNORE:
      response = XDG_DESKTOP_PORTAL_RESPONSE_SUCCESS;
      break;

    default:
      g_critical ("Unknown response %u", session_response);
      response = XDG_DESKTOP_PORTAL_RESPONSE_OTHER;
      goto out;
    }

  if (usb_permission_to_store)
    {
      set_usb_permission_sync (xdp_app_info_get_id (request->app_info),
                               usb_permission_to_store);

      if (usb_permission_to_store->permission == PERMISSION_NO)
        goto out;
    }

  /* Happy path, don't close the session */
  close_session = FALSE;

  session_register (session);

  /* Send initial list of devices the app has permission to see */
  if (request->exported)
    {
      GVariantBuilder devices_builder;
      GHashTableIter iter;
      GUdevDevice *device;
      const char *id;
      Usb *self;

      g_debug ("[usb] Appending devices to CreateSession response");

      g_variant_builder_init (&devices_builder, G_VARIANT_TYPE ("a(sa{sv})"));

      self = (Usb *) usb;

      g_assert (self != NULL);
      g_assert (usb_session != NULL);

      g_hash_table_iter_init (&iter, self->ids_to_devices);
      while (g_hash_table_iter_next (&iter, (gpointer *) &id, (gpointer *) &device))
        {
          g_autoptr(GVariant) device_variant = NULL;

          g_assert (G_UDEV_IS_DEVICE (device));
          g_assert (g_strcmp0 (g_udev_device_get_subsystem (device), "usb") == 0);

          if (!usb_session_match_device (usb_session, device))
            continue;

          device_variant = gudev_device_to_variant (self, usb_session, device);
          g_variant_builder_add (&devices_builder, "(s@a{sv})", id, g_steal_pointer (&device_variant));

          g_hash_table_add (usb_session->available_devices, g_strdup (id));
        }

      g_variant_builder_add (&results_builder, "{sv}",
                             "session_handle", g_variant_new ("s", session->id));
      g_variant_builder_add (&results_builder, "{sv}",
                             "available_devices", g_variant_builder_end (&devices_builder));
    }

out:
  if (request->exported)
    {
      xdp_dbus_request_emit_response (XDP_DBUS_REQUEST (request),
                                      response,
                                      g_variant_builder_end (&results_builder));
      request_unexport (request);
    }

  if (close_session)
    session_close (session, FALSE);
}

static gboolean
validate_access_mode (const char  *key,
                      GVariant    *value,
                      GVariant    *options,
                      GError     **error)
{
  UsbAccessMode access_mode;
  const char *string;

  string = g_variant_get_string (value, NULL);

  if (!str_to_access_mode (string, &access_mode))
    {
      g_set_error (error,
                   XDG_DESKTOP_PORTAL_ERROR,
                   XDG_DESKTOP_PORTAL_ERROR_INVALID_ARGUMENT,
                   "Access mode must be one of the following: listed-devices, all");
      return FALSE;
    }

  if (access_mode == USB_ACCESS_MODE_LISTED_DEVICES &&
      !g_variant_lookup (options, "devices", "aa{sv}", NULL))
    {
      g_set_error (error,
                   XDG_DESKTOP_PORTAL_ERROR,
                   XDG_DESKTOP_PORTAL_ERROR_INVALID_ARGUMENT,
                   "No devices passed, but requested \"listed-devices\" access mode");
      return FALSE;
    }

  return TRUE;
}

static gboolean
validate_devices (const char  *key,
                  GVariant    *value,
                  GVariant    *options,
                  GError     **error)
{
  /* Must have at least one device */
  if (g_variant_n_children (value) == 0)
    {
      g_set_error (error,
                   XDG_DESKTOP_PORTAL_ERROR,
                   XDG_DESKTOP_PORTAL_ERROR_INVALID_ARGUMENT,
                   "Invalid devices requested");
      return TRUE;
    }

  /* Validate devices */
  for (size_t i = 0; i < g_variant_n_children (value); i++)
    {
      const char * const device_fields[] = { "vendor_id", "product_id", };
      g_autoptr(GVariant) device = NULL;
      GVariantDict dict;

      device = g_variant_get_child_value (value, i);

      if (!g_variant_check_format_string (device, "a{sv}", TRUE))
        {
          g_set_error (error,
                       XDG_DESKTOP_PORTAL_ERROR,
                       XDG_DESKTOP_PORTAL_ERROR_INVALID_ARGUMENT,
                       "Invalid device");
          return TRUE;
        }

      g_variant_dict_init (&dict, device);
      for (size_t j = 0; j < G_N_ELEMENTS (device_fields); j++)
        {
          if (!g_variant_dict_contains (&dict, device_fields[j]))
            {
              g_set_error (error,
                           XDG_DESKTOP_PORTAL_ERROR,
                           XDG_DESKTOP_PORTAL_ERROR_INVALID_ARGUMENT,
                           "Device does not contain \"%s\"",
                           device_fields[j]);
              g_variant_dict_clear (&dict);
              return TRUE;
            }
        }
      g_variant_dict_clear (&dict);
    }

  return TRUE;
}

static gboolean
validate_reason (const char  *key,
                 GVariant    *value,
                 GVariant    *options,
                 GError     **error)
{
  const char *string = g_variant_get_string (value, NULL);

  if (g_utf8_strlen (string, -1) > 256)
    {
      g_set_error (error,
                   XDG_DESKTOP_PORTAL_ERROR,
                   XDG_DESKTOP_PORTAL_ERROR_INVALID_ARGUMENT,
                   "Reason must be shorter than 256 characters");
      return FALSE;
    }

  return TRUE;
}

static XdpOptionKey usb_create_session_options[] = {
  { "access_mode", G_VARIANT_TYPE_STRING, validate_access_mode },
  { "devices", (const GVariantType *) "aa{sv}", validate_devices },
  { "handle_token", G_VARIANT_TYPE_STRING, NULL },
  { "session_handle_token", G_VARIANT_TYPE_STRING, NULL },
  { "reason", G_VARIANT_TYPE_STRING, validate_reason },
};

static gboolean
handle_create_session (XdpDbusUsb            *object,
                       GDBusMethodInvocation *invocation,
                       const char            *arg_parent_window,
                       GVariant              *arg_options)
{
  g_autoptr(XdpDbusImplRequest) impl_request = NULL;
  g_autoptr(UsbPermission) usb_permission = NULL;
  g_autoptr(GVariant) impl_options = NULL;
  g_autoptr(GVariant) options = NULL;
  g_autoptr(GError) error = NULL;
  GDBusConnection *connection;
  GVariantBuilder options_builder;
  UsbSession *usb_session;
  Session *session;
  Request *request;
  Usb *self;

  self = (Usb *) object;
  request = request_from_invocation (invocation);

  g_debug ("[usb] Handling CreateSession");

  REQUEST_AUTOLOCK (request);

  usb_permission = get_usb_permission_sync (xdp_app_info_get_id (request->app_info));

  if (usb_permission && usb_permission->permission == PERMISSION_NO)
    {
      g_dbus_method_invocation_return_error (invocation,
                                             XDG_DESKTOP_PORTAL_ERROR,
                                             XDG_DESKTOP_PORTAL_ERROR_NOT_ALLOWED,
                                             "Not allowed to create USB sessions");
      return G_DBUS_METHOD_INVOCATION_HANDLED;
    }

  impl_request = xdp_dbus_impl_request_proxy_new_sync (g_dbus_proxy_get_connection (G_DBUS_PROXY (usb_impl)),
                                                       G_DBUS_PROXY_FLAGS_NONE,
                                                       g_dbus_proxy_get_name (G_DBUS_PROXY (usb_impl)),
                                                       request->id,
                                                       NULL,
                                                       &error);
  if (!impl_request)
    {
      g_dbus_method_invocation_return_gerror (invocation, error);
      return G_DBUS_METHOD_INVOCATION_HANDLED;
    }

  g_variant_builder_init (&options_builder, G_VARIANT_TYPE_VARDICT);
  if (!xdp_filter_options (arg_options,
                           &options_builder,
                           usb_create_session_options,
                           G_N_ELEMENTS (usb_create_session_options),
                           &error))
    {
      g_dbus_method_invocation_return_gerror (invocation, error);
      return G_DBUS_METHOD_INVOCATION_HANDLED;
    }
  options = g_variant_builder_end (&options_builder);

  connection = g_dbus_method_invocation_get_connection (invocation);
  usb_session = usb_session_new (connection, request, options, &error);
  if (!usb_session)
    {
      g_dbus_method_invocation_return_gerror (invocation, error);
      return G_DBUS_METHOD_INVOCATION_HANDLED;
    }

  g_object_set_data_full (G_OBJECT (request), "usb_session", g_object_ref (usb_session), g_object_unref);
  g_hash_table_add (self->sessions, usb_session);

  request_set_impl_request (request, impl_request);
  request_export (request, connection);

  /* Check if the session matches the permission store, and inject it in
   * the options variant for backends. */
    {
      GVariantBuilder impl_options_builder;
      gboolean matches_permission_store;

      g_assert (!usb_permission || usb_permission->permission != PERMISSION_NO);
      g_assert (usb_session->access_mode == USB_ACCESS_MODE_ALL ||
                usb_session->access_mode == USB_ACCESS_MODE_LISTED_DEVICES);

      g_variant_builder_init (&impl_options_builder, G_VARIANT_TYPE_VARDICT);
      if (!xdp_filter_options (arg_options,
                               &impl_options_builder,
                               usb_create_session_options,
                               G_N_ELEMENTS (usb_create_session_options),
                               &error))
        {
          g_dbus_method_invocation_return_gerror (invocation, error);
          return G_DBUS_METHOD_INVOCATION_HANDLED;
        }

      matches_permission_store = usb_permission &&
                                 usb_permission->permission == PERMISSION_YES &&
                                 usb_permission->access_mode == usb_session->access_mode &&
                                 /* TODO: compare device candidates */ TRUE;

      g_variant_builder_add (&impl_options_builder, "{sv}",
                             "matches_permission_store",
                             g_variant_new_boolean (matches_permission_store));

      impl_options = g_variant_builder_end (&impl_options_builder);
    }

  session = (Session *) usb_session;

  xdp_dbus_impl_usb_call_create_session (usb_impl,
                                         request->id,
                                         session->id,
                                         xdp_app_info_get_id (request->app_info),
                                         arg_parent_window,
                                         g_steal_pointer (&impl_options),
                                         NULL,
                                         usb_session_created_cb,
                                         g_object_ref (request));

  xdp_dbus_usb_complete_create_session (object, invocation, request->id);

  return G_DBUS_METHOD_INVOCATION_HANDLED;
}

/* EnumerateDevices */

static XdpOptionKey usb_enumerate_devices_options[] = {
};

static gboolean
handle_enumerate_devices (XdpDbusUsb            *object,
                          GDBusMethodInvocation *invocation,
                          const char            *arg_session_handle,
                          GVariant              *arg_options)
{
  g_autoptr(UsbPermission) usb_permission = NULL;
  g_autoptr(GVariant) options = NULL;
  g_autoptr(GVariant) devices = NULL;
  g_autoptr(GError) error = NULL;
  GVariantBuilder options_builder;
  UsbSession *usb_session;
  Call *call;
  Usb *self;

  self = (Usb *) object;
  call = call_from_invocation (invocation);

  usb_permission = get_usb_permission_sync (xdp_app_info_get_id (call->app_info));

  if (!usb_permission ||
      usb_permission->permission == PERMISSION_UNSET ||
      usb_permission->permission == PERMISSION_NO)
    {
      g_dbus_method_invocation_return_error (invocation,
                                             XDG_DESKTOP_PORTAL_ERROR,
                                             XDG_DESKTOP_PORTAL_ERROR_NOT_ALLOWED,
                                             "Not allowed to enumerate devices");
      return G_DBUS_METHOD_INVOCATION_HANDLED;
    }

  g_variant_builder_init (&options_builder, G_VARIANT_TYPE_VARDICT);
  if (!xdp_filter_options (arg_options, &options_builder,
                           usb_enumerate_devices_options,
                           G_N_ELEMENTS (usb_enumerate_devices_options),
                           &error))
    {
      g_dbus_method_invocation_return_gerror (invocation, error);
      return G_DBUS_METHOD_INVOCATION_HANDLED;
    }
  options = g_variant_builder_end (&options_builder);

  usb_session = (UsbSession *) acquire_session_from_call (arg_session_handle, call);
  if (!usb_session)
    {
      g_dbus_method_invocation_return_error (invocation,
                                             G_DBUS_ERROR,
                                             G_DBUS_ERROR_ACCESS_DENIED,
                                             "Invalid session");
      return G_DBUS_METHOD_INVOCATION_HANDLED;
    }

  /* List devices the app has permission */
    {
      GVariantBuilder builder;
      GHashTableIter iter;
      GUdevDevice *device;
      const char *id;

      g_variant_builder_init (&builder, G_VARIANT_TYPE ("a(sa{sv})"));

      g_hash_table_iter_init (&iter, self->ids_to_devices);
      while (g_hash_table_iter_next (&iter, (gpointer *) &id, (gpointer *) &device))
        {
          g_autoptr(GVariant) device_variant = NULL;

          g_assert (G_UDEV_IS_DEVICE (device));
          g_assert (g_strcmp0 (g_udev_device_get_subsystem (device), "usb") == 0);

          if (!usb_session_match_device (usb_session, device))
            continue;

          device_variant = gudev_device_to_variant (self, usb_session, device);
          g_variant_builder_add (&builder, "(s@a{sv})", id, g_steal_pointer (&device_variant));
        }

      devices = g_variant_builder_end (&builder);
    }

  xdp_dbus_usb_complete_enumerate_devices (object, invocation, g_steal_pointer (&devices));

  return G_DBUS_METHOD_INVOCATION_HANDLED;
}

/* AccessDevice */

static XdpOptionKey usb_device_options[] = {
  { "writable", G_VARIANT_TYPE_BOOLEAN, NULL },
};

static void
usb_access_devices_cb (GObject      *source_object,
                       GAsyncResult *result,
                       gpointer      data)
{
  XdgDesktopPortalResponseEnum response;
  g_autoptr(GVariantIter) devices_iter = NULL;
  g_auto(GVariantBuilder) results_builder;
  g_autoptr (GVariant) results = NULL;
  g_autoptr(Request) request = data;
  g_autoptr(GError) error = NULL;
  UsbSession *usb_session;
  GVariant *options;
  Session *session;
  const char *device_id;

  REQUEST_AUTOLOCK (request);

  response = XDG_DESKTOP_PORTAL_RESPONSE_OTHER;
  session = (Session *) g_object_get_data (G_OBJECT (request), "usb_session");
  usb_session = (UsbSession *) session;

  g_assert (usb_session->session_state == USB_SESSION_STATE_ACCESSING_DEVICES);
  g_assert (usb_session->accessing_devices == NULL);

  g_variant_builder_init (&results_builder, G_VARIANT_TYPE_VARDICT);

  xdp_dbus_impl_usb_call_access_devices_finish (usb_impl, &response, &results, result, &error);

  if (error)
    {
      response = XDG_DESKTOP_PORTAL_RESPONSE_OTHER;
      g_dbus_error_strip_remote_error (error);
      goto out;
    }

  /* TODO: check if the list of devices that the backend reported is strictly
   * equal or a subset of the devices the app requested. */

  /* TODO: check if we're strictly equal or downgrading the "writable" option */

  if (!g_variant_lookup (results, "devices", "a(sa{sv})", &devices_iter))
    goto out;

  usb_session->accessing_devices = g_ptr_array_new_full (g_variant_iter_n_children (devices_iter),
                                                         usb_device_access_data_free);
  while (g_variant_iter_next (devices_iter, "(&s@a{sv})", &device_id, &options))
    {
      g_autoptr(UsbDeviceAccessData) access_data = NULL;
      gboolean writable;

      if (!g_variant_lookup (options, "writable", "b", &writable))
        writable = FALSE;

      access_data = g_new0 (UsbDeviceAccessData, 1);
      access_data->device_id = g_strdup (device_id);
      access_data->writable = writable;

      g_ptr_array_add (usb_session->accessing_devices, g_steal_pointer (&access_data));

      g_clear_pointer (&options, g_variant_unref);
    }

out:
  if (request->exported)
    {
      xdp_dbus_request_emit_response (XDP_DBUS_REQUEST (request),
                                      response,
                                      g_variant_builder_end (&results_builder));
      request_unexport (request);
    }
}

static gboolean
filter_access_devices (Usb         *self,
                       UsbSession  *usb_session,
                       GVariant    *devices,
                       GVariant   **out_filtered_devices,
                       GError     **out_error)
{
  GVariantBuilder filtered_devices_builder;
  GVariantIter *device_options_iter;
  GVariantIter devices_iter;
  const char *device_id;
  size_t n_devices;

  g_assert (self != NULL);
  g_assert (usb_session != NULL);
  g_assert (devices != NULL);
  g_assert (out_filtered_devices != NULL && *out_filtered_devices == NULL);
  g_assert (out_error != NULL && *out_error == NULL);

  g_message ("Devices: %s", g_variant_print (devices, TRUE));

  n_devices = g_variant_iter_init (&devices_iter, devices);

  if (n_devices == 0)
    {
      g_set_error (out_error,
                   XDG_DESKTOP_PORTAL_ERROR,
                   XDG_DESKTOP_PORTAL_ERROR_INVALID_ARGUMENT,
                   "No devices in the devices array");
      return FALSE;
    }

  g_variant_builder_init (&filtered_devices_builder, G_VARIANT_TYPE ("a(sa{sv}a{sv})"));

  while (g_variant_iter_next (&devices_iter,
                              "(&sa{sv})",
                              &device_id,
                              &device_options_iter))
    {
      g_autoptr(GVariantIter) owned_deviced_options_iter = device_options_iter;
      g_autoptr(GVariant) device_variant = NULL;
      GVariantDict device_options_dict;
      GUdevDevice *device;
      GVariant *device_option_value;
      const char *device_option;

      device = g_hash_table_lookup (self->ids_to_devices, device_id);

      if (!device)
        {
          g_set_error (out_error,
                       XDG_DESKTOP_PORTAL_ERROR,
                       XDG_DESKTOP_PORTAL_ERROR_INVALID_ARGUMENT,
                       "Device %s not available",
                       device_id);
          return FALSE;
        }

      g_assert (G_UDEV_IS_DEVICE (device));
      g_assert (g_strcmp0 (g_udev_device_get_subsystem (device), "usb") == 0);

      /* Can the app even request this device? */
      if (!usb_session_match_device (usb_session, device))
        {
          g_set_error (out_error,
                       XDG_DESKTOP_PORTAL_ERROR,
                       XDG_DESKTOP_PORTAL_ERROR_NOT_ALLOWED,
                       "Access to device %s is not allowed",
                       device_id);
          return FALSE;
        }

      g_variant_dict_init (&device_options_dict, NULL);

      while (g_variant_iter_next (device_options_iter,
                                  "{&sv}",
                                  &device_option,
                                  &device_option_value))
        {
          for (size_t i = 0; i < G_N_ELEMENTS (usb_device_options); i++)
            {
              if (g_strcmp0 (device_option, usb_device_options[i].key) != 0)
                continue;

              if (!g_variant_is_of_type (device_option_value, usb_device_options[i].type))
                {
                  g_set_error (out_error,
                               XDG_DESKTOP_PORTAL_ERROR,
                               XDG_DESKTOP_PORTAL_ERROR_NOT_ALLOWED,
                               "Invalid type for option '%s'",
                               device_option);
                  g_variant_builder_clear (&filtered_devices_builder);
                  g_variant_dict_clear (&device_options_dict);
                  g_clear_pointer (&device_option_value, g_variant_unref);
                  return FALSE;
                }

              g_variant_dict_insert_value (&device_options_dict, device_option, device_option_value);

              g_clear_pointer (&device_option_value, g_variant_unref);
            }
        }

      device_variant = gudev_device_to_variant (self, usb_session, device);

      g_variant_builder_add (&filtered_devices_builder,
                             "(s@a{sv}@a{sv})",
                             device_id,
                             g_steal_pointer (&device_variant),
                             g_variant_dict_end (&device_options_dict));
    }

  *out_filtered_devices = g_variant_builder_end (&filtered_devices_builder);
  return TRUE;
}

static XdpOptionKey usb_access_devices_options[] = {
};

static gboolean
handle_access_devices (XdpDbusUsb            *object,
                       GDBusMethodInvocation *invocation,
                       const char            *arg_session_handle,
                       const char            *arg_parent_window,
                       GVariant              *arg_devices,
                       GVariant              *arg_options)
{
  g_autoptr(XdpDbusImplRequest) impl_request = NULL;
  g_autoptr(UsbPermission) usb_permission = NULL;
  g_autoptr(GVariant) filtered_devices = NULL;
  g_autoptr(GVariant) options = NULL;
  g_autoptr(GError) error = NULL;
  GVariantBuilder options_builder;
  UsbSession *usb_session;
  Request *request;
  Session *session;
  Usb *self;

  self = (Usb *) object;
  request = request_from_invocation (invocation);

  g_debug ("[usb] Handling AccessDevices");

  REQUEST_AUTOLOCK (request);

  session = acquire_session (arg_session_handle, request);
  if (!session)
    {
      g_dbus_method_invocation_return_error (invocation,
                                             G_DBUS_ERROR,
                                             G_DBUS_ERROR_ACCESS_DENIED,
                                             "Invalid session");
      return G_DBUS_METHOD_INVOCATION_HANDLED;
    }

  SESSION_AUTOLOCK_UNREF (session);

  usb_session = (UsbSession *) session;
  if (usb_session->session_state != USB_SESSION_STATE_DEFAULT)
    {
      g_dbus_method_invocation_return_error (invocation,
                                             G_DBUS_ERROR,
                                             G_DBUS_ERROR_INVALID_ARGS,
                                             "Invalid session state");
      return G_DBUS_METHOD_INVOCATION_HANDLED;
    }

  usb_permission = get_usb_permission_sync (xdp_app_info_get_id (request->app_info));
  if (usb_permission && usb_permission->permission == PERMISSION_NO)
    {
      g_dbus_method_invocation_return_error (invocation,
                                             XDG_DESKTOP_PORTAL_ERROR,
                                             XDG_DESKTOP_PORTAL_ERROR_NOT_ALLOWED,
                                             "Not allowed to create USB sessions");
      return G_DBUS_METHOD_INVOCATION_HANDLED;
    }

  impl_request = xdp_dbus_impl_request_proxy_new_sync (g_dbus_proxy_get_connection (G_DBUS_PROXY (usb_impl)),
                                                       G_DBUS_PROXY_FLAGS_NONE,
                                                       g_dbus_proxy_get_name (G_DBUS_PROXY (usb_impl)),
                                                       request->id,
                                                       NULL,
                                                       &error);
  if (!impl_request)
    {
      g_dbus_method_invocation_return_gerror (invocation, error);
      return G_DBUS_METHOD_INVOCATION_HANDLED;
    }

  g_variant_builder_init (&options_builder, G_VARIANT_TYPE_VARDICT);
  if (!xdp_filter_options (arg_options,
                           &options_builder,
                           usb_access_devices_options,
                           G_N_ELEMENTS (usb_access_devices_options),
                           &error))
    {
      g_dbus_method_invocation_return_gerror (invocation, error);
      return G_DBUS_METHOD_INVOCATION_HANDLED;
    }
  options = g_variant_builder_end (&options_builder);

  /* Validate devices */
  if (!filter_access_devices (self, usb_session, arg_devices, &filtered_devices, &error))
    {
      g_dbus_method_invocation_return_gerror (invocation, error);
      return G_DBUS_METHOD_INVOCATION_HANDLED;
    }

  g_object_set_data_full (G_OBJECT (request), "usb_session", g_object_ref (usb_session), g_object_unref);

  request_set_impl_request (request, impl_request);
  request_export (request, g_dbus_method_invocation_get_connection (invocation));

  usb_session->session_state = USB_SESSION_STATE_ACCESSING_DEVICES;

  xdp_dbus_impl_usb_call_access_devices (usb_impl,
                                         request->id,
                                         arg_session_handle,
                                         arg_parent_window,
                                         xdp_app_info_get_id (request->app_info),
                                         g_steal_pointer (&filtered_devices),
                                         g_steal_pointer (&options),
                                         NULL,
                                         usb_access_devices_cb,
                                         g_object_ref (request));

  xdp_dbus_usb_complete_access_devices (object, invocation, request->id);

  return G_DBUS_METHOD_INVOCATION_HANDLED;
}

/* FinishAccessDevices */

#define MAX_DEVICES 8

static gboolean
handle_finish_access_devices (XdpDbusUsb            *object,
                              GDBusMethodInvocation *invocation,
                              const gchar           *arg_session_handle,
                              GVariant              *arg_options)
{
  g_autoptr(UsbPermission) usb_permission = NULL;
  g_autoptr(GUnixFDList) fds = NULL;
  GVariantBuilder results_builder;
  UsbSession *usb_session;
  uint32_t accessed_devices;
  gboolean finished;
  Session *session;
  Call *call;
  Usb *self;

  self = (Usb *) object;
  call = call_from_invocation (invocation);

  g_debug ("[usb] Handling FinishAccessDevices");

  session = acquire_session_from_call (arg_session_handle, call);
  if (!session)
    {
      g_dbus_method_invocation_return_error (invocation,
                                             G_DBUS_ERROR,
                                             G_DBUS_ERROR_ACCESS_DENIED,
                                             "Invalid session");
      return G_DBUS_METHOD_INVOCATION_HANDLED;
    }

  SESSION_AUTOLOCK_UNREF (session);

  usb_session = (UsbSession *) session;
  if (usb_session->session_state != USB_SESSION_STATE_ACCESSING_DEVICES)
    {
      g_dbus_method_invocation_return_error (invocation,
                                             G_DBUS_ERROR,
                                             G_DBUS_ERROR_INVALID_ARGS,
                                             "Invalid session state");
      return G_DBUS_METHOD_INVOCATION_HANDLED;
    }

  usb_permission = get_usb_permission_sync (xdp_app_info_get_id (call->app_info));
  if (usb_permission && usb_permission->permission == PERMISSION_NO)
    {
      g_dbus_method_invocation_return_error (invocation,
                                             XDG_DESKTOP_PORTAL_ERROR,
                                             XDG_DESKTOP_PORTAL_ERROR_NOT_ALLOWED,
                                             "Not allowed to access USB devices");
      return G_DBUS_METHOD_INVOCATION_HANDLED;
    }

  g_assert (usb_session->session_state == USB_SESSION_STATE_ACCESSING_DEVICES);
  g_assert (usb_session->accessing_devices != NULL);

  fds = g_unix_fd_list_new ();

  g_variant_builder_init (&results_builder, G_VARIANT_TYPE ("a(sa{sv})"));

  accessed_devices = 0;
  while (accessed_devices < MAX_DEVICES &&
         usb_session->accessing_devices->len > 0)
    {
      g_autoptr(UsbDeviceAccessData) access_data = NULL;
      g_autoptr(GError) error = NULL;
      GVariantDict dict;
      GUdevDevice *device;
      const char *device_file;
      int fd_index;
      int fd;

      g_variant_dict_init (&dict, NULL);

      access_data = g_ptr_array_steal_index (usb_session->accessing_devices, 0);
      device = g_hash_table_lookup (self->ids_to_devices, access_data->device_id);

      if (!device)
        {
          g_variant_dict_insert (&dict, "success", "b", FALSE);
          g_variant_dict_insert (&dict, "error", "s", _("Device not available"));
          g_variant_builder_add (&results_builder, "(s@a{sv})",
                                 access_data->device_id,
                                 g_variant_dict_end (&dict));
          continue;
        }

      device_file = g_udev_device_get_device_file (device);
      if (!device_file)
        {
          g_variant_dict_insert (&dict, "success", "b", FALSE);
          g_variant_dict_insert (&dict, "error", "s", _("No device file"));
          g_variant_builder_add (&results_builder, "(s@a{sv})",
                                 access_data->device_id,
                                 g_variant_dict_end (&dict));
          continue;
        }

      /* Can the app even request this device? */
      if (!usb_session_match_device (usb_session, device))
        {
          g_variant_dict_insert (&dict, "success", "b", FALSE);
          g_variant_dict_insert (&dict, "error", "s", _("Not allowed"));
          g_variant_builder_add (&results_builder, "(s@a{sv})",
                                 access_data->device_id,
                                 g_variant_dict_end (&dict));
          continue;
        }

      fd = open (device_file, access_data->writable ? O_RDWR : O_RDONLY);
      if (fd == -1)
        {
          g_variant_dict_insert (&dict, "success", "b", FALSE);
          g_variant_dict_insert (&dict, "error", "s", g_strerror (errno));
          g_variant_builder_add (&results_builder, "(s@a{sv})",
                                 access_data->device_id,
                                 g_variant_dict_end (&dict));
          continue;
        }

      fd_index = g_unix_fd_list_append (fds, fd, &error);
      close (fd);

      if (error)
        {
          g_variant_dict_insert (&dict, "success", "b", FALSE);
          g_variant_dict_insert (&dict, "error", "s", error->message);
          g_variant_builder_add (&results_builder, "(s@a{sv})",
                                 access_data->device_id,
                                 g_variant_dict_end (&dict));
          continue;
        }

      g_variant_dict_insert (&dict, "success", "b", TRUE);
      g_variant_dict_insert (&dict, "fd", "h", fd_index);
      g_variant_builder_add (&results_builder, "(s@a{sv})",
                             access_data->device_id,
                             g_variant_dict_end (&dict));

      accessed_devices++;
    }

  finished = usb_session->accessing_devices->len == 0;

  if (finished)
    {
      usb_session->session_state = USB_SESSION_STATE_DEFAULT;
      g_clear_pointer (&usb_session->accessing_devices, g_ptr_array_unref);
    }

  g_dbus_method_invocation_return_value_with_unix_fd_list (invocation,
                                                           g_variant_new ("(@a(sa{sv})b)",
                                                                          g_variant_builder_end (&results_builder),
                                                                          finished),
                                                           g_steal_pointer (&fds));

  return G_DBUS_METHOD_INVOCATION_HANDLED;
}

static void
usb_iface_init (XdpDbusUsbIface *iface)
{
  iface->handle_create_session = handle_create_session;
  iface->handle_enumerate_devices = handle_enumerate_devices;
  iface->handle_access_devices = handle_access_devices;
  iface->handle_finish_access_devices = handle_finish_access_devices;
}

static void
usb_dispose (GObject *object)
{
  Usb *self = (Usb *) object;

  g_clear_pointer (&self->ids_to_devices, g_hash_table_unref);
  g_clear_pointer (&self->syspaths_to_ids, g_hash_table_unref);
  g_clear_pointer (&self->sessions, g_hash_table_unref);

  g_clear_object (&self->gudev_client);
}

static void
usb_class_init (UsbClass *klass)
{
  GObjectClass *object_class = G_OBJECT_CLASS (klass);

  object_class->dispose = usb_dispose;
}

static void
usb_init (Usb *self)
{
  g_autolist(GUdevDevice) devices = NULL;
  const char * const subsystems[] = {
    "usb",
    NULL,
  };

  g_debug ("[usb] Initializing USB portal");

  xdp_dbus_usb_set_version (XDP_DBUS_USB (self), 1);

  self->ids_to_devices = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_object_unref);
  self->syspaths_to_ids = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
  self->sessions = g_hash_table_new (g_direct_hash, g_direct_equal);

  self->gudev_client = g_udev_client_new (subsystems);
  g_signal_connect (self->gudev_client,
                    "uevent",
                    G_CALLBACK (on_gudev_client_uevent_cb),
                    self);

  /* Initialize devices */
  devices = g_udev_client_query_by_subsystem (self->gudev_client, "usb");
  for (GList *l = devices; l; l = l->next)
    {
      GUdevDevice *device = l->data;

      g_assert (G_UDEV_IS_DEVICE (device));
      g_assert (g_strcmp0 (g_udev_device_get_subsystem (device), "usb") == 0);

      if (!create_unique_usb_id (self, device, NULL))
        g_assert_not_reached ();
    }
}

GDBusInterfaceSkeleton *
usb_create (GDBusConnection *connection,
            const char      *dbus_name)
{
  g_autoptr(GError) error = NULL;

  usb_impl = xdp_dbus_impl_usb_proxy_new_sync (connection,
                                               G_DBUS_PROXY_FLAGS_NONE,
                                               dbus_name,
                                               DESKTOP_PORTAL_OBJECT_PATH,
                                               NULL,
                                               &error);
  if (usb_impl == NULL)
    {
      g_warning ("Failed to create USB proxy: %s", error->message);
      return NULL;
    }

  g_dbus_proxy_set_default_timeout (G_DBUS_PROXY (usb_impl), G_MAXINT);

  g_assert (usb_impl != NULL);
  g_assert (usb == NULL);

  usb = g_object_new (usb_get_type (), NULL);

  return G_DBUS_INTERFACE_SKELETON (usb);
}
