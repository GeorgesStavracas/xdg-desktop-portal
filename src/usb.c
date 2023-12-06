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
#include "xdp-devices-filter.h"
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

/* TODO:
 *
 * AccessDevices()
 *  - Check if backend is returning appropriate device ids
 *  - Check if backend is not increasing permissions
 *  - Save allowed devices in the permission store
 */

typedef struct _Usb
{
  XdpDbusUsbSkeleton parent_instance;

  GHashTable *ids_to_devices;
  GHashTable *syspaths_to_ids;

  GHashTable *sessions;
  GHashTable *sender_infos;

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

static gboolean
is_gudev_device_suitable (GUdevDevice *device)
{
  const char *device_file = NULL;

  g_assert (g_strcmp0 (g_udev_device_get_subsystem (device), "usb") == 0);

  device_file = g_udev_device_get_device_file (device);
  if (!device_file)
    return FALSE;

  return TRUE;
}

/* UsbDeviceAcquireData */

typedef struct
{
  char *device_id;
  gboolean writable;
} UsbDeviceAcquireData;

static void
usb_device_acquire_data_free (gpointer data)
{
  UsbDeviceAcquireData *access_data = (UsbDeviceAcquireData *) data;

  if (!access_data)
    return;

  g_clear_pointer (&access_data->device_id, g_free);
  g_clear_pointer (&access_data, g_free);
}

G_DEFINE_AUTOPTR_CLEANUP_FUNC (UsbDeviceAcquireData, usb_device_acquire_data_free)

/* UsbOwnedDevice */

typedef struct _UsbOwnedDevice
{
  char *sender_name;
  char *device_id;
  int fd;
} UsbOwnedDevice;

static void
usb_owned_device_free (gpointer data)
{
  UsbOwnedDevice *owned_device = (UsbOwnedDevice *) data;

  if (!owned_device)
    return;

  if (owned_device->fd != -1)
    {
      close (owned_device->fd);
      owned_device->fd = -1;
    }

  g_clear_pointer (&owned_device->device_id, g_free);
  g_clear_pointer (&owned_device, g_free);
}

G_DEFINE_AUTOPTR_CLEANUP_FUNC (UsbOwnedDevice, usb_owned_device_free)

/* UsbSenderInfo */

typedef enum
{
  USB_SENDER_STATE_DEFAULT,
  USB_SENDER_STATE_ACQUIRING_DEVICES,
} UsbSenderState;

typedef struct _UsbSenderInfo
{
  gatomicrefcount ref_count;

  char *sender_name;

  UsbSenderState sender_state;
  GPtrArray *filters;
  GPtrArray *acquiring_devices;

  GHashTable *owned_devices; /* device id → UsbOwnedDevices */
} UsbSenderInfo;

static void
usb_sender_info_unref (gpointer data)
{
  UsbSenderInfo *sender_info = (UsbSenderInfo *) data;

  if (g_atomic_ref_count_dec (&sender_info->ref_count))
    {
      g_clear_pointer (&sender_info->sender_name, g_free);
      g_clear_pointer (&sender_info->owned_devices, g_hash_table_destroy);
      g_clear_pointer (&sender_info->filters, g_ptr_array_unref);
      g_clear_pointer (&sender_info, g_free);
    }
}

G_DEFINE_AUTOPTR_CLEANUP_FUNC (UsbSenderInfo, usb_sender_info_unref)

static UsbSenderInfo *
usb_sender_info_new (const char *sender_name,
                     const char *app_id)
{
  g_autoptr(UsbSenderInfo) sender_info = NULL;

  sender_info = g_new0 (UsbSenderInfo, 1);
  g_atomic_ref_count_init (&sender_info->ref_count);
  sender_info->sender_name = g_strdup (sender_name);
  sender_info->sender_state = USB_SENDER_STATE_DEFAULT;
  sender_info->filters = xdp_devices_filter_get_all_for_app_id (app_id);
  sender_info->owned_devices = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, usb_owned_device_free);

  return g_steal_pointer (&sender_info);
}

static UsbSenderInfo *
usb_sender_info_from_call (Usb  *self,
                           Call *call)
{
  g_autoptr(UsbSenderInfo) sender_info = NULL;

  g_assert (call != NULL);

  sender_info = g_hash_table_lookup (self->sender_infos, call->sender);

  if (!sender_info)
    {
      sender_info = usb_sender_info_new (call->sender, xdp_app_info_get_id (call->app_info));
      g_hash_table_insert (self->sender_infos, g_strdup (call->sender), sender_info);
    }

  g_assert (sender_info != NULL);
  g_atomic_ref_count_inc (&sender_info->ref_count);

  return g_steal_pointer (&sender_info);
}

static UsbSenderInfo *
usb_sender_info_from_request (Usb     *self,
                              Request *request)
{
  g_autoptr(UsbSenderInfo) sender_info = NULL;

  g_assert (request != NULL);

  sender_info = g_hash_table_lookup (self->sender_infos, request->sender);

  if (!sender_info)
    {
      sender_info = usb_sender_info_new (request->sender, xdp_app_info_get_id (request->app_info));
      g_hash_table_insert (self->sender_infos, g_strdup (request->sender), sender_info);
    }

  g_assert (sender_info != NULL);
  g_atomic_ref_count_inc (&sender_info->ref_count);

  return g_steal_pointer (&sender_info);
}

static void
usb_sender_info_acquire_device (UsbSenderInfo *sender_info,
                                const char    *device_id,
                                int            fd)
{
  g_autoptr(UsbOwnedDevice) owned_device = NULL;

  g_assert (sender_info != NULL);
  g_assert (!g_hash_table_contains (sender_info->owned_devices, device_id));

  owned_device = g_new0 (UsbOwnedDevice, 1);
  owned_device->device_id = g_strdup (device_id);
  owned_device->fd = xdp_steal_fd (&fd);

  g_hash_table_insert (sender_info->owned_devices,
                       g_strdup (device_id),
                       g_steal_pointer (&owned_device));
}

static void
usb_sender_info_release_device (UsbSenderInfo *sender_info,
                                const char    *device_id)
{
  g_assert (sender_info != NULL);

  if (!g_hash_table_remove (sender_info->owned_devices, device_id))
    g_warning ("Device %s not owned by %s", device_id, sender_info->sender_name);

}

/* UsbSession */

typedef struct _UsbSession
{
  Session parent;

  GHashTable *available_devices;
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

static UsbSession *
usb_session_new (GDBusConnection  *connection,
                 Call             *call,
                 GVariant         *options,
                 GError          **error)
{
  UsbSession *usb_session;
  Session *session = NULL;

  session = g_initable_new (usb_session_get_type (),
                            NULL, error,
                            "connection", connection,
                            "sender", call->sender,
                            "app-id", xdp_app_info_get_id (call->app_info),
                            "token", lookup_session_token (options),
                            NULL);
  if (!session)
    return NULL;

  usb_session = (UsbSession *) session;
  usb_session->available_devices = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);

  g_debug ("[usb] USB session '%s' created", session->id);

  return (UsbSession *)session;
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

static gboolean
filters_match_device (GPtrArray   *filters,
                      GUdevDevice *device)
{
  for (size_t i = 0; i < filters->len; i++)
    {
      XdpDevicesFilter *filter = g_ptr_array_index (filters, i);

      if (xdp_devices_filter_match_device (filter, device))
        return TRUE;
    }

  return FALSE;
}

static GVariant *
gudev_device_to_variant (Usb         *self,
                         GPtrArray   *filters,
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
  if (parent != NULL && filters_match_device (filters, parent))
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

  g_assert (is_gudev_device_suitable (device));

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

  if (!is_gudev_device_suitable (device))
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
      g_autoptr(GPtrArray) devices_filters = NULL;
      g_autoptr(GVariant) device_variant = NULL;
      GVariantBuilder devices_builder;
      Session *session;

      g_assert (G_UDEV_IS_DEVICE (device));
      g_assert (g_strcmp0 (g_udev_device_get_subsystem (device), "usb") == 0);

      session = (Session *) usb_session;
      devices_filters = xdp_devices_filter_get_all_for_app_id (session->app_id);
      g_assert (devices_filters != NULL);

      /* We can't use filters_match_device() when a device is being removed because,
       * on removal, the only property the GUdevDevice has is its sysfs path.
       * Check if this device was previously available to the USB session
       * instead. */
      if ((removing && !g_hash_table_contains (usb_session->available_devices, id)) ||
          (!removing && !filters_match_device (devices_filters, device)))
        continue;


      g_variant_builder_init (&devices_builder, G_VARIANT_TYPE ("a(ssa{sv})"));

      device_variant = gudev_device_to_variant (self, devices_filters, device);
      g_variant_builder_add (&devices_builder, "(ss@a{sv})", action, id, g_steal_pointer (&device_variant));

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

static XdpOptionKey usb_create_session_options[] = {
  { "handle_token", G_VARIANT_TYPE_STRING, NULL },
  { "session_handle_token", G_VARIANT_TYPE_STRING, NULL },
};

static gboolean
handle_create_session (XdpDbusUsb            *object,
                       GDBusMethodInvocation *invocation,
                       GVariant              *arg_options)
{
  g_autoptr(GVariant) options = NULL;
  g_autoptr(GError) error = NULL;
  GDBusConnection *connection;
  GVariantBuilder options_builder;
  UsbSession *usb_session;
  Permission permission;
  Session *session;
  Call *call;
  Usb *self;

  self = (Usb *) object;
  call = call_from_invocation (invocation);

  g_debug ("[usb] Handling CreateSession");

  permission = get_permission_sync (xdp_app_info_get_id (call->app_info),
                                    PERMISSION_TABLE,
                                    PERMISSION_ID);
  if (permission == PERMISSION_NO)
    {
      g_dbus_method_invocation_return_error (invocation,
                                             XDG_DESKTOP_PORTAL_ERROR,
                                             XDG_DESKTOP_PORTAL_ERROR_NOT_ALLOWED,
                                             "Not allowed to create USB sessions");
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
  usb_session = usb_session_new (connection, call, options, &error);
  if (!usb_session)
    {
      g_dbus_method_invocation_return_gerror (invocation, error);
      return G_DBUS_METHOD_INVOCATION_HANDLED;
    }

  session = (Session *) usb_session;
  if (!session_export (session, &error))
    {
      g_dbus_method_invocation_return_gerror (invocation, error);
      session_close (session, FALSE);
      return G_DBUS_METHOD_INVOCATION_HANDLED;
    }

  session_register (session);

  g_debug ("New USB session registered: %s",  session->id);
  g_hash_table_add (self->sessions, usb_session);

  xdp_dbus_usb_complete_create_session (object, invocation, session->id);

  g_assert (permission != PERMISSION_NO);

  /* Send initial list of devices the app has permission to see */
    {
      g_autoptr(UsbSenderInfo) sender_info = NULL;
      GVariantBuilder devices_builder;
      GHashTableIter iter;
      GUdevDevice *device;
      const char *id;

      g_debug ("[usb] Appending devices to CreateSession response");

      g_variant_builder_init (&devices_builder, G_VARIANT_TYPE ("a(ssa{sv})"));

      g_assert (self != NULL);

      g_message ("A");

      sender_info = usb_sender_info_from_call (self, call);
      g_assert (sender_info != NULL);

      g_message ("B");

      g_hash_table_iter_init (&iter, self->ids_to_devices);
      while (g_hash_table_iter_next (&iter, (gpointer *) &id, (gpointer *) &device))
        {
          g_autoptr(GVariant) device_variant = NULL;

          g_assert (G_UDEV_IS_DEVICE (device));
          g_assert (g_strcmp0 (g_udev_device_get_subsystem (device), "usb") == 0);

          if (!filters_match_device (sender_info->filters, device))
            continue;

          g_message ("  B1");

          device_variant = gudev_device_to_variant (self, sender_info->filters, device);
          g_variant_builder_add (&devices_builder, "(ss@a{sv})", "add", id, g_steal_pointer (&device_variant));

          g_message ("  B2");

          g_hash_table_add (usb_session->available_devices, g_strdup (id));
        }

      g_message ("C");

      g_dbus_connection_emit_signal (session->connection,
                                     session->sender,
                                     "/org/freedesktop/portal/desktop",
                                     "org.freedesktop.portal.Usb",
                                     "DeviceEvents",
                                     g_variant_new ("(o@a(ssa{sv}))",
                                                    session->id,
                                                    g_variant_builder_end (&devices_builder)),
                                     NULL);
    }

  return G_DBUS_METHOD_INVOCATION_HANDLED;
}

/* EnumerateDevices */

static XdpOptionKey usb_enumerate_devices_options[] = {
};

static gboolean
handle_enumerate_devices (XdpDbusUsb            *object,
                          GDBusMethodInvocation *invocation,
                          GVariant              *arg_options)
{
  g_autoptr(GVariant) options = NULL;
  g_autoptr(GVariant) devices = NULL;
  g_autoptr(GError) error = NULL;
  GVariantBuilder options_builder;
  Permission permission;
  Call *call;
  Usb *self;

  self = (Usb *) object;
  call = call_from_invocation (invocation);

  permission = get_permission_sync (xdp_app_info_get_id (call->app_info),
                                    PERMISSION_TABLE,
                                    PERMISSION_ID);

  if (permission == PERMISSION_NO)
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

  /* List devices the app has permission */
    {
      g_autoptr(UsbSenderInfo) sender_info = NULL;
      GVariantBuilder builder;
      GHashTableIter iter;
      GUdevDevice *device;
      const char *id;

      sender_info = usb_sender_info_from_call (self, call);
      g_assert (sender_info->filters != NULL);

      g_variant_builder_init (&builder, G_VARIANT_TYPE ("a(sa{sv})"));

      g_hash_table_iter_init (&iter, self->ids_to_devices);
      while (g_hash_table_iter_next (&iter, (gpointer *) &id, (gpointer *) &device))
        {
          g_assert (G_UDEV_IS_DEVICE (device));
          g_assert (g_strcmp0 (g_udev_device_get_subsystem (device), "usb") == 0);

          if (filters_match_device (sender_info->filters, device))
            g_variant_builder_add (&builder, "(s@a{sv})", id, gudev_device_to_variant (self, sender_info->filters, device));
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
  g_autoptr(UsbSenderInfo) sender_info = NULL;
  g_autoptr(GVariantIter) devices_iter = NULL;
  g_auto(GVariantBuilder) results_builder;
  g_autoptr (GVariant) results = NULL;
  g_autoptr(Request) request = data;
  g_autoptr(GError) error = NULL;
  GVariant *options;
  const char *device_id;

  REQUEST_AUTOLOCK (request);

  response = XDG_DESKTOP_PORTAL_RESPONSE_OTHER;
  sender_info = usb_sender_info_from_request (usb, request);

  g_assert (sender_info != NULL);
  g_assert (sender_info->sender_state == USB_SENDER_STATE_ACQUIRING_DEVICES);
  g_assert (sender_info->acquiring_devices == NULL);

  g_variant_builder_init (&results_builder, G_VARIANT_TYPE_VARDICT);

  xdp_dbus_impl_usb_call_acquire_devices_finish (usb_impl, &response, &results, result, &error);

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

  sender_info->acquiring_devices = g_ptr_array_new_full (g_variant_iter_n_children (devices_iter),
                                                         usb_device_acquire_data_free);
  while (g_variant_iter_next (devices_iter, "(&s@a{sv})", &device_id, &options))
    {
      g_autoptr(UsbDeviceAcquireData) access_data = NULL;
      gboolean writable;

      if (!g_variant_lookup (options, "writable", "b", &writable))
        writable = FALSE;

      access_data = g_new0 (UsbDeviceAcquireData, 1);
      access_data->device_id = g_strdup (device_id);
      access_data->writable = writable;

      g_ptr_array_add (sender_info->acquiring_devices, g_steal_pointer (&access_data));

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
filter_access_devices (Usb       *self,
                       Request   *request,
                       GVariant  *devices,
                       GVariant **out_filtered_devices,
                       GError   **out_error)
{
  g_autoptr(UsbSenderInfo) sender_info = NULL;
  GVariantBuilder filtered_devices_builder;
  GVariantIter *device_options_iter;
  GVariantIter devices_iter;
  const char *device_id;
  size_t n_devices;

  g_assert (self != NULL);
  g_assert (request != NULL);
  g_assert (devices != NULL);
  g_assert (out_filtered_devices != NULL && *out_filtered_devices == NULL);
  g_assert (out_error != NULL && *out_error == NULL);

  n_devices = g_variant_iter_init (&devices_iter, devices);

  if (n_devices == 0)
    {
      g_set_error (out_error,
                   XDG_DESKTOP_PORTAL_ERROR,
                   XDG_DESKTOP_PORTAL_ERROR_INVALID_ARGUMENT,
                   "No devices in the devices array");
      return FALSE;
    }

  sender_info = usb_sender_info_from_request (self, request);
  g_assert (sender_info != NULL);

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
      if (!filters_match_device (sender_info->filters, device))
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

      device_variant = gudev_device_to_variant (self, sender_info->filters, device);

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
handle_acquire_devices (XdpDbusUsb            *object,
                        GDBusMethodInvocation *invocation,
                        const char            *arg_parent_window,
                        GVariant              *arg_devices,
                        GVariant              *arg_options)
{
  g_autoptr(XdpDbusImplRequest) impl_request = NULL;
  g_autoptr(GVariant) filtered_devices = NULL;
  g_autoptr(GVariant) options = NULL;
  g_autoptr(GError) error = NULL;
  GVariantBuilder options_builder;
  Permission permission;
  Request *request;
  Usb *self;

  self = (Usb *) object;
  request = request_from_invocation (invocation);

  g_debug ("[usb] Handling AccessDevices");

  REQUEST_AUTOLOCK (request);

  permission = get_permission_sync (xdp_app_info_get_id (request->app_info),
                                    PERMISSION_TABLE,
                                    PERMISSION_ID);
  if (permission == PERMISSION_NO)
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
  if (!filter_access_devices (self, request, arg_devices, &filtered_devices, &error))
    {
      g_dbus_method_invocation_return_gerror (invocation, error);
      return G_DBUS_METHOD_INVOCATION_HANDLED;
    }

  request_set_impl_request (request, impl_request);
  request_export (request, g_dbus_method_invocation_get_connection (invocation));

  xdp_dbus_impl_usb_call_acquire_devices (usb_impl,
                                          request->id,
                                          arg_parent_window,
                                          xdp_app_info_get_id (request->app_info),
                                          g_steal_pointer (&filtered_devices),
                                          g_steal_pointer (&options),
                                          NULL,
                                          usb_access_devices_cb,
                                          g_object_ref (request));

  xdp_dbus_usb_complete_acquire_devices (object, invocation, request->id);

  return G_DBUS_METHOD_INVOCATION_HANDLED;
}

/* FinishAccessDevices */

#define MAX_DEVICES 8

static gboolean
handle_finish_acquire_devices (XdpDbusUsb            *object,
                               GDBusMethodInvocation *invocation,
                               GVariant              *arg_options)
{
  g_autoptr(UsbSenderInfo) sender_info = NULL;
  g_autoptr(GUnixFDList) fds = NULL;
  GVariantBuilder results_builder;
  Permission permission;
  uint32_t accessed_devices;
  gboolean finished;
  Call *call;
  Usb *self;

  self = (Usb *) object;
  call = call_from_invocation (invocation);

  g_debug ("[usb] Handling FinishAccessDevices");

  sender_info = usb_sender_info_from_call (self, call);
  g_assert (sender_info != NULL);

  permission = get_permission_sync (xdp_app_info_get_id (call->app_info),
                                    PERMISSION_TABLE,
                                    PERMISSION_ID);
  if (permission == PERMISSION_NO)
    {
      /* If permission was revoken in between D-Bus calls, reset state */
      sender_info->sender_state = USB_SENDER_STATE_DEFAULT;
      g_clear_pointer (&sender_info->acquiring_devices, g_ptr_array_unref);

      g_dbus_method_invocation_return_error (invocation,
                                             XDG_DESKTOP_PORTAL_ERROR,
                                             XDG_DESKTOP_PORTAL_ERROR_NOT_ALLOWED,
                                             "Not allowed to access USB devices");
      return G_DBUS_METHOD_INVOCATION_HANDLED;
    }

  g_assert (sender_info->sender_state == USB_SENDER_STATE_ACQUIRING_DEVICES);
  g_assert (sender_info->acquiring_devices != NULL);

  fds = g_unix_fd_list_new ();

  g_variant_builder_init (&results_builder, G_VARIANT_TYPE ("a(sa{sv})"));

  accessed_devices = 0;
  while (accessed_devices < MAX_DEVICES &&
         sender_info->acquiring_devices->len > 0)
    {
      g_autoptr(UsbDeviceAcquireData) access_data = NULL;
      g_autoptr(GError) error = NULL;
      xdp_autofd int fd = -1;
      GVariantDict dict;
      GUdevDevice *device;
      const char *device_file;
      int fd_index;

      g_variant_dict_init (&dict, NULL);

      access_data = g_ptr_array_steal_index (sender_info->acquiring_devices, 0);
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
      g_assert (device_file != NULL);

      /* Can the app even request this device? */
      if (!filters_match_device (sender_info->filters, device))
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

      if (error)
        {
          g_variant_dict_insert (&dict, "success", "b", FALSE);
          g_variant_dict_insert (&dict, "error", "s", error->message);
          g_variant_builder_add (&results_builder, "(s@a{sv})",
                                 access_data->device_id,
                                 g_variant_dict_end (&dict));
          continue;
        }

      /* This sender now owns this device */
      usb_sender_info_acquire_device (sender_info,
                                      access_data->device_id,
                                      xdp_steal_fd (&fd));

      g_variant_dict_insert (&dict, "success", "b", TRUE);
      g_variant_dict_insert (&dict, "fd", "h", fd_index);
      g_variant_builder_add (&results_builder, "(s@a{sv})",
                             access_data->device_id,
                             g_variant_dict_end (&dict));

      accessed_devices++;
    }

  finished = sender_info->acquiring_devices->len == 0;

  if (finished)
    {
      sender_info->sender_state = USB_SENDER_STATE_DEFAULT;
      g_clear_pointer (&sender_info->acquiring_devices, g_ptr_array_unref);
    }

  g_dbus_method_invocation_return_value_with_unix_fd_list (invocation,
                                                           g_variant_new ("(@a(sa{sv})b)",
                                                                          g_variant_builder_end (&results_builder),
                                                                          finished),
                                                           g_steal_pointer (&fds));

  return G_DBUS_METHOD_INVOCATION_HANDLED;
}

/* ReleaseDevice */

static XdpOptionKey usb_release_devices_options[] = {
};

static gboolean
handle_release_devices (XdpDbusUsb            *object,
                        GDBusMethodInvocation *invocation,
                        const char * const    *arg_devices,
                        GVariant              *arg_options)
{
  g_autoptr(UsbSenderInfo) sender_info = NULL;
  g_autoptr(GVariant) options = NULL;
  g_autoptr(GError) error = NULL;
  GVariantBuilder options_builder;
  Call *call;
  Usb *self;

  self = (Usb *) object;
  call = call_from_invocation (invocation);

  g_debug ("[usb] Handling ReleaseDevices");

  g_variant_builder_init (&options_builder, G_VARIANT_TYPE_VARDICT);
  if (!xdp_filter_options (arg_options,
                           &options_builder,
                           usb_release_devices_options,
                           G_N_ELEMENTS (usb_release_devices_options),
                           &error))
    {
      g_dbus_method_invocation_return_gerror (invocation, error);
      return G_DBUS_METHOD_INVOCATION_HANDLED;
    }
  options = g_variant_builder_end (&options_builder);

  sender_info = usb_sender_info_from_call (self, call);
  g_assert (sender_info != NULL);

  for (size_t i = 0; arg_devices && arg_devices[i]; i++)
    usb_sender_info_release_device (sender_info, arg_devices[i]);

  xdp_dbus_usb_complete_release_devices (object, invocation);

  return G_DBUS_METHOD_INVOCATION_HANDLED;
}

static void
usb_iface_init (XdpDbusUsbIface *iface)
{
  iface->handle_create_session = handle_create_session;
  iface->handle_enumerate_devices = handle_enumerate_devices;
  iface->handle_acquire_devices = handle_acquire_devices;
  iface->handle_finish_acquire_devices = handle_finish_acquire_devices;
  iface->handle_release_devices = handle_release_devices;
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
  self->sender_infos = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, usb_sender_info_unref);

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

      if (!is_gudev_device_suitable (device))
        continue;

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

void
usb_revoke_devices_from_sender (const char *sender)
{
  if (usb && g_hash_table_remove (usb->sender_infos, sender))
    g_debug ("Revoked acquired USB devices from sender %s", sender);
}
