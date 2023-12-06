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

#include "config.h"

#include "xdp-devices-filter.h"

#include <glib/gi18n.h>
#include <json-glib/json-glib.h>
#include <stdint.h>

#ifdef HAVE_GUDEV
#include <gudev/gudev.h>
#endif

#define MAX_VERSION 1

/* TODO:
 *
 * - Add tests, lots of them
 *
 */

struct _XdpDevicesFilter
{
  GObject parent_instance;

  GFile *file;

  int64_t version;
  GPtrArray *usb_filters;
};

static void g_initable_iface_init (GInitableIface *iface);

G_DEFINE_FINAL_TYPE_WITH_CODE (XdpDevicesFilter, xdp_devices_filter, G_TYPE_OBJECT,
                               G_IMPLEMENT_INTERFACE (G_TYPE_INITABLE, g_initable_iface_init))

enum {
  PROP_0,
  PROP_VERSION,
  N_PROPS,
};

static GParamSpec *properties [N_PROPS] = { NULL, };

typedef struct
{
  gboolean has_vendor_id;
  uint16_t vendor_id;

  gboolean has_product_ids;
  GArray *product_ids;
} UsbFilter;

static void
usb_filter_free (gpointer data)
{
  UsbFilter *filter = (UsbFilter *)data;

  if (!filter)
    return;

  g_clear_pointer (&filter->product_ids, g_array_unref);
  g_free (filter);
}

G_DEFINE_AUTOPTR_CLEANUP_FUNC (UsbFilter, usb_filter_free)

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
parse_vendor_id (UsbFilter  *usb_filter,
                 JsonNode   *node,
                 GError    **error)
{
  const char *vendor_id;
  GValue value = G_VALUE_INIT;

  if (!JSON_NODE_HOLDS_VALUE (node))
    {
      g_set_error (error, JSON_PARSER_ERROR, JSON_PARSER_ERROR_INVALID_DATA,
                   "USB filter member \"vendor-id\" has an invalid value");
      return FALSE;
    }

  /* TODO: is g_value_type_compatible() appropriate here? */
  json_node_get_value (node, &value);
  if (!g_value_type_compatible (G_VALUE_TYPE (&value), G_TYPE_STRING))
    {
      g_set_error (error, JSON_PARSER_ERROR, JSON_PARSER_ERROR_INVALID_DATA,
                   "Member \"vendor-id\" has incompatible type");
      return FALSE;
    }

  vendor_id = g_value_get_string (&value);
  if (!hex_to_uint16 (vendor_id, &usb_filter->vendor_id))
    {
      g_set_error (error, JSON_PARSER_ERROR, JSON_PARSER_ERROR_INVALID_DATA,
                   "USB filter member \"vendor-id\" has an invalid value");
      return FALSE;
    }

  usb_filter->has_vendor_id = TRUE;
  return TRUE;
}

static gboolean
parse_product_id (UsbFilter  *usb_filter,
                  JsonNode   *node,
                  GError    **error)
{
  const char *product_id_string;
  uint16_t product_id;
  GValue value = G_VALUE_INIT;

  /* TODO: is g_value_type_compatible() appropriate here? */
  json_node_get_value (node, &value);
  if (!g_value_type_compatible (G_VALUE_TYPE (&value), G_TYPE_STRING))
    {
      g_set_error (error, JSON_PARSER_ERROR, JSON_PARSER_ERROR_INVALID_DATA,
                   "Member \"product-id\" has incompatible type");
      return FALSE;
    }

  product_id_string = g_value_get_string (&value);
  if (!hex_to_uint16 (product_id_string, &product_id))
    {
      g_set_error (error, JSON_PARSER_ERROR, JSON_PARSER_ERROR_INVALID_DATA,
                   "USB filter member \"product-id\" has an invalid value");
      return FALSE;
    }

  usb_filter->has_product_ids = TRUE;
  if (!usb_filter->product_ids)
    usb_filter->product_ids = g_array_new (FALSE, FALSE, sizeof (uint16_t));
  g_array_append_val (usb_filter->product_ids, product_id);
  return TRUE;
}
static UsbFilter *
usb_filter_from_json_object (JsonObject  *object,
                             GError     **error)
{
  g_autoptr(UsbFilter) filter = NULL;

  filter = g_new0 (UsbFilter, 1);

  if (json_object_has_member (object, "vendor-id"))
    {
      JsonNode *vendor_id_node = json_object_get_member (object, "vendor-id");

      if (!parse_vendor_id (filter, vendor_id_node, error))
        return NULL;
    }

  if (json_object_has_member (object, "product-id"))
    {
      JsonNode *product_id_node = json_object_get_member (object, "product-id");

      if (JSON_NODE_HOLDS_VALUE (product_id_node))
        {
          JsonNode *vendor_id_node = json_object_get_member (object, "product-id");

          if (!parse_product_id (filter, vendor_id_node, error))
            return NULL;
        }
      else if (JSON_NODE_HOLDS_ARRAY (product_id_node))
        {
          JsonArray *array = json_node_get_array (product_id_node);
          unsigned int n_elements = json_array_get_length (array);

          for (unsigned int i = 0; i < n_elements; i++)
            {
              JsonNode *element = json_array_get_element (array, i);
              if (!parse_product_id (filter, element, error))
                return NULL;
            }
        }
      else
        {
          g_set_error (error, JSON_PARSER_ERROR, JSON_PARSER_ERROR_INVALID_DATA,
                       "Member \"product-id\" has incompatible type");
          return NULL;
        }
    }

  if (filter->has_product_ids && !filter->has_vendor_id)
    {
      g_set_error (error, JSON_PARSER_ERROR, JSON_PARSER_ERROR_INVALID_DATA,
                   "Cannot have \"product-id\" without \"vendor-id\"");
      return NULL;
    }

  return g_steal_pointer (&filter);
}

#ifdef HAVE_GUDEV
static gboolean
usb_filter_match_device (UsbFilter   *usb_filter,
                         GUdevDevice *device)
{
  const char *product_id_str = NULL;
  const char *vendor_id_str = NULL;
  gboolean device_has_product_id = FALSE;
  gboolean device_has_vendor_id = FALSE;
  uint16_t device_product_id;
  uint16_t device_vendor_id;

  g_assert (usb_filter != NULL);
  g_assert (g_strcmp0 (g_udev_device_get_subsystem (device), "usb") == 0);

  vendor_id_str = g_udev_device_get_property (device, "ID_VENDOR_ID");
  if (vendor_id_str != NULL && hex_to_uint16 (vendor_id_str, &device_vendor_id))
    device_has_vendor_id = TRUE;

  if (usb_filter->has_vendor_id &&
      (!device_has_vendor_id || usb_filter->vendor_id != device_vendor_id))
    return FALSE;

  product_id_str = g_udev_device_get_property (device, "ID_MODEL_ID");
  if (product_id_str != NULL && hex_to_uint16 (product_id_str, &device_product_id))
    device_has_product_id = TRUE;

  if (usb_filter->has_product_ids)
    {
      gboolean matched_any = FALSE;

      if (!device_has_product_id)
        return FALSE;

      for (size_t i = 0; i < usb_filter->product_ids->len; i++)
        {
          uint16_t filter_product_id = g_array_index (usb_filter->product_ids, uint16_t, i);

          if (filter_product_id == device_product_id)
            {
              matched_any = TRUE;
              break;
            }
        }

      if (!matched_any)
        return FALSE;
    }

  return TRUE;
}
#endif

static char *
usb_filter_to_string (UsbFilter *usb_filter)
{
  GString *string;

  g_assert (usb_filter != NULL);

  string = g_string_new (NULL);

  if (usb_filter->has_vendor_id)
    g_string_append_printf (string, "vendor-id: 0x%.4x, ", usb_filter->vendor_id);

  if (usb_filter->has_product_ids)
    {
      g_assert (usb_filter->product_ids != NULL);

      g_string_append (string, "product-id: ");
      for (size_t i = 0; i < usb_filter->product_ids->len; i++)
        {
          uint16_t product_id = g_array_index (usb_filter->product_ids, uint16_t, i);
          if (i != 0)
            g_string_append (string, ",");
          g_string_append_printf (string, "0x%.4x", product_id);
        }
      g_string_append (string, ", ");
    }

  if (usb_filter->has_vendor_id || usb_filter->has_product_ids)
    g_string_truncate (string, string->len - 2);
  else
    g_string_append (string, _("(empty filter)"));

  return g_string_free (string, FALSE);
}

/* JSON Parser / Validator */

typedef struct
{
  const char *member_name;
  gboolean (*parse_func) (XdpDevicesFilter  *self,
                          JsonNode          *node,
                          GError           **error);
} ParserEntry;

static gboolean
parse_json_object (XdpDevicesFilter   *self,
                   JsonNode           *node,
                   const ParserEntry  *entries,
                   size_t              n_entries,
                   GError            **error)
{
  g_autoptr(GHashTable) visited_members = NULL;
  JsonObjectIter iter;
  JsonObject *object;
  const char *key;

  if (!JSON_NODE_HOLDS_OBJECT (node))
    {
      g_set_error (error, JSON_PARSER_ERROR, JSON_PARSER_ERROR_INVALID_DATA,
                   "Root node must be a dictionary");
      return FALSE;
    }

  visited_members = g_hash_table_new (g_str_hash, g_str_equal);
  object = json_node_get_object (node);
  for (size_t i = 0; i < n_entries; i++)
    {
      const ParserEntry *entry = &entries[i];
      JsonNode *value;

      if (!json_object_has_member (object, entry->member_name))
        {
          g_set_error (error, JSON_PARSER_ERROR, JSON_PARSER_ERROR_INVALID_DATA,
                       "Required member \"%s\" not found", entry->member_name);
          return FALSE;
        }

      value = json_object_get_member (object, entry->member_name);

      if (!entry->parse_func (self, value, error))
        return FALSE;

      g_hash_table_add (visited_members, (gpointer) entry->member_name);
    }

  json_object_iter_init (&iter, object);
  while (json_object_iter_next (&iter, &key, NULL))
    {
      if (!g_hash_table_contains (visited_members, key))
        {
          g_set_error (error, JSON_PARSER_ERROR, JSON_PARSER_ERROR_INVALID_DATA,
                       "Unrecognized element \"%s\"", key);
          return FALSE;
        }
    }

  return TRUE;
}

static gboolean
parse_individual_usb_filter (XdpDevicesFilter  *self,
                             JsonNode          *node,
                             GError           **error)
{
  g_autoptr(UsbFilter) usb_filter = NULL;
  JsonObject *object;

  if (!JSON_NODE_HOLDS_OBJECT (node))
    {
      g_set_error (error, JSON_PARSER_ERROR, JSON_PARSER_ERROR_INVALID_DATA,
                   "USB filter must be a dictionary");
      return FALSE;
    }

  object = json_node_get_object (node);
  usb_filter = usb_filter_from_json_object (object, error);
  if (!usb_filter)
    return FALSE;

  g_ptr_array_add (self->usb_filters, g_steal_pointer (&usb_filter));
  return TRUE;
}

static gboolean
parse_usb_filters (XdpDevicesFilter  *self,
                   JsonNode          *node,
                   GError           **error)
{
  unsigned int n_elements;
  JsonArray *array;

  if (!JSON_NODE_HOLDS_ARRAY (node))
    {
      g_set_error (error, JSON_PARSER_ERROR, JSON_PARSER_ERROR_INVALID_DATA,
                   "Member \"usb\" has incompatible type");
      return FALSE;
    }

  array = json_node_get_array (node);
  n_elements = json_array_get_length (array);
  for (unsigned int i = 0; i < n_elements; i++)
    {
      JsonNode *element = json_array_get_element (array, i);

      if (!parse_individual_usb_filter (self, element, error))
        return FALSE;
    }

  return TRUE;
}

static const ParserEntry device_filter_entries[] = {
  { "usb", parse_usb_filters },
};

static gboolean
parse_device_filters (XdpDevicesFilter  *self,
                      JsonNode          *node,
                      GError           **error)
{
  if (!JSON_NODE_HOLDS_OBJECT (node))
    {
      g_set_error (error, JSON_PARSER_ERROR, JSON_PARSER_ERROR_INVALID_DATA,
                   "Member \"device-filters\" has incompatible type");
      return FALSE;
    }

  return parse_json_object (self, node,
                            device_filter_entries,
                            G_N_ELEMENTS (device_filter_entries),
                            error);
}

static gboolean
parse_version (XdpDevicesFilter  *self,
               JsonNode          *node,
               GError           **error)
{
  GValue value = G_VALUE_INIT;
  int64_t version;

  if (!JSON_NODE_HOLDS_VALUE (node))
    {
      g_set_error (error, JSON_PARSER_ERROR, JSON_PARSER_ERROR_INVALID_DATA,
                   "Member \"version\" has incompatible type");
      return FALSE;
    }

  json_node_get_value (node, &value);

  if (!g_value_type_compatible (G_VALUE_TYPE (&value), G_TYPE_INT64))
    {
      g_set_error (error, JSON_PARSER_ERROR, JSON_PARSER_ERROR_INVALID_DATA,
                   "Member \"version\" has incompatible type");
      return FALSE;
    }

  version = g_value_get_int64 (&value);
  if (version < 1 || version > MAX_VERSION)
    {
      g_set_error (error, JSON_PARSER_ERROR, JSON_PARSER_ERROR_INVALID_DATA,
                   "Incompatible version");
      return FALSE;
    }

  self->version = version;

  return TRUE;
}

static const ParserEntry root_entries[] = {
  { "version", parse_version },
  { "device-filters", parse_device_filters },
};

static inline gboolean
parse_json_tree (XdpDevicesFilter  *self,
                 JsonNode          *root,
                 GError           **error)
{
  return parse_json_object (self, root,
                            root_entries,
                            G_N_ELEMENTS (root_entries),
                            error);
}

static gboolean
xdp_devices_filter_initable_init (GInitable     *initable,
                                  GCancellable  *cancellable,
                                  GError       **error)
{
  XdpDevicesFilter *self = XDP_DEVICES_FILTER (initable);
  g_autoptr(JsonParser) parser = NULL;
  g_autoptr(JsonNode) root = NULL;

  g_assert (G_IS_FILE (self->file));

  parser = json_parser_new_immutable ();
  if (!json_parser_load_from_mapped_file (parser, g_file_peek_path (self->file), error))
    return FALSE;

  if (json_parser_has_assignment (parser, NULL))
    {
      g_set_error (error, JSON_PARSER_ERROR, JSON_PARSER_ERROR_INVALID_DATA,
                   "Variable assignments are not allowed");
      return FALSE;
    }

  root = json_parser_steal_root (parser);
  if (!root)
    {
      g_set_error (error, JSON_PARSER_ERROR, JSON_PARSER_ERROR_INVALID_DATA,
                   "Empty file");
      return FALSE;
    }

  return parse_json_tree (self, root, error);
}

static void
g_initable_iface_init (GInitableIface *iface)
{
  iface->init = xdp_devices_filter_initable_init;
}

static void
xdp_devices_filter_finalize (GObject *object)
{
  XdpDevicesFilter *self = (XdpDevicesFilter *)object;

  g_clear_pointer (&self->usb_filters, g_ptr_array_unref);
  g_clear_object (&self->file);

  G_OBJECT_CLASS (xdp_devices_filter_parent_class)->finalize (object);
}

static void
xdp_devices_filter_get_property (GObject    *object,
                                 guint       prop_id,
                                 GValue     *value,
                                 GParamSpec *pspec)
{
  XdpDevicesFilter *self = XDP_DEVICES_FILTER (object);

  switch (prop_id)
    {
    case PROP_VERSION:
      g_value_set_int64 (value, self->version);
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
    }
}

static void
xdp_devices_filter_set_property (GObject      *object,
                                 guint         prop_id,
                                 const GValue *value,
                                 GParamSpec   *pspec)
{
  //XdpDevicesFilter *self = XDP_DEVICES_FILTER (object);

  switch (prop_id)
    {
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
    }
}

static void
xdp_devices_filter_class_init (XdpDevicesFilterClass *klass)
{
  GObjectClass *object_class = G_OBJECT_CLASS (klass);

  object_class->finalize = xdp_devices_filter_finalize;
  object_class->get_property = xdp_devices_filter_get_property;
  object_class->set_property = xdp_devices_filter_set_property;

  properties[PROP_VERSION] =
    g_param_spec_int64 ("version", "", "",
                        1, G_MAXINT64, 1,
                        G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

  g_object_class_install_properties (object_class, N_PROPS, properties);
}

static void
xdp_devices_filter_init (XdpDevicesFilter *self)
{
  self->version = 1;
  self->usb_filters = g_ptr_array_new_with_free_func (usb_filter_free);
}

XdpDevicesFilter *
xdp_devices_filter_new (GFile   *file,
                        GError **error)
{
  g_autoptr(XdpDevicesFilter) self = NULL;

  g_return_val_if_fail (G_IS_FILE (file), NULL);
  g_return_val_if_fail (error == NULL || *error == NULL, NULL);

  self = g_object_new (XDP_TYPE_DEVICES_FILTER, NULL);
  self->file = g_object_ref (file);

  if (!g_initable_init (G_INITABLE (self), NULL, error))
    return NULL;

  return g_steal_pointer (&self);
}

GPtrArray *
xdp_devices_filter_get_all_for_app_id (const char *app_id)
{
  g_autoptr(GPtrArray) devices_filters = NULL;
  const char * const *system_datadirs;
  g_autofree char *filename = NULL;

  system_datadirs = g_get_system_data_dirs ();
  filename = g_strconcat (app_id, ".json", NULL);
  devices_filters = g_ptr_array_new_with_free_func (g_object_unref);

  for (size_t i = 0; system_datadirs && system_datadirs[i]; i++)
    {
      g_autoptr(XdpDevicesFilter) devices_filter = NULL;
      g_autoptr(GError) error = NULL;
      g_autoptr(GFile) file = NULL;
      g_autofree char *path = NULL;

      path = g_build_filename (system_datadirs[i],
                               "xdg-desktop-portal",
                               "devices",
                               filename,
                               NULL);

      if (!g_file_test (path, G_FILE_TEST_IS_REGULAR))
        continue;

      file = g_file_new_for_path (path);
      devices_filter = xdp_devices_filter_new (file, &error);
      if (error)
        {
          g_warning ("File %s is not a valid devices filter: %s",
                     g_file_peek_path (file),
                     error->message);
          break;
        }

      g_ptr_array_add (devices_filters, g_steal_pointer (&devices_filter));
    }

  return g_steal_pointer (&devices_filters);
}

gboolean
xdp_devices_filter_match_device (XdpDevicesFilter *self,
                                 gpointer          gudev_device)
{
#ifdef HAVE_GUDEV
  GUdevDevice *device = (GUdevDevice *) gudev_device;

  g_return_val_if_fail (XDP_IS_DEVICES_FILTER (self), FALSE);
  g_return_val_if_fail (G_UDEV_IS_DEVICE (device), FALSE);

  if (self->usb_filters->len == 0)
    return FALSE;

  if (g_strcmp0 (g_udev_device_get_subsystem (device), "usb") == 0)
    {
      for (size_t i = 0; i < self->usb_filters->len; i++)
        {
          UsbFilter *usb_filter = g_ptr_array_index (self->usb_filters, i);

          if (usb_filter_match_device (usb_filter, device))
            return TRUE;
        }
    }

  return FALSE;

#else
  return FALSE;
#endif
}

char *
xdp_devices_filter_to_string (XdpDevicesFilter *self)
{
  g_autofree char *basename = NULL;
  GString *string;

  g_return_val_if_fail (XDP_IS_DEVICES_FILTER (self), NULL);

  string = g_string_new (NULL);
  basename = g_file_get_basename (self->file);

  g_string_append_printf (string, " * %s:\n", basename);
  g_string_append_printf (string, "   Version: %" G_GINT64_FORMAT "\n", self->version);

  if (self->usb_filters->len > 0)
    {
      g_string_append_printf (string, "   USB filters (%u):\n", self->usb_filters->len);

      for (size_t i = 0; i < self->usb_filters->len; i++)
        {
          UsbFilter *usb_filter = g_ptr_array_index (self->usb_filters, i);
          g_autofree char *usb_filter_str = usb_filter_to_string (usb_filter);

          g_string_append_printf (string, "      %lu. %s\n", i + 1, usb_filter_str);
        }
    }

  return g_string_free (string, FALSE);
}
