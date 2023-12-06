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

#include <locale.h>
#include <stdio.h>

#include <gio/gio.h>
#include <glib/gi18n.h>

#ifdef HAVE_GUDEV
#include <gudev/gudev.h>
#endif

#include "xdp-devices-filter.h"

static const struct
{
  const char *command_name;
  const char *description;
  const char *synopsis;
} command_help_data[] = {
  { "help", N_("Print help"), "[COMMAND]" },
  { "list-filters", N_("List devices filters installed by applications"), NULL },
  { "match", N_("Match connected devices against an application"), "[APPID]" },
  { "validate", N_("Validate a devices JSON file"), "[FILE]" },
};

static gboolean
command_help (int      argc,
              char    *argv[],
              GError **error)
{
  g_assert (argc >= 2);

  if (argc == 2)
    {
      g_print (_("Usage:\n"
                 "  xdg-desktop-portal-devices [--verbose] COMMAND [ARGS…]\n"
                 "\n"
                 "Commands:\n"));

      for (size_t i = 0; i < G_N_ELEMENTS (command_help_data); i++)
        g_print ("  %-20s  %s\n", command_help_data[i].command_name, _(command_help_data[i].description));

      g_print ("\n%s\n\n", _("Use “xdg-desktop-portal-devices help COMMAND” to get detailed help."));
    }
  else
    {
      size_t i;

      for (i = 0; i < G_N_ELEMENTS (command_help_data); i++)
        {
          if (g_strcmp0 (argv[2], command_help_data[i].command_name) == 0)
            break;
        }

      if (i >= G_N_ELEMENTS (command_help_data))
        return FALSE;

      g_print (_("Usage:\n"
                 "  xdg-desktop-portal-devices [--verbose] %s %s\n"
                 "\n"
                 "%s\n"
                 "\n"),
               command_help_data[i].command_name,
               command_help_data[i].synopsis ? _(command_help_data[i].synopsis) : "",
               _(command_help_data[i].description));
    }

  return TRUE;
}

static gboolean
command_list_filters (int      argc,
                      char    *argv[],
                      GError **error)
{
  const char * const *system_datadirs = g_get_system_data_dirs ();

  for (size_t i = 0; system_datadirs && system_datadirs[i]; i++)
    {
      g_autoptr(GFileEnumerator) enumerator = NULL;
      g_autoptr(GError) local_error = NULL;
      g_autoptr(GFile) directory = NULL;
      g_autofree char *path = NULL;

      path = g_build_filename (system_datadirs[i], "xdg-desktop-portal", "devices", NULL);
      directory = g_file_new_for_path (path);
      g_print ("%s:\n", path);

      enumerator = g_file_enumerate_children (directory,
                                              G_FILE_ATTRIBUTE_STANDARD_NAME,
                                              G_FILE_QUERY_INFO_NONE,
                                              NULL,
                                              &local_error);

      if (local_error)
        {
          g_print ("  %s", _("(No device filters)\n\n"));
          continue;
        }

      do
        {
          g_autoptr(XdpDevicesFilter) devices_filter = NULL;
          g_autofree char *filter_string = NULL;
          GFile *child;

          if (!g_file_enumerator_iterate (enumerator, NULL, &child, NULL, &local_error))
            {
              g_warning ("Failed to enumerate directory: %s", local_error->message);
              break;
            }

          if (!child)
            break;

          devices_filter = xdp_devices_filter_new (child, &local_error);
          if (local_error)
            {
              g_warning ("File %s is not a valid devices filter: %s",
                         g_file_peek_path (child),
                         local_error->message);
              break;
            }

          filter_string = xdp_devices_filter_to_string (devices_filter);
          g_print ("%s\n", filter_string);
        }
      while (TRUE);
    }

  return TRUE;
}

static gboolean
command_match (int      argc,
               char    *argv[],
               GError **error)
{
#ifdef HAVE_GUDEV
  g_autolist(GUdevDevice) devices = NULL;
  g_autoptr(GUdevClient) client = NULL;
  g_autoptr(GPtrArray) devices_to_match = NULL;
  g_autoptr(GPtrArray) matched_devices = NULL;
  g_autoptr(GPtrArray) devices_filters = NULL;
  const char *app_id;

  if (argc != 3)
    {
      g_set_error (error, G_OPTION_ERROR, G_OPTION_ERROR_FAILED, "Invalid usage");
      return FALSE;
    }

  /* Initialize devices */
  devices_to_match = g_ptr_array_new_with_free_func (g_object_unref);
  client = g_udev_client_new ((const gchar *const []) {"usb", NULL});
  devices = g_udev_client_query_by_subsystem (client, NULL);
  for (GList *l = devices; l; l = l->next)
    {
      GUdevDevice *device = l->data;
      const char *device_file;

      g_assert (G_UDEV_IS_DEVICE (device));

      device_file = g_udev_device_get_device_file (device);
      if (!device_file)
        continue;

      g_ptr_array_add (devices_to_match, g_object_ref (device));
    }

  app_id = argv[2];
  devices_filters = xdp_devices_filter_get_all_for_app_id (app_id);
  g_assert (devices_filters != NULL);

  matched_devices = g_ptr_array_new_with_free_func (g_object_unref);

  for (size_t i = 0; i < devices_filters->len; i++)
    {
      XdpDevicesFilter *devices_filter = g_ptr_array_index (devices_filters, i);

      for (size_t i = 0; i < devices_to_match->len; i++)
        {
          GUdevDevice *device = g_ptr_array_index (devices_to_match, i);
          if (xdp_devices_filter_match_device (devices_filter, device) &&
              !g_ptr_array_find (matched_devices, device, NULL))
            g_ptr_array_add (matched_devices, g_object_ref (device));
        }
    }

  if (matched_devices->len > 0)
    {
      g_print ("\nThe following connected devices are available to %s:\n", app_id);
      for (size_t i = 0; i < matched_devices->len; i++)
        {
          GUdevDevice *device = g_ptr_array_index (matched_devices, i);
          const char *property;

          g_print (" *");

          property = g_udev_device_get_sysfs_attr (device, "manufacturer");
          if (!property)
            property = g_udev_device_get_property (device, "ID_VENDOR");
          if (!property)
            property = g_udev_device_get_property (device, "ID_USB_VENDOR");
          if (property)
            g_print (" %s", property);

          property = g_udev_device_get_sysfs_attr (device, "product");
          if (!property)
            property = g_udev_device_get_property (device, "ID_MODEL");
          if (!property)
            property = g_udev_device_get_property (device, "ID_USB_MODEL");
          if (property)
            g_print (" %s", property);

          property = g_udev_device_get_sysfs_attr (device, "serial");
          if (!property)
            property = g_udev_device_get_property (device, "ID_SERIAL");
          if (!property)
            property = g_udev_device_get_property (device, "ID_SERIAL_SHORT");
          if (property)
            g_print (" %s", property);

          if (!property)
            g_print ("%s", g_udev_device_get_sysfs_path (device));

          g_print (" (%s) \n", g_udev_device_get_subsystem (device));
        }
      g_print ("\n");
    }
  else
    {
      g_print ("\n");
      g_print (_("No connected devices match application %s"), app_id);
      g_print ("\n\n");
    }

  return TRUE;
#else
  return FALSE;
#endif
}

static gboolean
command_validate (int      argc,
                  char    *argv[],
                  GError **error)
{
  int n_files = argc - 2;

  if (n_files < 1)
    {
      g_set_error (error, G_OPTION_ERROR, G_OPTION_ERROR_FAILED, "Invalid usage");
      return FALSE;
    }

  g_print ("\n");
  g_print (_("Validating files:"));
  g_print ("\n");

  for (int i = 0; i < n_files; i++)
    {
      g_autoptr(XdpDevicesFilter) devices_filter = NULL;
      g_autoptr(GError) local_error = NULL;
      g_autofree char *basename = NULL;
      g_autoptr(GFile) file = NULL;

      file = g_file_new_for_commandline_arg (argv[i + 2]);
      basename = g_file_get_basename (file);

      devices_filter = xdp_devices_filter_new (file, &local_error);
      if (local_error)
        g_print (_(" * %s: error: %s"), basename, local_error->message);
      else
        g_print (_(" * %s: ok"), basename);

      g_print ("\n");
    }

  g_print ("\n");

  return TRUE;
}

typedef struct
{
  const char *name;

  gboolean (*fn) (int      argc,
                  char    *argv[],
                  GError **error);
} Command;

static Command commands[] = {
  { "help", command_help },
  { "list-filters", command_list_filters },
  { "match", command_match },
  { "validate", command_validate },
};

static gboolean opt_verbose;

static GOptionEntry entries[] = {
  { "verbose", 'v', 0, G_OPTION_ARG_NONE, &opt_verbose, "Print debug information during command processing", NULL },
  { NULL }
};

static void
message_handler (const gchar   *log_domain,
                 GLogLevelFlags log_level,
                 const gchar   *message,
                 gpointer       user_data)
{
  /* Make this look like normal console output */
  if (log_level & G_LOG_LEVEL_DEBUG)
    fprintf (stderr, "xdp-devices: %s\n", message);
  else
    fprintf (stderr, "%s: %s\n", g_get_prgname (), message);
}

static void
printerr_handler (const gchar *string)
{
  int is_tty = isatty (1);
  const char *prefix = "";
  const char *suffix = "";
  if (is_tty)
    {
      prefix = "\x1b[31m\x1b[1m"; /* red, bold */
      suffix = "\x1b[22m\x1b[0m"; /* bold off, color reset */
    }
  fprintf (stderr, "%serror: %s%s\n", prefix, suffix, string);
}

static const Command *
find_command (int      argc,
              char    *argv[],
              GError **error)
{
  if (argc < 2)
    {
      g_set_error (error, G_OPTION_ERROR, G_OPTION_ERROR_FAILED, _("No command specified"));
      return NULL;
    }

  for (size_t i = 0; i < G_N_ELEMENTS (commands); i++)
    {
      const Command *command = &commands[i];

      if (g_strcmp0 (argv[1], command->name) == 0)
        return command;
    }

  g_set_error (error, G_OPTION_ERROR, G_OPTION_ERROR_FAILED, _("Command \"%s\" not found"), argv[1]);
  return NULL;
}

int
main (int   argc,
      char *argv[])
{
  g_autoptr(GOptionContext) context = NULL;
  g_autoptr(GError) error = NULL;
  const Command *command;

  setlocale (LC_ALL, "");
  bindtextdomain (GETTEXT_PACKAGE, LOCALEDIR);
  bind_textdomain_codeset (GETTEXT_PACKAGE, "UTF-8");
  textdomain (GETTEXT_PACKAGE);

  g_set_printerr_handler (printerr_handler);
  if (opt_verbose)
    g_log_set_handler (G_LOG_DOMAIN, G_LOG_LEVEL_DEBUG, message_handler, NULL);
  g_set_prgname (argv[0]);

  context = g_option_context_new ("- device utility for XDG Desktop Portal");
  g_option_context_set_strict_posix (context, TRUE);
  g_option_context_set_summary (context, "Utilitary tool for XDG Desktop Portal device management.");
  g_option_context_add_main_entries (context, entries, NULL);
  if (!g_option_context_parse (context, &argc, &argv, &error))
    {
      g_printerr ("%s: %s\n", g_get_application_name (), error->message);
      g_print ("Try \"%s --help\" for more information.\n", g_get_prgname ());
      return 1;
    }

  command = find_command (argc, argv, &error);
  if (error)
    {
      g_printerr ("%s: %s\n", g_get_application_name (), error->message);
      g_print ("Try \"%s --help\" for more information.\n", g_get_prgname ());
      return 1;
    }

  if (!command->fn (argc, argv, &error))
    {
      g_printerr ("%s: %s\n", g_get_application_name (), error->message);
      g_print ("Try \"%s --help\" for more information.\n", g_get_prgname ());
      return 1;
    }

  return 0;
}
