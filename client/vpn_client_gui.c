#include <gtk/gtk.h>
#include <glib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/wait.h>

// GUI Widgets
static GtkWidget *entry_ip = NULL;
static GtkWidget *entry_port = NULL;
static GtkWidget *btn_start = NULL;
static GtkWidget *btn_stop = NULL;
static GtkWidget *btn_ping = NULL;
static GtkWidget *btn_dns = NULL;
static GtkWidget *btn_http = NULL;
static GtkWidget *btn_browser = NULL;
static GtkWidget *label_stats = NULL;
static GtkWidget *main_window = NULL;

// VPN process state
static GPid vpn_pid = 0;
static GIOChannel *stdout_channel = NULL;
static guint stdout_watch_id = 0;

// Forward declarations
static gboolean show_test_result(gpointer data);
static gpointer ping_test_thread(gpointer data);
static gpointer dns_test_thread(gpointer data);
static gpointer http_test_thread(gpointer data);

// Handler for vpn_client process stdout
static gboolean on_vpn_output(GIOChannel *source, GIOCondition cond, gpointer user_data) {
    gchar *line = NULL;
    GError *error = NULL;
    if (g_io_channel_read_line(source, &line, NULL, NULL, &error) == G_IO_STATUS_NORMAL) {
        if (line) {
            size_t len = strlen(line);
            if (len > 0 && line[len-1] == '\n') line[len-1] = '\0';

            if (g_str_has_prefix(line, "STATS:")) {
                gtk_label_set_text(GTK_LABEL(label_stats), line + 7);
            } else {
                g_print("%s\n", line);
            }
            g_free(line);
        }
    }
    if (cond & (G_IO_HUP | G_IO_ERR)) {
        return FALSE; // Stop watch
    }
    return TRUE;
}

// Handler for vpn_client process exit
static void on_vpn_exit(GPid pid, gint status, gpointer user_data) {
    if (stdout_watch_id) {
        g_source_remove(stdout_watch_id);
        stdout_watch_id = 0;
    }
    if (stdout_channel) {
        g_io_channel_unref(stdout_channel);
        stdout_channel = NULL;
    }
    g_spawn_close_pid(pid);
    vpn_pid = 0;

    gtk_widget_set_sensitive(btn_start, TRUE);
    gtk_widget_set_sensitive(btn_stop, FALSE);
    gtk_widget_set_sensitive(btn_ping, FALSE);
    gtk_widget_set_sensitive(btn_dns, FALSE);
    gtk_widget_set_sensitive(btn_http, FALSE);
    gtk_widget_set_sensitive(btn_browser, FALSE);

    gtk_label_set_text(GTK_LABEL(label_stats), "Disconnected.");
}

// Start VPN
static void start_vpn(GtkButton *button, gpointer user_data) {
    const gchar *ip = gtk_entry_get_text(GTK_ENTRY(entry_ip));
    const gchar *port = gtk_entry_get_text(GTK_ENTRY(entry_port));
    if (!ip || !port || strlen(ip) == 0 || strlen(port) == 0) {
        GtkWidget *dlg = gtk_message_dialog_new(GTK_WINDOW(main_window),
            GTK_DIALOG_MODAL, GTK_MESSAGE_ERROR, GTK_BUTTONS_OK,
            "Please enter Server IP and Port.");
        gtk_dialog_run(GTK_DIALOG(dlg));
        gtk_widget_destroy(dlg);
        return;
    }

    gchar *argv[] = { "./vpn_client", "vpn1", (gchar*)ip, (gchar*)port, NULL };
    GError *error = NULL;
    gint stdout_fd;

    if (!g_spawn_async_with_pipes(NULL, argv, NULL, G_SPAWN_DO_NOT_REAP_CHILD,
                                  NULL, NULL, &vpn_pid, NULL, &stdout_fd, NULL, &error)) {
        GtkWidget *dlg = gtk_message_dialog_new(GTK_WINDOW(main_window),
            GTK_DIALOG_MODAL, GTK_MESSAGE_ERROR, GTK_BUTTONS_OK,
            "Failed to start VPN Client: %s", error->message);
        gtk_dialog_run(GTK_DIALOG(dlg));
        gtk_widget_destroy(dlg);
        g_error_free(error);
        return;
    }

    stdout_channel = g_io_channel_unix_new(stdout_fd);
    g_io_channel_set_encoding(stdout_channel, NULL, NULL);
    g_io_channel_set_close_on_unref(stdout_channel, TRUE);
    stdout_watch_id = g_io_add_watch(stdout_channel, G_IO_IN | G_IO_HUP | G_IO_ERR, on_vpn_output, NULL);

    g_child_watch_add(vpn_pid, on_vpn_exit, NULL);

    gtk_widget_set_sensitive(btn_start, FALSE);
    gtk_widget_set_sensitive(btn_stop, TRUE);
    gtk_widget_set_sensitive(btn_ping, TRUE);
    gtk_widget_set_sensitive(btn_dns, TRUE);
    gtk_widget_set_sensitive(btn_http, TRUE);
    gtk_widget_set_sensitive(btn_browser, TRUE);

    gtk_label_set_text(GTK_LABEL(label_stats), "Connecting...");
}

// Stop VPN
static void stop_vpn(GtkButton *button, gpointer user_data) {
    if (vpn_pid) {
        kill(vpn_pid, SIGINT);
    }
}

// Show test result in dialog
static gboolean show_test_result(gpointer data) {
    gchar *msg = (gchar*)data;
    GtkWidget *dlg = gtk_message_dialog_new(GTK_WINDOW(main_window),
        GTK_DIALOG_MODAL, GTK_MESSAGE_INFO, GTK_BUTTONS_OK, "%s", msg);
    gtk_dialog_run(GTK_DIALOG(dlg));
    gtk_widget_destroy(dlg);
    g_free(msg);
    return FALSE;
}

// Ping Test Thread
static gpointer ping_test_thread(gpointer data) {
    system("ping -c 4 8.8.8.8 > /tmp/pingtest.txt");
    gchar *content = NULL;
    g_file_get_contents("/tmp/pingtest.txt", &content, NULL, NULL);
    g_idle_add(show_test_result, content ? content : g_strdup("Ping failed."));
    return NULL;
}

// DNS Test Thread
static gpointer dns_test_thread(gpointer data) {
    system("dig google.com > /tmp/dnstest.txt");
    gchar *content = NULL;
    g_file_get_contents("/tmp/dnstest.txt", &content, NULL, NULL);
    g_idle_add(show_test_result, content ? content : g_strdup("DNS lookup failed."));
    return NULL;
}

// HTTP Test Thread
static gpointer http_test_thread(gpointer data) {
    system("curl -I http://example.com > /tmp/httptest.txt 2>&1");
    gchar *content = NULL;
    g_file_get_contents("/tmp/httptest.txt", &content, NULL, NULL);
    g_idle_add(show_test_result, content ? content : g_strdup("HTTP fetch failed."));
    return NULL;
}

// Button Callbacks
static void on_ping_clicked(GtkButton *button, gpointer user_data) {
    g_thread_new("ping_test", ping_test_thread, NULL);
}
static void on_dns_clicked(GtkButton *button, gpointer user_data) {
    g_thread_new("dns_test", dns_test_thread, NULL);
}
static void on_http_clicked(GtkButton *button, gpointer user_data) {
    g_thread_new("http_test", http_test_thread, NULL);
}
static void on_browser_clicked(GtkButton *button, gpointer user_data) {
    system("firefox &");
}

// Window Close Event
static void on_window_destroy(GtkWidget *widget, gpointer user_data) {
    if (vpn_pid) {
        kill(vpn_pid, SIGINT);
        sleep(1);
    }
    gtk_main_quit();
}

// Main Function
int main(int argc, char *argv[]) {
    gtk_init(&argc, &argv);

    main_window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(main_window), "VPN Client GUI");
    gtk_window_set_default_size(GTK_WINDOW(main_window), 500, 400);
    g_signal_connect(main_window, "destroy", G_CALLBACK(on_window_destroy), NULL);

    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_container_add(GTK_CONTAINER(main_window), vbox);

    GtkWidget *hbox1 = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
    entry_ip = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(entry_ip), "Server IP");
    entry_port = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(entry_port), "Port (e.g., 5555)");
    gtk_box_pack_start(GTK_BOX(hbox1), entry_ip, TRUE, TRUE, 5);
    gtk_box_pack_start(GTK_BOX(hbox1), entry_port, TRUE, TRUE, 5);

    GtkWidget *hbox2 = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
    btn_start = gtk_button_new_with_label("Start VPN");
    btn_stop = gtk_button_new_with_label("Stop VPN");
    gtk_box_pack_start(GTK_BOX(hbox2), btn_start, TRUE, TRUE, 5);
    gtk_box_pack_start(GTK_BOX(hbox2), btn_stop, TRUE, TRUE, 5);

    GtkWidget *hbox3 = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
    btn_ping = gtk_button_new_with_label("Ping Test");
    btn_dns = gtk_button_new_with_label("DNS Test");
    btn_http = gtk_button_new_with_label("HTTP Test");
    btn_browser = gtk_button_new_with_label("Open Browser");
    gtk_box_pack_start(GTK_BOX(hbox3), btn_ping, TRUE, TRUE, 5);
    gtk_box_pack_start(GTK_BOX(hbox3), btn_dns, TRUE, TRUE, 5);
    gtk_box_pack_start(GTK_BOX(hbox3), btn_http, TRUE, TRUE, 5);
    gtk_box_pack_start(GTK_BOX(hbox3), btn_browser, TRUE, TRUE, 5);

    label_stats = gtk_label_new("Status: Disconnected.");

    gtk_box_pack_start(GTK_BOX(vbox), hbox1, FALSE, FALSE, 5);
    gtk_box_pack_start(GTK_BOX(vbox), hbox2, FALSE, FALSE, 5);
    gtk_box_pack_start(GTK_BOX(vbox), hbox3, FALSE, FALSE, 5);
    gtk_box_pack_start(GTK_BOX(vbox), label_stats, FALSE, FALSE, 5);

    g_signal_connect(btn_start, "clicked", G_CALLBACK(start_vpn), NULL);
    g_signal_connect(btn_stop, "clicked", G_CALLBACK(stop_vpn), NULL);
    g_signal_connect(btn_ping, "clicked", G_CALLBACK(on_ping_clicked), NULL);
    g_signal_connect(btn_dns, "clicked", G_CALLBACK(on_dns_clicked), NULL);
    g_signal_connect(btn_http, "clicked", G_CALLBACK(on_http_clicked), NULL);
    g_signal_connect(btn_browser, "clicked", G_CALLBACK(on_browser_clicked), NULL);

    gtk_widget_set_sensitive(btn_stop, FALSE);
    gtk_widget_set_sensitive(btn_ping, FALSE);
    gtk_widget_set_sensitive(btn_dns, FALSE);
    gtk_widget_set_sensitive(btn_http, FALSE);
    gtk_widget_set_sensitive(btn_browser, FALSE);

    gtk_widget_show_all(main_window);
    gtk_main();
    return 0;
}

