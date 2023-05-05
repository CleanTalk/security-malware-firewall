<?php

use CleantalkSP\Variables\Post;
use CleantalkSP\Variables\Server;
use CleantalkSP\SpbctWP\Firewall\WAF;
use CleantalkSP\SpbctWP\ListTable;
use CleantalkSP\SpbctWP\Scanner\ScannerQueue;
use CleantalkSP\SpbctWP\CleantalkSettingsTemplates;
use CleantalkSP\SpbctWP\G2FA\GoogleAuthenticator;
use CleantalkSP\SpbctWP\Variables\Cookie;

// Settings page
require_once('spbc-settings.php');

/**
 * Admin action 'admin_init' - Add the admin settings and such
 */
function spbc_admin_init()
{
    global $spbc, $apbct;

    //Logging admin actions
    if (! defined('DOING_AJAX')) {
        spbc_admin_log_action();
    }

    spbc_set_malware_scan_warns();

    // Admin bar
    $spbc->admin_bar_enabled = $spbc->settings['admin_bar__show'] && current_user_can('activate_plugins');

    if ($spbc->admin_bar_enabled) {
        require_once SPBC_PLUGIN_DIR . '/inc/admin-bar.php';

        if (
            /** @psalm-suppress UndefinedFunction */
            ! has_action('admin_bar_menu', 'apbct_admin__admin_bar__add_structure') &&
            ! has_action('admin_bar_menu', 'spbc_admin__admin_bar__add_structure')
        ) {
            add_action('admin_bar_menu', 'spbc_admin__admin_bar__add_structure', 999);
        }

        add_action('cleantalk_admin_bar__parent_node__before', 'spbc_admin__admin_bar__prepare_counters');
        add_action('cleantalk_admin_bar__add_icon_to_parent_node', 'spbc_admin__admin_bar__prepare_counters');
        // Temporary disable the icon
        // add_filter( 'cleantalk_admin_bar__parent_node__before', 'spbc_admin__admin_bar__add_parent_icon', 10, 1 );
        add_filter('cleantalk_admin_bar__parent_node__after', 'spbc_admin__admin_bar__add_counter', 10, 1);

        add_filter('admin_bar_menu', 'spbc_admin__admin_bar__add_child_nodes', 1000);
        if ( ! $apbct) {
            add_filter('admin_bar_menu', 'spbc_apbct_admin__admin_bar__add_child_nodes', 1001);
        }
    }

    // Admin bar
    add_action('wp_ajax_spbc_get_authorized_admins', 'spbc_get_authorized_admins'); // Counting online users

    // Logs
    add_action('wp_ajax_spbc_show_more_security_logs', 'spbc_show_more_security_logs_callback');
    add_action('wp_ajax_spbc_show_more_security_firewall_logs', 'spbc_show_more_security_firewall_logs_callback');
    add_action('wp_ajax_spbc_tc__filter_ip', 'spbc_tc__filter_ip');

    // Scanner
    add_action('wp_ajax_spbc_scanner_controller_front', array(ScannerQueue::class, 'controllerFront'));
    add_action('wp_ajax_spbc_scanner_save_to_pdf', 'spbc_scanner_save_to_pdf');
    add_action('wp_ajax_spbc_scanner_get_pdf_file_name', 'spbc_scanner_get_pdf_file_name');
    add_action('wp_ajax_spbc_scanner_clear', 'spbc_scanner_clear'); // Debug. Clear the table
    add_action('wp_ajax_spbc_scanner__last_scan_info', 'spbc_scanner__last_scan_info');

    // Scanner buttons
    add_action('wp_ajax_spbc_scanner_file_send', 'spbc_scanner_file_send');
    add_action('wp_ajax_spbc_scanner_file_delete', 'spbc_scanner_file_delete');
    add_action('wp_ajax_spbc_scanner_file_approve', 'spbc_scanner_file_approve');
    add_action('wp_ajax_spbc_scanner_file_view', 'spbc_scanner_file_view');
    add_action('wp_ajax_spbc_scanner_page_view', 'spbc_scanner_page_view');
    add_action('wp_ajax_spbc_scanner_page_approve', 'spbc_scanner_page_approve');
    add_action('wp_ajax_spbc_scanner_file_compare', 'spbc_scanner_file_compare');
    add_action('wp_ajax_spbc_scanner_file_replace', 'spbc_scanner_file_replace');
    add_action('wp_ajax_spbc_scanner_file_check_analysis_status', 'spbc_scanner_pscan_check_analysis_status');
    add_action('wp_ajax_spbc_scanner_analysis_log_delete_from_log', 'spbc_scanner_analysis_log_delete_from_log');

    // Settings
    add_action('wp_ajax_spbc_settings__draw_elements', 'spbc_settings__draw_elements');
    if (! empty($spbc->data['scanner']['last_scan'])) {
        add_action('wp_ajax_spbc_scanner_tab__reload_accordion', 'spbc_field_scanner__show_accordion');
    }

    // SPBC Table
    add_action('wp_ajax_spbc_tbl-action--bulk', array(ListTable::class, 'ajaxBulkActionHandler'));
    add_action('wp_ajax_spbc_tbl-action--row', array(ListTable::class, 'ajaxRowActionHandler'));
    add_action('wp_ajax_spbc_tbl-pagination', array(ListTable::class, 'ajaxPaginationHandler'));
    add_action('wp_ajax_spbc_tbl-sort', array(ListTable::class, 'ajaxSortHandler'));
    add_action('wp_ajax_spbc_tbl-switch', array(ListTable::class, 'ajaxSwitchTable'));

    // Send logs_mscan
    add_action('wp_ajax_spbc_send_traffic_control', 'spbc_send_firewall_logs', 1, 0);
    add_action('wp_ajax_spbc_send_security_log', 'spbc_send_logs', 1, 0);

    // WAF. Notification about blocked file.
    add_action('wp_ajax_spbc_check_file_block', array(WAF::class, 'wafFileGetLastBlockedInfo'));

    // Backups
    add_action('wp_ajax_spbc_rollback', 'spbc_rollback');
    add_action('wp_ajax_spbc_backup__delete', 'spbc_backup__delete');

    // Misc
    add_action('wp_ajax_spbc_settings__get_description', 'spbc_settings__get_description');
    add_action('wp_ajax_spbc_settings__check_renew_banner', 'spbc_settings__check_renew_banner');
    add_action('wp_ajax_spbc_sync', 'spbc_sync');
    add_action('wp_ajax_spbc_get_key_auto', 'spbc_get_key_auto');

    // Confirm the email to activate 2FA
    add_action('wp_ajax_spbc_generate_confirmation_code', 'spbctGenerateAndSendConfirmationCode');
    add_action('wp_ajax_spbc_check_confirmation_code', 'spbctCheckConfirmationCode');

    // Auto-adding admin IP to the whitelist
    add_action('wp_ajax_spbc_private_list_add', 'spbc_private_list_add');

    // Settings Templates
    if ($spbc->is_mainsite || $spbc->ms__work_mode != 2) {
        new CleantalkSettingsTemplates($spbc->api_key);
    }

    // Getting key for daughter blogs once
    if (!$spbc->is_mainsite && $spbc->ms__work_mode == 1 && $spbc->ms__hoster_api_key && $spbc->data['ms__key_tries'] < 3) {
        $spbc->data['ms__key_tries'] ++;
        $spbc->save('data');
        spbc_set_api_key();
    }

    // Drop debug data
    if (Post::get('spbc_debug__drop')) {
        $spbc->deleteOption('debug', 'use_prefix');
    }

    // Drop debug data
    if (Post::get('spbc_debug__check_connection')) {
        $result = spbc_test_connection();
        spbc_log($result);
    }

    // Set cookie to detect admin on public pages
    if ( ! empty($spbc->settings['data__set_cookies']) && ! Cookie::get('spbc_admin_logged_in') && is_admin() && current_user_can('manage_options') ) {
        Cookie::set('spbc_admin_logged_in', md5($spbc->data['salt'] . 'admin' . parse_url(get_option('home'), PHP_URL_HOST)), time() + 86400 * 365, '/');
    }
}

/**
 * Manage links in plugins list
 * @return array
 */
function spbc_plugin_action_links($links)
{
    $settings_link = is_network_admin()
        ? '<a href="settings.php?page=spbc">' . __('Settings') . '</a>'
        : '<a href="options-general.php?page=spbc">' . __('Settings') . '</a>';

    array_unshift($links, $settings_link); // before other links

    // Add "Start scan" link only of the main site
    if (is_main_site()) {
        $start_scan = is_network_admin()
            ? '<a href="settings.php?page=spbc&spbc_tab=scanner&spbc_target=spbc_perform_scan&spbc_action=click">' . __('Start scan') . '</a>'
            : '<a href="options-general.php?page=spbc&spbc_tab=scanner&spbc_target=spbc_perform_scan&spbc_action=click">' . __('Start scan') . '</a>';
        array_unshift($links, $start_scan); // before other links
    }

    $trial = spbc_badge__get_premium(false);
    if ( ! empty($trial)) {
        array_unshift($links, spbc_badge__get_premium(false));
    }

    return $links;
}

/**
 * Manage links and plugins page
 * @return array
 */
function spbc_plugin_links_meta($meta, $plugin_file)
{
    global $spbc;

    $plugin_name = SPBC_NAME ?: 'Security by CleanTalk';

    //Return if it's not our plugin
    if (strpos($plugin_file, SPBC_PLUGIN_BASE_NAME) === false) {
        return $meta;
    }

    // $links[] = is_network_admin()
    // ? '<a class="ct_meta_links ct_setting_links" href="settings.php?page=spbc">' . __( 'Settings' ) . '</a>'
    // : '<a class="ct_meta_links ct_setting_links" href="options-general.php?page=spbc">' . __( 'Settings' ) . '</a>';

    if ($spbc->data["wl_mode_enabled"]) {
        $meta   = array_slice($meta, 0, 1);
        $meta[] = "<script " . (class_exists('Cookiebot_WP') ? 'data-cookieconsent="ignore"' : '') . ">
        function changedPluginName(){
            jQuery('.plugin-title strong').each(function(i, item){
            if(jQuery(item).html() == '{$plugin_name}')
                jQuery(item).html('{$spbc->data["wl_brandname"]}');
            });
        }
        changedPluginName();
		jQuery( document ).ajaxComplete(function() {
            changedPluginName();
        });
		</script>";

        return $meta;
    }

    if (substr(get_locale(), 0, 2) != 'en') {
        $meta[] = '<a class="spbc_meta_links spbc_translate_links" href="'
                  . sprintf('https://translate.wordpress.org/locale/%s/default/wp-plugins/security-malware-firewall', substr(get_locale(), 0, 2))
                  . '" target="_blank">'
                  . __('Translate', 'security-malware-firewall')
                  . '</a>';
    }
    $meta[] = '<a class="spbc_meta_links spbc_faq_links" href="https://wordpress.org/plugins/security-malware-firewall/faq/" target="_blank">' . __('FAQ', 'security-malware-firewall') . '</a>';
    $meta[] = '<a class="spbc_meta_links spbc_support_links" href="https://wordpress.org/support/plugin/security-malware-firewall" target="_blank">' . __('Support', 'security-malware-firewall') . '</a>';

    return $meta;
}

/**
 * Register stylesheet and scripts.
 */
function spbc_enqueue_scripts($hook)
{
    // If the user is not admin
    if ( ! current_user_can('upload_files')) {
        return;
    }

    global $spbc;

    // For ALL admin pages
    wp_enqueue_style('spbc_admin_css', SPBC_PATH . '/css/spbc-admin.min.css', array(), SPBC_VERSION, 'all');
    wp_enqueue_style('spbc-icons', SPBC_PATH . '/css/spbc-icons.min.css', array(), SPBC_VERSION, 'all');
    wp_enqueue_script('spbc-common-js', SPBC_PATH . '/js/spbc-common.min.js', array('jquery'), SPBC_VERSION, false);
    wp_enqueue_script('spbc-admin-js', SPBC_PATH . '/js/spbc-admin.min.js', array('jquery'), SPBC_VERSION, false);

    wp_localize_script('spbc-common-js', 'spbcSettings', array(
        'wpms'                            => (int) is_multisite(),
        'is_main_site'                    => (int) is_main_site(),
        'img_path'                        => SPBC_PATH . '/images',
        'key_is_ok'                       => $spbc->key_is_ok,
        'ajax_nonce'                      => wp_create_nonce("spbc_secret_nonce"),
        'ajaxurl'                         => admin_url('admin-ajax.php', 'relative'),
        //'debug'        => !empty($debug) ? 1 : 0,
        'key_changed'                     => ! empty($spbc->data['key_changed']),
        'admin_bar__admins_online_counter' => $spbc->settings['admin_bar__admins_online_counter'] ? 1 : 0,
        'needToWhitelist'                 => ! Cookie::get('spbc_secfw_ip_wl'),
        'frontendAnalysisAmount'          => (defined('SPBCT_ALLOW_CURL_SINGLE') && SPBCT_ALLOW_CURL_SINGLE) ? 2 : 20,
    ));

    wp_enqueue_script('spbc_cookie', SPBC_PATH . '/js/spbc-cookie.min.js', array('jquery'), SPBC_VERSION, false /*in header*/);
    wp_localize_script('spbc_cookie', 'spbcPublic', array(
        '_ajax_nonce'                          => wp_create_nonce('ct_secret_stuff'),
        '_rest_nonce'                          => wp_create_nonce('wp_rest'),
        '_ajax_url'                            => admin_url('admin-ajax.php', 'relative'),
        '_rest_url'                            => esc_url(get_rest_url()),
        //            '_apbct_ajax_url'                      => APBCT_URL_PATH . '/lib/Cleantalk/ApbctWP/Ajax.php',
        'data__set_cookies'                    => $spbc->settings['data__set_cookies'],
        'data__set_cookies__alt_sessions_type' => $spbc->settings['data__set_cookies__alt_sessions_type'],
    ));

    if ($spbc->settings['waf__file_check'] && in_array($hook, array('upload.php', 'media-new.php'))) {
        wp_enqueue_script('spbc-upload-js', SPBC_PATH . '/js/spbc-upload.min.js', array('jquery'), SPBC_VERSION, false);
    }

    // Load UI (modal window) for profile pages
    if ($hook === 'profile.php' || $hook === 'user-edit.php') {
        wp_enqueue_style('jquery-ui', SPBC_PATH . '/css/jquery-ui.min.css', array(), '1.12.1', 'all');        // JS
        wp_enqueue_script('jquery-ui-dialog');
    }

    // For settings page
    if ($hook === 'settings_page_spbc') {
        $button_template = '<button %sclass="spbc_scanner_button_file_%s">%s<img class="spbc_preloader_button" src="' . SPBC_PATH . '/images/preloader.gif" /></button>';

        $button_template_send     = sprintf($button_template, '', 'send', __('Send for analysys', 'security-malware-firewall'));
        $button_template_delete   = sprintf($button_template, '', 'delete', __('Delete', 'security-malware-firewall'));
        $button_template_approve  = sprintf($button_template, '', 'approve', __('Approve', 'security-malware-firewall'));
        $button_template_view     = sprintf($button_template, '', 'view', __('View', 'security-malware-firewall'));
        $button_template_view_bad = sprintf($button_template, '', 'view_bad', __('View suspicious code', 'security-malware-firewall'));
        $button_template_replace  = sprintf($button_template, '', 'replace', __('Replace with original', 'security-malware-firewall'));
        $button_template_compare  = sprintf($button_template, '', 'compare', __('Show difference', 'security-malware-firewall'));
        $actions_unknown  = $button_template_send . $button_template_delete . $button_template_approve . $button_template_view;
        $actions_modified = $button_template_approve . $button_template_replace . $button_template_compare . $button_template_view_bad;

        // CSS
        wp_enqueue_style('spbc-settings', SPBC_PATH . '/css/spbc-settings.min.css', array(), SPBC_VERSION, 'all');
        wp_enqueue_style('spbc-table', SPBC_PATH . '/css/spbc-table.min.css', array(), SPBC_VERSION, 'all');
        wp_deregister_style('jquery-ui-style');
        wp_enqueue_style('jquery-ui', SPBC_PATH . '/css/jquery-ui.min.css', array(), '1.12.1', 'all');

        // JS
        wp_enqueue_script('jquery-ui', SPBC_PATH . '/js/jquery-ui.min.js', array('jquery'), '1.13.1', true);
        wp_enqueue_script('spbc-settings-js', SPBC_PATH . '/js/spbc-settings.min.js', array('jquery'), SPBC_VERSION, true);
        wp_enqueue_script('spbc-table-js', SPBC_PATH . '/js/spbc-table.min.js', array('jquery'), SPBC_VERSION, true);

        wp_localize_script('spbc-table-js', 'spbcTableLocalize', array(
            'scannerIsActive' => esc_html__('Scanner is active for now. Try later.', 'security-malware-firewall'),
        ));

        wp_enqueue_script('spbc-modal', SPBC_PATH . '/js/spbc-modal.min.js', array('jquery'), SPBC_VERSION, true);

        wp_localize_script('spbc-settings-js', 'spbcSettingsSecLogs', array(
            'amount' => SPBC_LAST_ACTIONS_TO_VIEW,
            'clicks' => 0,
        ));

        wp_localize_script('spbc-settings-js', 'spbcSettingsFWLogs', array(
            'moderate' => $spbc->moderate ? 1 : 0,
            'amount'   => SPBC_LAST_ACTIONS_TO_VIEW,
            'clicks'   => 0,
        ));

        wp_localize_script('spbc-settings-js', 'spbcTable', array(
            'warning_bulk'       => __('Are sure you want to perform these actions?', 'security-malware-firewall'),
            'warning_default'    => __('Do you want to proceed?', 'security-malware-firewall'),
            'warning_delte'      => __('This can\'t be undone and could damage your website. Are you sure?', 'security-malware-firewall'),
            'warning_replace'    => __('This can\'t be undone. Are you sure?', 'security-malware-firewall'),
            'warning_quarantine' => __('This can\'t be undone and could damage your website. Are you sure?', 'security-malware-firewall'),
        ));

        // Getting scanner settings
        $scanner_settings = array_filter(
            (array) $spbc->settings,
            function ($key) {
                return strpos($key, 'scanner') === 0;
            },
            ARRAY_FILTER_USE_KEY
        );

        wp_localize_script('spbc-settings-js', 'spbcScaner', array(

            // PARAMS
            'settings'                            => $scanner_settings,
            'states'                              => ScannerQueue::$stages,
            'timezone_shift'                            => $spbc->data['site_utc_offset_in_seconds'] ?: false,

            // Settings / Statuses
            'scaner_enabled'                      => $spbc->scaner_enabled ? 1 : 0,
            'check_links'                         => $spbc->settings['scanner__outbound_links'] ? 1 : 0,
            'check_heuristic'                     => $spbc->settings['scanner__heuristic_analysis'] ? 1 : 0,
            'check_signature'                     => $spbc->settings['scanner__signature_analysis'] ? 1 : 0,
            'auto_cure'                           => $spbc->settings['scanner__auto_cure'] ? 1 : 0,
            'check_frontend'                      => $spbc->settings['scanner__frontend_analysis'] ? 1 : 0,
            'check_listing'                       => $spbc->settings['scanner__important_files_listing'] ? 1 : 0,
            'wp_content_dir'                      => realpath(WP_CONTENT_DIR),
            'wp_root_dir'                         => realpath(ABSPATH),

            // Templates
            'row_template'                        => '<tr type="%s" class="spbc_scan_result_row" file_id="%s"><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>',
            'row_template_links'                  => '<tr class="spbc_scan_result_row"><td><a href=%s target="_blank">%s</a></td><td><a href=%s target="_blank">%s</a></td><td>%s</td></tr>',
            'actions_unknown'                     => $actions_unknown,
            'actions_modified'                    => $actions_modified,
            'page_selector_template'              => '<li class="pagination"><a href="#" class="spbc_page" type="%s" page="%s"><span%s>%s</span></a></li>',

            //TRANSLATIONS

            //Confirmation
            'scan_modified_confiramation'         => __('There is more than 30 modified files and this could take time. Do you want to proceed?', 'security-malware-firewall'),
            'warning_about_cancel'                => __('Scan will be performed in the background mode soon.', 'security-malware-firewall'),
            'delete_warning'                      => __('Are you sure you want to delete the file? It can not be undone.'),
            // Buttons
            'button_scan_perform'                 => __('Perform Scan', 'security-malware-firewall'),
            'button_scan_pause'                   => __('Pause scan', 'security-malware-firewall'),
            'button_scan_resume'                  => __('Resume scan', 'security-malware-firewall'),
            // Progress bar
            'progressbar_get_cms_hashes'          => __('Receiving hashes', 'security-malware-firewall'),
            'progressbar_get_modules_hashes'      => __('Receiving plugins hashes', 'security-malware-firewall'),
            'progressbar_get_approved_hashes'     => __('Updating statuses for the approved files', 'security-malware-firewall'),
            'progressbar_clean_results'           => __('Preparing', 'security-malware-firewall'),
            // Scanning core
            'progressbar_file_system_analysis'    => __('Scanning for modifications', 'security-malware-firewall'),
            'progressbar_heuristic_analysis'      => __('Heuristic analysis', 'security-malware-firewall'),
            'progressbar_signature_analysis'      => __('Searching for signatures', 'security-malware-firewall'),
            //Cure
            'progressbar_auto_cure_backup'        => __('Creating a backup', 'security-malware-firewall'),
            'progressbar_auto_cure'               => __('Cure', 'security-malware-firewall'),
            // Links
            'progressbar_outbound_links'          => __('Scanning links', 'security-malware-firewall'),
            // Frontend
            'progressbar_frontend_analysis'       => __('Scanning pages', 'security-malware-firewall'),
            // Other
            'progressbar_important_files_listing' => __('Check pages for listing', 'security-malware-firewall'),
            'progressbar_send_results'            => __('Sending results', 'security-malware-firewall'),
            // Warnings
            'result_text_bad_template'            => __('Recommend to scan all (%s) of the found files to make sure the website is secure.', 'security-malware-firewall'),
            'result_text_good_template'           => __('No threats are found.', 'security-malware-firewall'),
            //Misc
            'look_below_for_scan_res'             => __('Look below for scan results.', 'security-malware-firewall'),
            'view_all_results'                    => sprintf(
                __('</br>%sView all scan results for this website%s', 'security-malware-firewall'),
                '<a target="blank" href="https://cleantalk.org/my/logs_mscan?service=' . $spbc->service_id . '">',
                '</a>'
            ),
            'last_scan_was_just_now'              => __('The last scan of this website happened just now. Files scanned: %s.', 'security-malware-firewall'),
            'last_scan_was_just_now_links'        => __('The last scan of this website happened just now. Files scanned: %s. Outbound links found: %s.', 'security-malware-firewall'),
        ));

        wp_localize_script('spbc-settings-js', 'spbcDescriptions', array(
            'waf__enabled'                => __('Bla bla', 'security-malware-firewall'),
            'waf__xss_check'              => __('Cross-Site Scripting (XSS) — prevents malicious code to be executed/sent to any user. As a result malicious scripts can not get access to the cookie files, session tokens and any other confidential information browsers use and store. Such scripts can even overwrite content of HTML pages. CleanTalk WAF monitors for patterns of these parameters and block them.', 'security-malware-firewall'),
            'waf__sql_check'              => __('SQL Injection — one of the most popular ways to hack websites and programs that work with databases. It is based on injection of a custom SQL code into database queries. It could transmit data through GET, POST requests or cookie files in an SQL code. If a website is vulnerable and execute such injections then it would allow attackers to apply changes to the website\'s MySQL database.', 'security-malware-firewall'),
            'waf__file_check'             => __('The option checks each uploaded file to a website for malicious code. If it\'s possible for visitors to upload files to a website, for instance a work resume, then attackers could abuse it and upload an infected file to execute it later and get access to your website.', 'security-malware-firewall'),
            'traffic_control__enabled'    => __('It analyzes quantity of requests towards website from any IP address for a certain period of time. For example, for an ordinary visitor it\'s impossible to generate 2000 requests within 1 hour. Big amount of requests towards website from the same IP address indicates that there is a high chance of presence of a malicious program.', 'security-malware-firewall'),
            'scanner__outbound_links'     => __('This option allows you to know the number of outgoing links on your website and website addresses they lead to. These websites addresses will be checked with the CleanTalk Database and the results will show if they were used in spam messages. The option\'s purpose is to check your website and find hidden, forgotten and spam links. You should always remember if you have links to other websites which have a bad reputation, it could affect your visitors\' trust and your SEO.', 'security-malware-firewall'),
            'scanner__heuristic_analysis' => __('Often, authors of malicious code disguise their code which makes it difficult to identify it by their signatures. The malicious code itself can be placed anywhere on the site, for example the obfuscated PHP-code in the "logo.png" file, and the code itself is called by one inconspicuous line in "index.php". Therefore, the usage of plugins to search for malicious code is preferable. Heuristic analysis can indicate suspicious PHP constructions in a file that you should pay attention to.', 'security-malware-firewall'),
            'scanner__signature_analysis' => __('Code signatures — it\'s a code sequence a malicious program consists of. Signatures are being added to the database after analysis of the infected files. Search for such malicious code sequences is performed in scanning by signatures. If any part of code matches a virus code from the database, such files would be marked as critical.', 'security-malware-firewall'),
            'scanner__auto_cure'          => __('It cures infected files automatically if the scanner knows cure methods for these specific cases. If the option is disabled then when the scanning process ends you will be presented with several actions you can do to the found files: Cure. Malicious code will be removed from the file. Replace. The file will be replaced with the original file. Delete. The file will be put in quarantine. Do nothing. Before any action is chosen, backups of the files will be created and if the cure is unsuccessful it\'s possible to restore each file.', 'security-malware-firewall'),
            'misc__backend_logs_enable'   => __('To control appearing errors you have to check log file of your hosting account regularly. It\'s inconvenient and just a few webmasters pay attention to it. Also, errors could appear for a short period of time and only when one specific function is running, they can\'t be spotted in other circumstances so it\'s hard to catch them. PHP errors tell you that some of your website functionality doesn\'t work correctly, furthermore hackers may use these errors to get access to your website. The CleanTalk Scanner will check your website backend once per hour. Statistics of errors is available in your CleanTalk Dashboard.', 'security-malware-firewall'),
            'data__set_cookies'           => __('Part of the CleanTalk FireWall functions depend on cookie files, so disabling this option could lead to deceleration of the firewall work. It will affect user identification who are logged in right now. Traffic Control will not be able to determine authorized users and they could be blocked when the request limit is reached. We do not recommend to disable this option without serious reasons. However, you should disable this option is you\'re using Varnish.', 'security-malware-firewall'),
            '2fa__enable'                 => __('Two-Factor Authentication for WordPress admin accounts will improve your website security and make it safer, if not impossible, for hackers to breach your WordPress account. Two-Factor Authentication works via e-mail. Authentication code will be sent to your admin email. When authorizing, a one-time code will be sent to your email. While entering the code, make sure that it does not contain spaces. With your first authorization, the CleanTalk Security plugin remembers your browser and you won’t have to input your authorization code every time anymore. However, if you started to use a new device or a new browser then you are required to input your authorization code. The plugin will remember your browser for 30 days.', 'security-malware-firewall'),
        ));
    }
}

function spbc_admin_add_script_attribute($tag, $handle)
{
    $async_scripts = array(
        //'jquery-ui',
        //'spbc-common-js',
        'spbc-scannerplugin-js',
        'spbc-scaner-events-js',
        'spbc-scaner-callbacks-js',
    );

    $defer_scripts = array(
        'spbc-settings-js',
        'spbc-scaner-js',
    );

    if (in_array($handle, $async_scripts)) {
        return str_replace(' src', ' async="async" src', $tag);
    } elseif (in_array($handle, $defer_scripts)) {
        return str_replace(' src', ' defer="defer" src', $tag);
    } else {
        return $tag;
    }
}

/*
 * Logging admin action
*/
function spbc_admin_log_action()
{
    $user = wp_get_current_user();
    $secure_cookies = array();

    try {
        $secure_cookies = spbc_get_secure_cookies();
    } catch (Exception $e) {
        // @ToDo for the handling failing cookies testing
    }

    if ( ! empty($secure_cookies)) {
        try {
            spbc_write_timer($secure_cookies);
        } catch (Exception $e) {
            error_log($e->getMessage());
        }
    }

    if (isset($user->ID) && $user->ID > 0) {
        $roles = (is_array($user->roles) && ! empty($user->roles) ? reset($user->roles) : null); // Takes only first role.

        $log_id = spbc_auth_log(array(
            'username' => $user->get('user_login'),
            'event'    => 'view',
            'page'     => Server::get('REQUEST_URI'),
            'blog_id'  => get_current_blog_id(),
            'roles'    => $roles
        ));
    }

    // Setting timer with event ID
    if (isset($log_id)) {
        $cookies_arr = array(
            'spbc_log_id' => $log_id,
            'spbc_timer'  => time()
        );

        try {
            spbc_set_secure_cookies($cookies_arr);
        } catch (Exception $e) {
            error_log($e->getMessage());
        }
    }

    return;
}

/**
 * Calculates and writes page time to DB
 *
 * @param $timer               array of the row like array('spbc_log_id' => $log_id, 'spbc_timer'  => time())
 *
 * @throws Exception           throws if the query faults
 */
function spbc_write_timer($timer)
{
    global $wpdb;

    if ( ! isset($timer['log_id'], $timer['timer'])) {
        throw new Exception('SPBC: Can not update the logs table (cookies was not provided).');
    }

    $result = $wpdb->update(
        SPBC_TBL_SECURITY_LOG,
        array('page_time' => (string) (time() - $timer['timer'])),
        array('id' => $timer['log_id']),
        '%s',
        '%s'
    );

    if (false === $result) {
        throw new Exception('SPBC: Can not update the logs table.');
    }
}

function spbc_badge__get_premium($print = true, $make_it_right = false, $out = '')
{
    global $spbc;

    if ($spbc->data['license_trial'] == 1 && ! empty($spbc->user_token) && ! $spbc->data["wl_mode_enabled"] ) {
        $out = '<b style="display: inline-block; margin-top: 10px;">'
               . ($make_it_right ? __('Make it right!', 'cleantalk') . ' ' : '')
               . sprintf(
                   __('%sGet premium%s', 'cleantalk'),
                   $spbc->data["wl_mode_enabled"] ? $spbc->data["wl_support_url"] : '<a href="https://cleantalk.org/my/bill/security?user_token=' . $spbc->user_token . '" target="_blank">',
                   '</a>'
               )
               . '</b>';
    }

    if ($print) {
        echo $out;
    } else {
        return $out;
    }
}

/**
 * Setting up secure cookies
 *
 * @param $cookies            array of the cookies to be set
 *
 * @throws Exception          error_log errors of setting cookies
 */
function spbc_set_secure_cookies($cookies)
{
    if (headers_sent()) {
        throw new Exception('SPBC: Secure cookies does not set (headers already sent).');
    }

    if (!is_array($cookies) || empty($cookies)) {
        throw new Exception('SPBC: Secure cookies does not set (there are not cookies).');
    }

    global $spbc;
    $domain  = parse_url(get_option('home'), PHP_URL_HOST);
    $success = array();

    $cookie_test_value = array(
        'cookies_names' => array(),
        'check_value'   => $spbc->settings['spbc_key'],
    );

    foreach ($cookies as $cookie_name => $cookie_value) {
        $success[] = Cookie::set($cookie_name, $cookie_value, 0, '/', $domain, false, true);
        $cookie_test_value['cookies_names'][] = $cookie_name;
        $cookie_test_value['check_value']     .= $cookie_value;
    }

    $cookie_test_value['check_value'] = md5($cookie_test_value['check_value']);
    $success[]                        = Cookie::set('spbc_cookies_test', $cookie_test_value, 0, '/', $domain, false, true);

    if (in_array(false, $success)) {
        throw new Exception('SPBC: Secure cookies does not set (setcookie error).');
    }
}

/**
 * Getting the secure cookies
 *
 * @return array       array of cookies
 * @throws Exception   throws if our $_COOKIE not set
 */
function spbc_get_secure_cookies()
{
    $secure_cookies = array();

    if (Cookie::get('spbc_cookies_test')) {
        $cookie_test = Cookie::get('spbc_cookies_test');

        if (!is_array($cookie_test)) {
            throw new Exception('SPBC: Secure cookies does not get (there are not cookies).');
        }

        $check_secure_cookies = spbc_validate_secure_cookies($cookie_test);

        if (!$check_secure_cookies) {
            throw new Exception('SPBC: Secure cookies does not get (cookies was malformed).');
        } else {
            foreach ($cookie_test['cookies_names'] as $cookie_name) {
                if (Cookie::get($cookie_name)) {
                    $cookie_name_prepared                    = str_replace('spbc_', '', $cookie_name);
                    $secure_cookies[ $cookie_name_prepared ] = Cookie::get($cookie_name);
                }
            }
        }
    }

    return $secure_cookies;
}

/**
 * Check if cookies was not malformed
 *
 * @param $cookies_arr    array of cookies
 *
 * @return bool           true|false
 */
function spbc_validate_secure_cookies($cookies_arr)
{
    global $spbc;

    $check_string = $spbc->settings['spbc_key'];
    foreach ($cookies_arr['cookies_names'] as $cookie_name) {
        $check_string .= Cookie::get($cookie_name);
    }
    unset($cookie_name);

    if ($cookies_arr['check_value'] == md5($check_string)) {
        return true;
    } else {
        return false;
    }
}

/**
 * Add option to the profile page.
 *
 * @param WP_User $wp_user
 */
function spbc_2fa__SelfUserProfileEdit($wp_user)
{
    global $spbc;

    if (spbc_is_user_role_in($spbc->settings['2fa__roles'], $wp_user)) {
        $type2fa = get_user_meta($wp_user->ID, 'spbc_2fa_type', true);
        $button  = '';

        if ($type2fa === 'google_authenticator') {
            $type2fa_label = esc_html__('Google authenticator', 'security-malware-firewall');
            // Disable G2FA can only admin and self-edited user.
            if (current_filter() === 'show_user_profile' || current_user_can('manage_options')) {
                $button = '<button class="button" id="spbc-g2fa-disable" data-user-id="' . sanitize_key((string) $wp_user->ID) . '">' . esc_html__('Disable Google Authenticator', 'security-malware-firewall') . '</button>';
                $button .= '<br><em>' . esc_html__('To disable the Google authentication click the button above or reset the password to the account. The two-factor authentication will be switched to Email. Or you can disable it directly on the page of the WordPress site profile.', 'security-malware-firewall') . '</em>';
            }
        } else {
            $type2fa_label = esc_html__('Email', 'security-malware-firewall');
            // Enable G2FA can only self-edited user.
            if (current_filter() === 'show_user_profile') {
                $button = '<button class="button" id="spbc-g2fa-enable">' . esc_html__('Enable Google Authenticator', 'security-malware-firewall') . '</button>';
            }
        }

        echo '<h2>' . $spbc->data["wl_brandname"] . esc_html__(' 2FA', 'security-malware-firewall') . '</h2>';
        ?>
        <table class="form-table">
            <tr id="spbc-2fa-type">
                <th>
                    <label for="spbc-2fa-type"><?php esc_html_e('2FA type', 'security-malware-firewall'); ?></label>
                </th>
                <td>
                    <p><?php echo esc_html__('Two-factor authentication (2FA) type:', 'security-malware-firewall') . ' '; ?>
                        <strong><?php echo $type2fa_label; ?></strong></p>
                    <p><?php echo $button; ?></p>
                </td>
            </tr>
        </table>
        <div id="spbct-google-qr-code" class="spbc_hide" style="padding: 0 15px;text-align:center;">
            <p><?php esc_html_e('Please scan this with the Google Authenticator App.', 'security-malware-firewall'); ?></p>
            <div id="spbct-google-qr-code-img"></div>
            <p><?php esc_html_e('Enter Google Authenticator code.', 'security-malware-firewall'); ?></p>
            <input name="spbct-google-qr-code" type="text"/>
        </div>
        <?php
    }
}

/**
 * Getting Google QR
 * AJAX action.
 */
function spbc_2fa__GetGoogleQrCode()
{
    spbc_check_ajax_referer('spbc_secret_nonce', 'security');
    $user_obj = wp_get_current_user();

    if (property_exists($user_obj, 'ID')) {
        $user_token = get_user_meta($user_obj->ID, 'spbc_g2fa_token', true);
        $ga = new GoogleAuthenticator();

        if (!$user_token) {
            $user_token = $ga->generateSecret();
            update_user_meta($user_obj->ID, 'spbc_g2fa_token', $user_token);
        }

        $url        = sprintf("otpauth://totp/%s?secret=%s", $user_obj->get('user_login') . '(' . get_site_url() . ')', $user_token);
        $encoder    = 'https://chart.googleapis.com/chart?chs=200x200&chld=M|0&cht=qr&chl=';
        $qrImageURL = sprintf("%s%s", $encoder, urlencode($url));
        $qr         = '<img style="border:0;padding:10px;width:200px;height:auto;" src="' . $qrImageURL . '" alt="Google authenticator QR code"/>';

        wp_send_json_success(array('img' => $qr, 'code' => $user_token));
    }

    wp_send_json_error(esc_html__('Error: Current user is undefined.', 'security-malware-firewall'));
}

/**
 * Checking 6 digit Google 2fa code.
 * AJAX action.
 */
function spbc_2fa__CheckGoogleCode()
{
    spbc_check_ajax_referer('spbc_secret_nonce', 'security');

    if (isset($_POST['code']) && preg_match('/^\d{6}$/', trim($_POST['code']))) {
        $user_obj = wp_get_current_user();

        if (property_exists($user_obj, 'ID')) {
            $user_token = get_user_meta($user_obj->ID, 'spbc_g2fa_token', true);

            if ($user_token) {
                $ga   = new GoogleAuthenticator();
                $code = $ga->getCode($user_token);

                if (trim($_POST['code']) === $code) {
                    if (update_user_meta($user_obj->ID, 'spbc_2fa_type', 'google_authenticator')) {
                        wp_send_json_success();
                    }
                    wp_send_json_error(esc_html__('Error: 2FA type not updated.', 'security-malware-firewall'));
                }

                wp_send_json_error(esc_html__('Error: The code not match.', 'security-malware-firewall'));
            }

            wp_send_json_error(esc_html__('Error: User token error.', 'security-malware-firewall'));
        }

        wp_send_json_error(esc_html__('Error: Current user is undefined.', 'security-malware-firewall'));
    }

    wp_send_json_error(esc_html__('Error: The code is incorrect.', 'security-malware-firewall'));
}

/**
 * Disable Google 2fa.
 * AJAX action.
 */
function spbc_2fa__DisableGoogle2fa()
{
    spbc_check_ajax_referer('spbc_secret_nonce', 'security');

    if (isset($_POST['user_id'])) {
        $user_obj = spbc_get_user_by('id', sanitize_key($_POST['user_id']));

        if (is_object($user_obj) && property_exists($user_obj, 'ID')) {
            if (spbc_2fa__Google2fa_replace_meta($user_obj)) {
                wp_send_json_success();
            }

            wp_send_json_error(esc_html__('Error: 2FA type not updated.', 'security-malware-firewall'));
        }
    }

    wp_send_json_error(esc_html__('Error: Current user is undefined.', 'security-malware-firewall'));
}

function spbc_get_authorized_admins($direct_call = false)
{
    if ( ! $direct_call) {
        spbc_check_ajax_referer('spbc_secret_nonce', 'security');
    }

    $users = \CleantalkSP\Monitoring\User::getAdminsOnline();

    if ($direct_call) {
        return $users;
    } else {
        header('Content-Type: application/json');
        die(json_encode(array('count' => count($users), 'users' => $users)));
    }
}

/**
 * Action for shuffle authentication unique keys and salts
 */
add_action('wp_ajax_spbc_action_shuffle_salts', 'spbc_action_shuffle_salts');

function spbc_action_shuffle_salts()
{
    spbc_check_ajax_referer('spbc_secret_nonce', 'security');

    global $spbc;
    $salts_array = array(
        'AUTH_KEY',
        'SECURE_AUTH_KEY',
        'LOGGED_IN_KEY',
        'NONCE_KEY',
        'AUTH_SALT',
        'SECURE_AUTH_SALT',
        'LOGGED_IN_SALT',
        'NONCE_SALT',
    );

    $http_salts     = wp_remote_get('https://api.wordpress.org/secret-key/1.1/salt/');
    $returned_salts = wp_remote_retrieve_body($http_salts);
    $new_salts      = explode("\n", $returned_salts);

    if (empty($new_salts[0])) {
        wp_send_json_error(esc_html__('Error: Something went wrong. Please, try again.', 'security-malware-firewall'));
    }

    // Adding filters for additional salts.
    $new_salts   = apply_filters('spbc_new_salts_filter', $new_salts);
    $salts_array = apply_filters('spbc_salts_array_filter', $salts_array);

    $shuffle_salts_result = spbc_write_salts($salts_array, $new_salts);

    if (!$shuffle_salts_result) {
        wp_send_json_error(esc_html__('Error: Something went wrong. Please, try again.', 'security-malware-firewall'));
    }

    $spbc->settings['there_was_signature_treatment'] = 0;
    $spbc->save('settings');

    //drop spbc_is_logged_in cookie to prevent ЕС and BFP incorrect work
    Cookie::set('spbc_is_logged_in', '0', time() - 30, '/');

    wp_send_json_success();
}

/**
 * Write salts in wp-config.php
 */
function spbc_write_salts($salts_array, $new_salts)
{
    $config_file = spbc_config_file_path();

    // Not founded wp-config.php
    if ( ! $config_file) {
        return false;
    }

    // Get the current permissions of wp-config.php.
    $config_file_permissions = fileperms($config_file);

    $tmp_config_file = ABSPATH . 'wp-config-temp.php';

    $reading_config = fopen($config_file, 'r');
    $writing_config = fopen($tmp_config_file, 'w');

    while (!feof($reading_config)) {
        $line = fgets($reading_config);
        foreach ($salts_array as $salt_key => $salt_value) {
            if (strripos($line, $salt_value)) {
                $line = $new_salts[ $salt_key ] . "\n";
                unset($salts_array[ $salt_key ]);
            }
        }
        fputs($writing_config, $line);
    }

    fclose($reading_config);
    fclose($writing_config);
    rename($tmp_config_file, $config_file);

    // Keep the original permissions of wp-config.php.
    chmod($config_file, $config_file_permissions);

    return true;
}

/**
 * Get wp-config.php path
 */
function spbc_config_file_path()
{
    $config_file_name = 'wp-config';
    $config_file      = ABSPATH . $config_file_name . '.php';
    $config_file_up   = ABSPATH . '../' . $config_file_name . '.php';

    if (file_exists($config_file) && is_writable($config_file)) {
        return $config_file;
    } elseif (file_exists($config_file_up) && is_writable($config_file_up) && ! file_exists(dirname(ABSPATH) . '/wp-settings.php')) {
        return $config_file_up;
    }

    return false;
}

function spbc_set_malware_scan_warns()
{
    global $wpdb, $spbc;
    $query = 'SELECT COUNT(*)
        FROM ' . SPBC_TBL_SCAN_FILES . ' 
        WHERE (STATUS = "INFECTED" AND severity = "CRITICAL" AND analysis_status IS NULL) 
        OR STATUS = "DENIED_BY_CLOUD"';
    $critical_count = (int)$wpdb->get_var($query) > 0;

    $query = 'SELECT COUNT(*) 
        FROM ' . SPBC_TBL_SCAN_FRONTEND . ' 
        WHERE approved IS NULL';
    $frontend_count = (int)$wpdb->get_var($query) > 0;

    $query = 'SELECT COUNT(*) 
        FROM ' . SPBC_TBL_SCAN_FILES . ' 
        WHERE pscan_status = "DANGEROUS" OR analysis_status = "DANGEROUS"';
    $analysis_has_dangerous = (int)$wpdb->get_var($query) > 0;

    $query = 'SELECT COUNT(*) 
        FROM ' . SPBC_TBL_SCAN_FILES . ' 
        WHERE last_sent IS NOT NULL
        AND (pscan_processing_status <> "DONE" OR analysis_status = "NEW")';
    $analysis_has_uncheked = (int)$wpdb->get_var($query) <> 0;

    $spbc->data['display_scanner_warnings'] = array(
        'critical' => $critical_count,
        'frontend' => $frontend_count,
        'analysis' => $analysis_has_dangerous,
        'analysis_all_safe' => !$analysis_has_uncheked && !$analysis_has_dangerous,
        'warn_on_admin_bar' => $critical_count || $frontend_count || $analysis_has_dangerous
    );
    $spbc->save('data');
}
