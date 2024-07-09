<?php

namespace CleantalkSP\SpbctWP\Firewall;

use CleantalkSP\Security\Firewall\Result;
use CleantalkSP\SpbctWP\Firewall;
use CleantalkSP\SpbctWP\Helpers\Data;
use CleantalkSP\SpbctWP\Helpers\Helper;
use CleantalkSP\SpbctWP\Helpers\IP;
use CleantalkSP\SpbctWP\Scanner\FileInfoExtended;
use CleantalkSP\SpbctWP\VulnerabilityAlarm\VulnerabilityAlarm;
use CleantalkSP\Variables\Post;
use CleantalkSP\Variables\Server;
use CleantalkSP\SpbctWP\Escape;
use FilesystemIterator;

class UploadChecker extends FirewallModule
{
    public $module_name = 'UploadChecker';

    /**
     * If it needs to check uploaded plugins/themes.
     * @var bool
     */
    protected $upload_checker__do_check_wordpress_modules = false;

    /**
     * List there all the severity levels that UploadChecker should react to during upload.
     * Has different levels for types, for file or WordPress module.
     * @var array[]
     */
    private static $uploads_severity_warning_levels = array(
        'file' => array('CRITICAL', 'SUSPICIOUS'),
        'wordpress_module' => array('CRITICAL')
    );

    /**
     * @psalm-suppress PossiblyUnusedProperty
     */
    protected $api_key = false;

    /**
     * Supported mime types list.
     * @var string[]
     */
    public $waf_file_mime_check = array(
        'text/x-php',
        'text/plain',
        'image/x-icon',
        'application/zip',
        'application/x-zip-compressed',
    );

    /**
     * Supported mime types list, archive exactly.
     * @var string[]
     */
    public $waf_file_mime_check_zip = array(
        'application/zip',
        'application/x-zip-compressed',
    );

    /**
     * FireWall_module constructor.
     * Use this method to prepare any data for the module working.
     *
     * @param array $params
     */
    public function __construct($params = array())
    {
        parent::__construct($params);
    }

    /**
     * Implement parent firewall module call
     * @return bool[]|Result[]
     */
    public function check()
    {
        $result_passed = new Result(
            array(
                'module' => $this->module_name,
                'ip'     => end($this->ip_array),
                'status' => 'PASS',
            )
        );
        $result = $this->runCheckForFilesGlobalVariable($_FILES);

        return false !== $result ? array($result) : array($result_passed);
    }

    /**
     * Checks uploaded files for malicious code. This method checks $_FILES array.
     * If class static param "upload_checker__do_check_wordpress_modules" is true, this method will add filter method
     * runCheckForWordpressModules() for 'upgrader_source_selection' action to run WordPress plugins/themes check
     * @return false|Result Is the file contained a malicious code
     * @psalm-suppress InvalidArrayOffset
     */
    private function runCheckForFilesGlobalVariable($global_files_variable)
    {
        $trust_module = false;
        if (array_key_exists('trust_module', $_POST)) {
            $trust_module = $_POST['trust_module'];
        }
        foreach ( $global_files_variable as $files ) {
            if ( (empty($files['error']) || $files['error'] === UPLOAD_ERR_OK) ) {
                $files['tmp_name'] = is_array($files['tmp_name']) ? $files['tmp_name'] : array($files['tmp_name']);
                foreach ( $files['tmp_name'] as $file_path ) {
                    if (
                        is_string($file_path) &&
                        is_uploaded_file($file_path) &&
                        is_readable($file_path) &&
                        in_array(Data::getMIMEType($file_path), $this->waf_file_mime_check) &&
                        $trust_module == false
                    ) {
                        //Check uploaded plugins and themes, this sign can be fired only on due $_FILES handling
                        if ( $this->upload_checker__do_check_wordpress_modules ) {
                            add_filter(
                                'upgrader_source_selection',
                                '\CleantalkSP\SpbctWP\Firewall\UploadChecker::runCheckForWordpressModules',
                                2,
                                4
                            );
                        }

                        $file_is_packed = false;
                        if (Server::get('QUERY_STRING') !== 'action=upload-plugin' &&
                            Server::get('QUERY_STRING') !== 'action=upload-theme' &&
                            in_array(Data::getMIMEType($file_path), $this->waf_file_mime_check_zip)
                        ) {
                            $file_is_packed = true;
                        }

                        $file_check_result = $file_is_packed
                            ? self::checkUploadedArchive($file_path)
                            : self::checkFileContent($file_path);

                        //if we have a result, return it immediately
                        if ( false !== $file_check_result ) {
                            return $file_check_result;
                        }
                        //skip if nothing found on current file
                    }
                    //skip if file meta checks are not passed
                }
            }
            //do nothing on WP errors
        }
        //false if nothing found on all of files
        return false;
    }

    /**
     * Scan file content with signatures and heuristics. Returns first found Result severity, false if nothing found.
     * @param $file_path
     * @return Result|false
     */
    public function checkFileContent($file_path)
    {
        $file_content = file_get_contents($file_path);

        //check signatures first
        if (
            in_array(Data::getMIMEType($file_path), array('text/x-php', 'text/plain', 'image/x-icon', 'text/javascript'))
        ) {
            $signatures = $this->db->fetchAll('SELECT * FROM ' . SPBC_TBL_SCAN_SIGNATURES);
            if ( !empty($signatures) ) {
                $signatures_scanner = new \CleantalkSP\Common\Scanner\SignaturesAnalyser\Controller();
                $file_to_check = new \CleantalkSP\Common\Scanner\SignaturesAnalyser\Structures\FileInfo(
                    $file_path,
                    md5($file_content)
                );
                $signature_result = $signatures_scanner->scanFile($file_to_check, '', $signatures);
            }
        }

        if ( isset($signature_result->severity) && $signature_result->severity === 'CRITICAL' ) {
            //return immediately if signatures found
            return new Result(
                array(
                    'module'        => $this->module_name,
                    'ip'            => end($this->ip_array),
                    'status'        => 'DENY_BY_WAF_FILE',
                    'pattern'       => array('CRITICAL' => 'malware signatures'),
                    'triggered_for' => 'uploaded_file',
                    'waf_action'    => 'DENY',
                )
            );
        }
        //signatures check end

        //then check heuristics if signatures passed
        $heuristic_scanner = new \CleantalkSP\Common\Scanner\HeuristicAnalyser\Controller();
        $file_to_check = new FileInfoExtended(array('path' => $file_path));
        $heuristic_result = $heuristic_scanner->scanFile($file_to_check, '');

        if ( ! empty($heuristic_result->weak_spots) ) {
            $patterns = array();
            foreach ( $heuristic_result->weak_spots as $severity => $result ) {
                // filter severity based on prepared levels depends on type
                if ( static::doUploadStopOnSeverity($severity, self::$uploads_severity_warning_levels['file']) ) {
                    $patterns[$severity] = reset($result);
                    $patterns['file_path'] = $file_to_check->path;
                }
            }

            if ( !empty($patterns) ) {
                //return immediately if heuristics found
                return new Result(
                    array(
                        'module'        => $this->module_name,
                        'ip'            => end($this->ip_array),
                        'status'        => 'DENY_BY_WAF_FILE',
                        'pattern'       => $patterns,
                        'triggered_for' => 'uploaded_file',
                        'waf_action'    => 'DENY',
                    )
                );
            }
        }
        //heuristics check end

        return false;
    }

    /**
     * Filter for WordPress hook 'upgrader_source_selection'. Do filter uploaded module.
     * @param $source
     * @param $remote_source
     * @param \WP_Upgrader $upgrader
     * @param $args_hook_extra
     * @return \WP_Error
     * @psalm-suppress PossiblyUnusedMethod
     */
    public static function runCheckForWordpressModules(
        $source,
        $remote_source,
        \WP_Upgrader $upgrader,
        $args_hook_extra
    ) {
        global $spbc;

        // Show initial check message
        show_message($spbc->data["wl_brandname"] . sprintf(' Signatures analysis is checking the uploaded %s&#8230;', $args_hook_extra['type']));

        // Prepare and run scan
        $dir_scan = new \CleantalkSP\SpbctWP\Scanner\DirectoryScan(
            $source,
            \CleantalkSP\SpbctWP\Scanner\Controller::getRootPath(),
            array(
                'output_file_details' => array('path', 'full_hash'),
            )
        );

        // Output the result
        $details = '<div id="spbct-upload-checker-details">';
        $details .= '<ul>';

        $overall_result = true;
        $total_files_checked_count = 0;

        try {
            $dir_scan->setElements();
            $results = $dir_scan->scan(true);
            $total_files_checked_count = count($results);
            foreach ($results as $result) {
                // if http error collected or result array invalid
                if ( !empty($result['error']) || in_array(array('path','status','severity'), array_keys($result))) {
                    $details .= '<li>&nbsp;&nbsp;<b>'
                    . __('Error occurred while checking file', 'security_malware_firewall')
                    . '</b>'
                    . ' '
                    . (!empty($result['path']) ? $result['path'] : '')
                    . ':'
                    . ' '
                    . !empty($result['error']) ? $result['error'] : __('internal directory scan error', 'security_malware_firewall')
                        . "</li>";
                } else {
                    $file_is_ok = !static::doUploadStopOnStatus($result['status']) &&
                        !static::doUploadStopOnSeverity(
                            $result['severity'],
                            self::$uploads_severity_warning_levels['wordpress_module']
                        );
                    if ( !$file_is_ok ) {
                        // Cutting useless path prefix
                        $title = json_encode($result['weak_spots']);
                        $title = $title ? esc_html($title) : 'Unknown weak spots';
                        $display_path = preg_replace('#^.wp-content.upgrade[\\\\].+?[\\\\]#', '', $result['path']);
                        $details .= "<li><a title='Weak spots JSON: $title'>&nbsp;&nbsp;&nbsp;&nbsp;$display_path: <b>{$result['status']}</b></a></li>";
                        $overall_result = false;
                        $fired_result = $result;
                    }
                }
            }
        } catch (\Exception $e) {
            $details = '<li>&nbsp;&nbsp;<b>'
                . __('internal directory scan error', 'security_malware_firewall')
                . ':'
                . ' '
                . $e;
            $overall_result = true;
        }

        $details .= '</ul>';
        $details .= '</div>';

        show_message('&nbsp;&nbsp;' . __('Checked files count: ', 'security-malware-firewall') . $total_files_checked_count);

        // Output result message
        if ( $overall_result ) {
            if (self::checkVulnerability($source)) {
                $message = '<b>' . __('If you want to continue the installation, add the file and click install.', 'security-malware-firewall') . '</b>';
                echo Escape::escKsesPreset($message, 'spbc_cdn_checker_table');
                ?>
                <form method="post" enctype="multipart/form-data" class="wp-upload-form"
                action="<?php echo esc_url(self_admin_url('update.php?action=upload-plugin')); ?>">
                    <?php wp_nonce_field('plugin-upload'); ?>
                    <label class="screen-reader-text" for="pluginzip">
                        <?php
                        /* translators: Hidden accessibility text. */
                        _e('Plugin zip file', 'security-malware-firewall');
                        ?>
                    </label>
                    <input type="hidden" name="trust_module" value="true">
                    <input type="hidden" name="file_path" id="file_path">
                    <input type="file" id="pluginzip" name="pluginzip" accept=".zip"/>
                    <?php submit_button(__('Install Now', 'security-malware-firewall'), '', 'install-plugin-submit', false); ?>
                </form>
                <?php

                return new \WP_Error(
                    'spbct.plugin_check.malware_found',
                    '<b>' . __('Found vulnerabilities ', 'security-malware-firewall') . '. Installation interrupted.</b>'
                );
            }
            show_message('&nbsp;&nbsp;<b>No malware has been found. Installation continues.</b>');
        } else {
            show_message('&nbsp;&nbsp;' . __('List of infected files:', 'security-malware-firewall'));
            show_message($details);
            // Remove the directory with bad plugin
            Data::removeDirectoryRecursively($source);

            $firewall = new Firewall();
            $checker = new self();
            $firewall->loadFwModule($checker);
            $reason = __('Malicious signature found.', 'security-malware-firewall');
            if ( isset($fired_result) && !empty($fired_result['weak_spots']) && !empty($fired_result['weak_spots']['SIGNATURES']) ) {
                $signatures = $fired_result['weak_spots']['SIGNATURES'];
                foreach ($signatures as $_row => $signature_ids) {
                    $reason_signature_ids[] = is_array($signature_ids) ? implode(array_values($signature_ids)) : $signature_ids;
                }
                $reason = __('Malicious signatures found: ', 'security-malware-firewall') . '#' . implode(',#', $reason_signature_ids);
            }
            $checker->logDenyUploadedModule(new Result(
                array(
                    'module' => $checker->module_name,
                    'ip' => IP::get(),
                    'status' => 'DENY_BY_WAF_FILE',
                    'pattern' => $reason,
                    'triggered_for' => 'uploaded_module',
                    'waf_action' => 'DENY',
                )
            ));

            return new \WP_Error(
                'spbct.plugin_check.malware_found',
                '<b>Malware has been found. Installation interrupted.</b>'
            );
        }

        return $source;
    }

    /**
     * Prepared method to check packed files.
     * @param $archive_path
     * @return Result|false
     */
    private function checkUploadedArchive($archive_path)
    {
        global $wp_filesystem;

        if ( !empty($archive_path) && is_string($archive_path)) {
            if (!function_exists('unzip_file')) {
                require_once ABSPATH . 'wp-admin/includes/file.php';
            }

            if ( ! $wp_filesystem ) {
                WP_Filesystem();
            }

            $destination = wp_get_upload_dir()['path'] . DIRECTORY_SEPARATOR . 'spbct_' . time();
            if (!is_dir($destination)) {
                mkdir($destination);
            }

            $unzipped = unzip_file($archive_path, $destination);
            if (is_wp_error($unzipped)) {
                return false;
            }

            $unzipped_files = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator($destination, FilesystemIterator::SKIP_DOTS),
                \RecursiveIteratorIterator::CHILD_FIRST,
                \RecursiveIteratorIterator::CATCH_GET_CHILD
            );

            $result = false;

            foreach ($unzipped_files as $path => $dir) {
                if ($dir->isDir()) {
                    $unzipped_files->next();
                } else {
                    $result = $this->checkFileContent($path);
                }

                if ($result !== false) {
                    $wp_filesystem->delete($destination, true);
                    return $result;
                }
            }
            $wp_filesystem->delete($destination, true);
        }

        return false;
    }

    /**
     * AJAX callback for details about latest blocked file. Returns HTML code that will be used to replace origin
     * WP message of unsuccessful upload via wp_send_json for action 'wp_ajax_spbc_check_file_block'
     */
    public static function uploadCheckerGetLastBlockInfo()
    {
        spbc_check_ajax_referer('spbc_secret_nonce', 'security');

        global $wpdb, $spbc;

        $timestamp = intval(Post::get('timestamp'));

        // Select only latest ones.
        $result = $wpdb->get_results(
            'SELECT *'
            . ' FROM ' . SPBC_TBL_FIREWALL_LOG
            . ' WHERE status = "DENY_BY_WAF_FILE" AND entry_timestamp > ' . ($timestamp - 2)
            . ' ORDER BY entry_timestamp DESC LIMIT 1;',
            OBJECT
        );

        if ( $result ) {
            $result = $result[0];
            $result->pattern = str_replace('\\', '\\\\', $result->pattern);
            $out    = array(
                'blocked' => true,
                'warning' => $spbc->data["wl_brandname"] . __(
                    ': File was blocked by Upload Checker module.',
                    'security-malware-firewall'
                ),
                'pattern_title' => __('Detected pattern: ', 'security-malware-firewall'),
                'pattern' => json_decode($result->pattern, true),
            );
        } else {
            $out = array('blocked' => false);
        }

        wp_send_json($out);
    }

    /**
     * Check if it needs to stop upload process on severity level.
     * @param string $severity file severity
     * @param array $warning_levels warning levels for selected type
     * @return bool
     */
    private static function doUploadStopOnSeverity($severity, $warning_levels)
    {
        if (
            empty($severity) ||
            !is_string($severity) ||
            !in_array($severity, array('CRITICAL', 'SUSPICIOUS', 'DANGER')) ||
            !is_array($warning_levels)
        ) {
            return false;
        }
        return in_array($severity, $warning_levels);
    }

    /**
     * Check if it needs to stop upload process on file status statement.
     * @param $status
     * @return bool
     */
    private static function doUploadStopOnStatus($status)
    {
        return is_string($status) && !in_array($status, array('OK', 'APROVED', 'APPROVED_BY_CT', 'MODIFIED', 'UNKNOWN'));
    }


    /**
     * Log a record. The same code as WAF log. :(
     * @param Result $upload_checker_result
     * @return void
     */
    public function logDenyUploadedModule(Result $upload_checker_result)
    {
        //single quote escaping
        foreach ($upload_checker_result->pattern as &$pattern ) {
            $pattern = str_replace(array("'", '"'), array("ESC_S_QUOTE", "ESC_D_QUOTE"), $pattern);
        }
        unset($pattern);

        $pattern         = ! empty($upload_checker_result->pattern)
            ? json_encode($upload_checker_result->pattern)
            : '';
        $triggered_for   = ! empty($upload_checker_result->triggered_for)
            ? Helper::prepareParamForSQLQuery(substr($upload_checker_result->triggered_for, 0, 100), '')
            : '';
        $page_url        = substr(
            addslashes(
                (Server::get('HTTPS') !== 'off' ? 'https://' : 'http://')
                . Server::get('HTTP_HOST')
                . Server::get('REQUEST_URI')
            ),
            0,
            4096
        );
        $http_user_agent = Server::get('HTTP_USER_AGENT')
            ? addslashes(htmlspecialchars(substr(Server::get('HTTP_USER_AGENT'), 0, 300)))
            : 'unknown';
        $ip              = $upload_checker_result->ip;
        $time            = time();
        $status          = $upload_checker_result->status;
        $request_method  = Server::get('REQUEST_METHOD');
        $x_forwarded_for = addslashes(htmlspecialchars(substr(Server::get('HTTP_X_FORWARDED_FOR'), 0, 15)));
        $network         = $upload_checker_result->network;
        $mask            = $upload_checker_result->mask;
        $is_personal     = $upload_checker_result->is_personal;
        $country_code    = $upload_checker_result->country_code;
        $id              = md5($upload_checker_result->ip . $http_user_agent . $upload_checker_result->status . $upload_checker_result->waf_action . $upload_checker_result->triggered_for);
        $signature_id    = $upload_checker_result->signature_id;

        $query = "INSERT INTO " . SPBC_TBL_FIREWALL_LOG
            . " SET
                entry_id        = '$id',
				ip_entry        = '$ip',
				entry_timestamp = $time,
				status          = '$status',
				pattern         = IF('$pattern' = '', NULL, '$pattern'),
				signature_id    = IF('$signature_id' = 0, NULL, '$signature_id'),
				triggered_for   = IF('$triggered_for' = '', NULL, '$triggered_for'),
				requests        = 1,
				page_url        = '$page_url',
				http_user_agent = '$http_user_agent',
				request_method  = '$request_method',
				x_forwarded_for = IF('$x_forwarded_for' = '', NULL, '$x_forwarded_for'),
				network         = IF('$network' = '' OR '$network' IS NULL, NULL, $network),
				mask            = IF('$mask' = '' OR '$mask' IS NULL, NULL, $mask),
				country_code    = IF('$country_code' = '',    NULL, '$country_code'),
				is_personal     = $is_personal
			ON DUPLICATE KEY UPDATE
				ip_entry        = ip_entry,
				entry_timestamp = $time,
				status          = '$status',
				pattern         = IF('$pattern' = '', NULL, '$pattern'),
				signature_id    = IF('$signature_id' = 0, NULL, '$signature_id'),
				triggered_for   = IF('$triggered_for' = '', NULL, '$triggered_for'),
				requests        = requests + 1,
				page_url        = '$page_url',
				http_user_agent = http_user_agent,
				request_method  = '$request_method',
				x_forwarded_for = IF('$x_forwarded_for' = '', NULL, '$x_forwarded_for'),
				network         = IF('$network' = '' OR '$network' IS NULL, NULL, $network),
				mask            = IF('$mask' = '' OR '$mask' IS NULL, NULL, $mask),
				country_code    = IF('$country_code' = '',    NULL, '$country_code'),
				is_personal     = $is_personal";

        $this->db->execute($query);
    }

    /**
     * @return bool
     */
    public static function checkVulnerability($source)
    {
        $plugin_data_from_source = static::getPluginDataFromSource($source);

        if ( $plugin_data_from_source !== false ) {
            $plugin_data_to_check = $plugin_data_from_source;
        } else {
            $plugin_data_to_check = static::getPluginDataFromFilesGlob($source);
        }
        return $plugin_data_to_check !== false && VulnerabilityAlarm::checkSinglePluginViaAPI($plugin_data_to_check['Name'], $plugin_data_to_check['Version']);
    }

    /**
     * Check the glob result of source path to find any php file to get the plugin data.
     * @param string $source Path to the plugin source folder
     * @return array|false
     */
    private static function getPluginDataFromSource($source)
    {
        if ( !empty($source) && is_dir($source) && is_readable($source) ) {
            foreach ( glob($source . '/*.php') as $module_file_path ) {
                if ( !is_file($module_file_path) || !is_readable($module_file_path) ) {
                    continue;
                }
                $plugin_data = @get_file_data($module_file_path, array(
                    'Version' => 'Version',
                    'Name' => 'Plugin Name',
                ));
                if ( empty($plugin_data['Name']) || empty($plugin_data['Version']) ) {
                    continue;
                }
                return array(
                    'Name' => $plugin_data['Name'],
                    'Version' => $plugin_data['Version'],
                );
            }
        }
        return false;
    }

    /**
     * Check the file from $_FILES to get the plugin data.
     * @param string $source Path to the plugin source folder
     * @return array|false
     */
    private static function getPluginDataFromFilesGlob($source)
    {
        if ( !isset($_FILES['pluginzip']['name']) ) {
            return false;
        }

        preg_match('#^([A-Za-z\d]+)#', $_FILES['pluginzip']['name'], $match);
        if ( !isset($match[0]) ) {
            return false;
        }

        $plugin_data = get_plugin_data($source . $match[0] . '.php');

        if ( !empty($plugin_data['Name']) && !empty($plugin_data['Version']) ) {
            return array(
                'Name' => $plugin_data['Name'],
                'Version' => $plugin_data['Version'],
            );
        }

        return false;
    }
}
