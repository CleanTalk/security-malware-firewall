<?php

namespace CleantalkSP\SpbctWP\Scanner;

use CleantalkSP\SpbctWP\API;
use CleantalkSP\SpbctWP\Helpers\HTTP;

/**
 * Class Frontend
 *
 * Scan wordpress public pages for malware
 *
 * @version       2.0.0
 * @package       Security by Cleantalk
 * @category      ScannerFrontend
 * @author        Cleantalk team (welcome@cleantalk.org)
 * @copyright (C) 2014 CleanTalk team (http://cleantalk.org)
 * @license       GNU/GPL: http://www.gnu.org/copyleft/gpl.html
 * @link          https://github.com/CleanTalk/php-antispam
 */
class Frontend
{
    /**
     * @var int Count checked pages
     * @psalm-suppress PossiblyUnusedProperty
     */
    public $posts_count = 0;

    /**
     * @var array
     */
    public $pages = array();        // Posts to check with ID and URI

    /**
     * Posts IDs that have been checked
     * @var array
     */
    public $post_checked = array();

    /**
     * Default pages to check
     * @var array
     * @psalm-suppress UnusedProperty
     */
    private static $default_pages = array(
        '/index.php',
        '/wp-signup.php',
        '/wp-login.php',
    );

    /**
     * Signatures with HTML and JS type
     *
     * @var
     */
    private $signatures;

    private $domains_exceptions;

    private $csrf_check;

    /**
     * @param array $params
     */
    public function __construct($params = array())
    {
        // Setting params
        // Amount of pages to check in execution
        $amount                   = isset($params['amount']) ? $params['amount'] : 10;
        $last_scan                = isset($params['last_scan']) ? $params['last_scan'] : date(
            'Y-m-d H:i:s',
            time() - 86400 * 30
        );
        $this->signatures         = isset($params['signatures']) ? $params['signatures'] : array();
        $this->domains_exceptions = isset($params['domains_exceptions']) ? $params['domains_exceptions'] : array();

        // Check typs
        $this->csrf_check = ! empty($params['csrf_check']);

        // Do all the work
        $this->getPagesUri($amount, $last_scan);  // Get content to check

        if ( ! empty($this->pages) ) {
            // Count everything
            $this->posts_count = count($this->pages);
            $this->getContent();
        }

        if ( ! empty($this->pages) ) {
            $this->check();
        }

        if ( count($this->post_checked) ) {
            $this->postAllMarkAsChecked();
        }
    }

    /**
     * Counts pages left to check (without or passed meta 'spbc_frontend__last_checked').
     *
     * @param $last_scan
     * @param string $type
     * @param int $out
     *
     * @return int
     */
    public static function countUncheckedPages($last_scan = null, $type = 'all', $out = 0)
    {
        global $wpdb, $spbc;

        $last_scan = $last_scan ?: date('Y-m-d H:i:s', time() - 86400 * 30);
        $last_scan_timestamp = strtotime($last_scan);

        /**
         * If not the first scan, then add the condition to the request
         */
        $not_first_scan_sql = '';
        if (isset($spbc->data['scanner']['first_scan__front_end']) && (int)$spbc->data['scanner']['first_scan__front_end'] === 0) {
            $not_first_scan_sql = "post_modified > '" . $last_scan . "' AND";
        }

        if ( in_array($type, array('all', 'post')) ) {
            $posts_table_name = $wpdb->prefix . 'posts';
            $postmeta_table_name = $wpdb->prefix . 'postmeta';
            $sql   = "SELECT COUNT(ID) as cnt
			FROM $posts_table_name as posts
			WHERE
				post_status = 'publish' AND
				post_type IN ('post', 'page') AND
			    $not_first_scan_sql
				NOT EXISTS(
					SELECT post_id, meta_key
						FROM $postmeta_table_name as meta
						WHERE posts.ID = meta.post_id AND
							meta.meta_key = '_spbc_frontend__last_checked' AND
							meta.meta_value > '$last_scan_timestamp'
				) AND NOT EXISTS (
                	SELECT post_id, meta_key
						FROM $postmeta_table_name as meta
						WHERE posts.ID = meta.post_id AND
                   			meta.meta_key = '_spbc_frontend__approved' AND 
                			meta.meta_value = 1
                );";
            $posts = $wpdb->get_results($sql, ARRAY_A);
            $out   += $posts[0]['cnt'];
        }

        /*
        @todo default page check
        if(in_array($type, array('all', 'default'))){
            $out += count(self::$default_pages);
        }
        //*/

        return $out;
    }

    /**
     * Getting POSTS headers: guid, ID, post_type
     *
     * @param $amount
     * @param $last_scan
     */
    public function getPagesUri($amount, $last_scan)
    {
        global $wpdb, $spbc;

        $last_scan_timestamp = strtotime($last_scan);

        /**
         * If not the first scan, then add the condition to the request
         */
        $not_first_scan_sql = '';
        if (isset($spbc->data['scanner']['first_scan__front_end']) && (int)$spbc->data['scanner']['first_scan__front_end'] === 0) {
            $not_first_scan_sql = "post_modified > '" . $last_scan . "' AND";
        }

        // Get page from POSTS table
        $sql         = "SELECT guid, ID, post_type
			FROM {$wpdb->posts} as posts
			WHERE
				post_status IN('publish','inherit') AND
				post_type IN('post','page') AND
			    $not_first_scan_sql
				NOT EXISTS(
					SELECT post_id, meta_key
						FROM {$wpdb->postmeta} as meta
						WHERE posts.ID = meta.post_id AND
							meta.meta_key = '_spbc_frontend__last_checked' AND
							meta.meta_value > '$last_scan_timestamp'
				) AND NOT EXISTS (
                	SELECT post_id, meta_key
						FROM {$wpdb->postmeta} as meta
						WHERE posts.ID = meta.post_id AND
                   			meta.meta_key = '_spbc_frontend__approved' AND 
                			meta.meta_value = 1
                )
			LIMIT $amount";

        $this->pages = $wpdb->get_results($sql, ARRAY_A);

        /*
        @todo default page check
        //Add default page to check only if 0 < posts to check > $amount
        if(count($this->pages) < $amount  && count($this->pages) != 0){
            foreach(self::$default_pages as $page){
                $this->pages[] = array(
                    'guid' => $page,
                    'ID' => get_site_url() . $page,
                    'post_type' => 'default',
                );
            }
        }
        //*/
    }

    /**
     * Get content from given URL
     */
    public function getContent()
    {
        if (defined('SPBCT_ALLOW_CURL_SINGLE') && SPBCT_ALLOW_CURL_SINGLE) {
            foreach ( $this->pages as $key => &$page ) {
                if ( filter_var($page['guid'], FILTER_VALIDATE_URL) ) {
                    $result = HTTP::getContentFromURL($page['guid']);
                    if (empty($result['error'])) {
                        $this->pages[ $key ]['content'] = $result;
                    } else {
                        $this->postMarkAsChecked($page['ID']);
                        unset($this->pages[ $key ]);
                    }
                } else {
                    $this->postMarkAsChecked($page['ID']);
                    unset($this->pages[$key]);
                }
            }
        } else {
            $http    = new \CleantalkSP\Common\HTTP\Request();
            $results = $http
                ->setUrl(array_column($this->pages, 'guid'))
                ->setPresets('get')
                ->addCallback(
                    static function ($response) {
                        if ( (int) $response->getResponseCode() !== 200 ) {
                            return ['error' => 'Wrong HTTP code'];
                        }

                        return $response->getContentProcessed();
                    },
                    [],
                    null,
                    true
                )
                ->request();

            foreach ( $this->pages as $key => $page ) {
                if ( empty($results[$page['guid']]['error']) ) {
                    $this->pages[$key]['content'] = $results[$page['guid']];
                } else {
                    $this->postMarkAsChecked($this->pages[$key]['ID']);
                    unset($this->pages[$key]);
                }
            }
        }
    }

    public static function getTotalPages()
    {
        global $wpdb;
        $query = "SELECT COUNT(*) FROM $wpdb->posts WHERE post_type IN ( 'post', 'page' ) AND post_status = 'publish'";
        return $wpdb->get_var($query);
    }

    /**
     * @param $haystack
     * @param $needle
     *
     * @todo make it
     *
     * Get line number of needle in haystack
     *
     * @ToDo remove these suppresses after implementing the method
     * @psalm-suppress UnusedMethod
     * @psalm-suppress UnusedParam
     */
    private function getLineNumberOfContent($haystack, $needle)
    {
    }

    /**
     * Checks current $this->pages for malware.
     * Set results in
     * $page['found']['redirects'] - redirects flag
     * $page['found']['dbd'] - drive by download flag
     * $page['found']['signatures'] - signatures flag
     * $page['found']['weak_spots']['CRITICAL'][LINE_NUMBER] - found
     */
    public function check()
    {
        // Getting signatures
        $check_list = array('redirects', 'dbd', 'signatures_js', 'signatures_html');
        if ( $this->csrf_check ) {
            $check_list[] = 'csrf';
        }


        foreach ( $this->pages as &$page ) {
            $fe_scanner = new FrontendScan($check_list);

            $page['bad'] = false;
            $weak_spots  = array();

            $results = $fe_scanner
                ->setHomeUrl(get_option('home'))
                ->setExceptUrls($this->domains_exceptions)
                ->setSignatures($this->signatures)
                ->setContent($page['content'])
                ->check()
                ->getResult();

            $page['bad'] = $results ? true : $page['bad'];

            $page['found']['redirects']  = 0;
            $page['found']['dbd']        = 0;
            $page['found']['signatures'] = 0;
            $page['found']['csrf']       = 0;

            foreach ( $results as $result ) {
                switch ($result->type) {
                    case 'redirects':
                        $page['found']['redirects'] = 1;
                        break;
                    case 'dbd':
                        $page['found']['dbd'] = 1;
                        break;
                    case 'signatures':
                        $page['found']['signatures'] = 1;
                        break;
                    case 'csrf':
                        $page['found']['csrf'] = 1;
                        break;
                }

                $page['found']['line']   = $result->line;
                $page['found']['needle'] = $result->needle;

                $bad_line = str_replace(
                    $result->found,
                    '__SPBCT_RED__' . $result->found . '__SPBCT_RED_END__',
                    $result->surroundings
                );

                $bad_code_len = 200;
                $weak_code_start_pos = strpos($page['content'], htmlspecialchars_decode($result->found));
                $page_content_before_bad_code = substr($page['content'], $weak_code_start_pos - $bad_code_len, $bad_code_len);
                $page_content_after_bad_code = substr($page['content'], $weak_code_start_pos + strlen($result->found), $bad_code_len);

                $weak_spots['CRITICAL'][$result->line] = $bad_line;
                $weak_spots['CONTENT_BEFORE'][$result->line] = $page_content_before_bad_code;
                $weak_spots['CONTENT_AFTER'][$result->line] = $page_content_after_bad_code;
            }

            $page['found']['weak_spots'] = $page['bad'] ? json_encode($weak_spots) : null;

            $this->post_checked[] = $page['ID'];
        }
    }

    /**
     * Mark checked pages
     * Sets or update meta for posts spbc_frontend__last_checked === time()
     */
    public function postAllMarkAsChecked()
    {
        foreach ( $this->post_checked as $id ) {
            $this->postMarkAsChecked($id);
        }
    }

    /**
     * @param int $post_id
     */
    private function postMarkAsChecked($post_id)
    {
        update_post_meta($post_id, '_spbc_frontend__last_checked', time());
    }

    public static function resetCheckResult()
    {
        global $wpdb;
        $wpdb->query("DELETE FROM {$wpdb->postmeta} WHERE meta_key = '_spbc_frontend__last_checked' OR meta_key = 'spbc_frontend__last_checked';");

        return $wpdb->query('DELETE FROM ' . SPBC_TBL_SCAN_FRONTEND . ';');
    }

    /**
     * Sending logs about scanned frontend malware
     *
     * @return void
     * @throws \Exception
     */
    public static function sendFmsLogs()
    {
        global $spbc, $wpdb;

        $spbc->data['scanner']['last_scan__front_end'] = time();

        $fms_logs_data = $wpdb->get_results(
            'SELECT page_id, url, weak_spots, dbd_found, redirect_found, signature, csrf'
            . ' FROM ' . SPBC_TBL_SCAN_FRONTEND
            . ' WHERE approved IS NULL OR approved <> 1;',
            ARRAY_A
        );

        function spbc_check_encoding($string)
        {
            if (spbc_check_ascii($string)) {
                return $string;
            }

            $string = utf8_decode($string);

            if (spbc_check_ascii($string)) {
                return $string;
            } else {
                return false;
            }
        }

        $fms_logs_data_prepare = [];
        $fms_skipped_urls_from_sending = [];
        foreach ($fms_logs_data as $fms_value) {
            if (!is_string($fms_value['weak_spots'])) {
                $fms_skipped_urls_from_sending[] = array('url' => $fms_value['url'], 'skip_reason' => 'weak_spots is not a string');
                continue;
            }

            $weak_spots_decoded = json_decode($fms_value['weak_spots'], true);

            if ( is_null($weak_spots_decoded) ) {
                $fms_skipped_urls_from_sending[] = array('url' => $fms_value['url'], 'skip_reason' => 'can not decode JSON of weak_spots');
                continue;
            } else {
                $weak_codes         = !empty($weak_spots_decoded['CRITICAL'])       ? $weak_spots_decoded['CRITICAL']       : null;
                $weak_codes_before  = !empty($weak_spots_decoded['CONTENT_BEFORE']) ? $weak_spots_decoded['CONTENT_BEFORE'] : null;
                $weak_codes_after   = !empty($weak_spots_decoded['CONTENT_AFTER'])  ? $weak_spots_decoded['CONTENT_AFTER']  : null;
            }

            if (is_null($weak_codes)) {
                $fms_skipped_urls_from_sending[] = array('url' => $fms_value['url'], 'skip_reason' => 'weak_spot has no CRITICAL severity');
                continue;
            }

            foreach ( $weak_codes as $weak_code_line => $weak_code ) {
                $weak_code = htmlspecialchars_decode($weak_code);
                $weak_code = str_replace(array("__SPBCT_RED__", "__SPBCT_RED_END__"), "", $weak_code);

                $page_content_before_bad_code = ! is_null($weak_codes_before) ? $weak_codes_before[$weak_code_line] : '';
                $page_content_after_bad_code = ! is_null($weak_codes_after) ? $weak_codes_after[$weak_code_line] : '';

                if (
                    !spbc_check_encoding($weak_code) ||
                    !spbc_check_encoding($page_content_before_bad_code) ||
                    !spbc_check_encoding($weak_code)
                ) {
                    $fms_skipped_urls_from_sending[] = array('url' => $fms_value['url'], 'skip_reason' => 'non-ASCII symbols found in weak_spots or nearby code');
                    continue(2);
                }

                if (strpos($weak_code, 'iframe') !== false) {
                    $weak_type = 'DBD';
                } elseif (strpos($weak_code, 'location') !== false) {
                    $weak_type = 'REDIR';
                } elseif (strpos(json_encode(['cid', 'uid', 'account', 'user']), $weak_code) !== false) {
                    $weak_type = 'CSRF';
                } else {
                    $weak_type = 'SIG';
                }

                //[<URL>,<bad code>, <100 before>, <100 after>, <modified datetime>, <danger_code_type>]
                $fms_logs_data_prepare[] = [
                    $fms_value['url'],
                    $weak_code,
                    $page_content_before_bad_code,
                    $page_content_after_bad_code,
                    get_the_modified_date('Y-m-d H:i:s', $fms_value['page_id']),
                    $weak_type
                ];
            }
        }

        // save skipped url to the data for further investigations
        if ( ! empty($fms_skipped_urls_from_sending) ) {
            $spbc->data['fms_log_skipped_urls_from_sending'] = $fms_skipped_urls_from_sending;
            $spbc->save('data');
        }

        $scanner_start_local_date = isset($spbc->data['scanner']['scanner_start_local_date'])
            ? $spbc->data['scanner']['scanner_start_local_date']
            : current_time('Y-m-d H:i:s');

        $total_site_pages = isset($spbc->data['scanner']['total_site_pages']) ? $spbc->data['scanner']['total_site_pages'] : self::getTotalPages();

        if (count($fms_logs_data_prepare) > 0) {
            $json_data = json_encode($fms_logs_data_prepare);
            if ( empty($json_data) ) {
                throw new \Exception(' Frontend result send: can not encode data to JSON');
            }
            $result_fms = API::method__security_fms_logs(
                $spbc->settings['spbc_key'],                 // API key
                $total_site_pages,  // Total pages
                count($fms_logs_data_prepare),               // Total infected pages
                $scanner_start_local_date,                   // Scanner start date
                $json_data // Logs data
            );
            if ( ! empty($result_fms['error']) ) {
                $error_msg = 'Unknown error.';
                if (isset($result_fms['error_message'])) {
                    $error_msg = $result_fms['error_message'];
                } elseif (is_string($result_fms['error'])) {
                    $error_msg = $result_fms['error'];
                }
                throw new \Exception(' Frontend result send: ' . $error_msg);
            }
        }
    }
}
