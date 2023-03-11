<?php

namespace CleantalkSP\SpbctWP\Scanner;

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
            $sql   = "SELECT COUNT(ID) as cnt
			FROM {$wpdb->posts} as posts
			WHERE
				post_status = 'publish' AND
				post_type IN ('post', 'page') AND
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
                    if ( HTTP::getResponseCode($page['guid']) === 200 ) {
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
        return wp_count_posts()->publish + wp_count_posts('page')->publish;
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

            foreach ( $results as $result ) {
                $page['found']['redirects']  = $result->type === 'redirects' ? 1 : 0;
                $page['found']['dbd']        = $result->type === 'dbd' ? 1 : 0;
                $page['found']['signatures'] = $result->type === 'signatures' ? 1 : 0;
                $page['found']['csrf']       = $result->type === 'csrf' ? 1 : 0;

                $page['found']['line']   = $result->line;
                $page['found']['needle'] = $result->needle;

                $bad_line = str_replace(
                    $result->found,
                    '__SPBCT_RED__' . $result->found . '__SPBCT_RED_END__',
                    $result->surroundings
                );

                $weak_spots['CRITICAL'][$result->line] = $bad_line;
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
}
