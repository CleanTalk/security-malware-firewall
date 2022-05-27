<?php

namespace CleantalkSP\SpbctWP\Scanner;

use CleantalkSP\SpbctWP\Helper as SpbcHelper;
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
		$amount           = isset( $params['amount'] )     ? $params['amount']     : 10;
		$last_scan        = isset( $params['last_scan'] )  ? $params['last_scan']  : date( 'Y-m-d H:i:s', time() - 86400 * 30 );
		$this->signatures = isset( $params['signatures'] ) ? $params['signatures'] : array();
        $this->domains_exceptions = isset( $params['domains_exceptions'] ) ? $params['domains_exceptions'] : array();
        
        // Check typs
        $this->csrf_check = ! empty( $params['csrf_check'] );
			
		// Do all the work
		$this->get_pages_uri($amount, $last_scan);  // Get content to check
		
		if(!empty($this->pages)){
			// Count everything
			$this->posts_count = count($this->pages);
			$this->get_content();
		}
		
		if(!empty($this->pages)){
			$this->check();
		}
		
		if(count($this->post_checked)){
            $this->post__all__mark_as_checked();
        }
	}
	
	/**
	 * Counts pages left to to check (without or passed meta 'spbc_frontend__last_checked').
	 *
	 * @param $last_scan
	 * @param string $type
	 * @param int    $out
	 *
	 * @return int
	 */
	public static function count_unchecked_pages($last_scan = null, $type = 'all', $out = 0)
	{
		global $wpdb;
		
		$last_scan = $last_scan ?: date('Y-m-d H:i:s', time() - 86400 * 30);
		
		if(in_array($type, array('all', 'post'))){
			$sql = "SELECT COUNT(ID) as cnt
			FROM {$wpdb->posts} as posts
			WHERE
				post_status = 'publish' AND
				post_type IN ('post', 'page') AND
				NOT EXISTS(
					SELECT post_id, meta_key
						FROM {$wpdb->postmeta} as meta
						WHERE posts.ID = meta.post_id AND
							meta.meta_key = 'spbc_frontend__last_checked' AND
							meta.meta_value < '$last_scan'
				);";
			$posts = $wpdb->get_results($sql, ARRAY_A);
			$out += $posts[0]['cnt'];
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
	public function get_pages_uri($amount, $last_scan)
	{
		global $wpdb;
		
		// Get page from POSTS table
		$sql = "SELECT guid, ID, post_type
			FROM {$wpdb->posts} as posts
			WHERE
				post_status IN('publish','inherit') AND
				post_type IN('post','page') AND
				NOT EXISTS(
					SELECT post_id, meta_key
						FROM {$wpdb->postmeta} as meta
						WHERE posts.ID = meta.post_id AND
							meta.meta_key = 'spbc_frontend__last_checked' AND
							meta.meta_value < '$last_scan'
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
	public function get_content(){
		foreach($this->pages as $key => &$page){
			if(filter_var($page['guid'], FILTER_VALIDATE_URL)){
				if( HTTP::getResponseCode($page['guid']) === 200){
					$result = HTTP::getContentFromURL($page['guid']);
					if(empty($result['error'])){
                        $this->pages[$key]['content'] = $result;
                    }else{
						$this->post__mark_as_checked( $page['ID'] );
						unset( $this->pages[ $key ] );
					}
				}else{
					$this->post__mark_as_checked( $page['ID'] );
					unset($this->pages[$key]);
				}
			}else{
				$this->post__mark_as_checked( $page['ID'] );
				unset( $this->pages[ $key ] );
			}
		}
	}
	
	/**
	 * @todo make it
	 *
	 * Get line number of needle in haystack
	 *
	 * @param $haystack
	 * @param $needle
	 */
	private function get_line_number_of_content($haystack, $needle){
	
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
        if( $this->csrf_check ){
            $check_list[] = 'csrf';
        }

		
		foreach ($this->pages as &$page){

            $fe_scanner = new FrontendScan( $check_list );
			
			$page['bad'] = false;
			$weak_spots = array();
			
			$results = $fe_scanner
				->setHomeUrl( get_option( 'home' ) )
				->setExceptUrls( $this->domains_exceptions )
				->setSignatures( $this->signatures )
				->setContent( $page['content'] )
				->check()
				->getResult();
			
			$page['bad'] = $results ? true : $page['bad'];
			
			foreach ( $results as $result ){
				
				$page['found']['redirects']  = $result['type'] === 'redirects'  ? 1 : 0;
				$page['found']['dbd']        = $result['type'] === 'dbd'        ? 1 : 0;
				$page['found']['signatures'] = $result['type'] === 'signatures' ? 1 : 0;
				$page['found']['csrf']       = $result['type'] === 'csrf'       ? 1 : 0;
				
				$page['found']['line']       = $result['line'];
				$page['found']['needle']     = $result['needle'];

				$bad_line = str_replace(
					$result['found'],
					'__SPBCT_RED__' . $result['found'] . '__SPBCT_RED_END__',
					$result['found_extended']
				);

                $weak_spots['CRITICAL'][ $result['line'] ] = $bad_line;
				
			}
			
			$page['found']['weak_spots'] = $page['bad'] ? json_encode( $weak_spots ) : null;
			
			$this->post_checked[] = $page['ID'];
		}
	}
	
	/**
	 * Mark checked pages
	 * Sets or update meta for posts spbc_frontend__last_checked === time()
	 */
	public function post__all__mark_as_checked()
	{
		foreach($this->post_checked as $id){
			$this->post__mark_as_checked( $id );
		}
	}
	
	/**
	 * @param int $post_id
	 */
	private function post__mark_as_checked( $post_id ){
		global $wpdb;
		$wpdb->query("INSERT INTO {$wpdb->postmeta} SET
				post_id = $post_id,
				meta_key = 'spbc_frontend__last_checked',
				meta_value = " . time() . "
			ON DUPLICATE KEY UPDATE
				meta_value = " . time() . ";" );
	}
    
    public static function resetCheckResult()
    {
        global $wpdb;
        $wpdb->query("DELETE FROM {$wpdb->postmeta} WHERE meta_key = 'spbc_frontend__last_checked';");
        
        return $wpdb->query('DELETE FROM ' . SPBC_TBL_SCAN_FRONTEND . ';');
    }

}
