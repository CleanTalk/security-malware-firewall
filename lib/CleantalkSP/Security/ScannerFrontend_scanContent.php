<?php

namespace CleantalkSP\Security;

/**
 * Class ScannerFrontend_scanContent
 *
 * Scan any content for frontend malware (HTML, JS)
 *
 * @version       1.1.0
 * @package       Security by Cleantalk
 * @category      ScannerFrontend
 * @author        Cleantalk team (welcome@cleantalk.org)
 * @copyright (C) 2014 CleanTalk team (http://cleantalk.org)
 * @license       GNU/GPL: http://www.gnu.org/copyleft/gpl.html
 * @link          https://github.com/CleanTalk/php-antispam
 */
class ScannerFrontend_scanContent {
	
	/**
	 * Given conten to check
	 * @var string
	 */
	private $content;
	/**
	 * DOMDocument created from content
	 * @var \DOMDocument
	 */
	private $dom;
	/**
	 * @var \DOMXPath Contains JS tags from content
	 */
	private $js_tags = null;
	/**
	 * URL that consider as home URL. All links with this host consider as harmful
	 * @var string
	 */
	private $home_url;
	/**
	 * URL that consider as harmful
	 * @var array|string
	 */
	private $except_urls = array();
	
	
	/**
	 * Signatures with HTML code
	 * @var array
	 */
	private $signatures_html;
	/**
	 * Signatures with JS code
	 * @var array
	 */
	private $signatures_js;
	
	/*
	 * Flags for scan type
	 */
	private $scan_for_redirect        = false;
	private $scan_for_dbd             = false;
	private $scan_for_signatures_js   = false;
	private $scan_for_signatures_html = false;
	
	/**
	 * Results of a scan
	 * @var array
	 */
	private $result = array();
	
	/**
	 * Constructor
	 *
	 * @param array $check_list
	 */
	function __construct( $check_list = array('redirects', 'dbd', 'signatures_js', 'signatures_html') )
	{
		$this->scan_for_redirect        = in_array( 'redirects',       $check_list );
		$this->scan_for_dbd             = in_array( 'dbd',             $check_list );
		$this->scan_for_signatures_js   = in_array( 'signatures_js',   $check_list );
		$this->scan_for_signatures_html = in_array( 'signatures_html', $check_list );
	}
	
	/**
	 * Method which gathering all check types
	 *
	 * Liquid interface
	 *
	 * @return ScannerFrontend_scanContent
	 */
	public function check(){
		
		$this->scan_for_redirect        = $this->scan_for_redirect        && $this->home_url;
		$this->scan_for_dbd             = $this->scan_for_dbd             && $this->home_url;
		$this->scan_for_signatures_js   = $this->scan_for_signatures_js   && $this->signatures_js;
		$this->scan_for_signatures_html = $this->scan_for_signatures_html && $this->signatures_html;
		
		$this->result = array_merge(
			$this->scan_for_redirect  ? $this->check__for_redirects()        : array(),
			$this->scan_for_dbd       ? $this->check__for_driveByDownload()  : array(),
			$this->scan_for_signatures_js ? $this->check__for_signatures__js()   : array(),
			$this->scan_for_signatures_html  ? $this->check__for_signatures__html() : array()
		);
		
		return $this;
	}
	
	/**
	 * Check given DOMDocument for redirects
	 *
	 * @return array
	 */
	private function check__for_redirects(){
		
		if( ! $this->js_tags ){
			// Getting JS tags to check
			$xpath = new \DOMXPath($this->dom);
			$this->js_tags = $xpath->evaluate( "/html//script" );
		}
		
		$results = $this->check__for_anything(
			$this->js_tags,
			'/location(?:\s*\.\s*href\s*)?\s*=\s*["\'](?:http[s]?:\/\/)(?:www\.)?(?!'.$this->home_url.').*/',
			'regexp'
		);
		
		foreach ( $results as $result ){
			$out[] = array(
				'type'           => 'redirects',
				'line'           => $result['haystack_original'] instanceof \DOMElement
					? $result['haystack_original']->getLineNo()
					: 0,
				'found'          => htmlentities( $result['found'] ),
				'found_extended' => htmlentities( substr(
					$result['haystack'],
					strpos( $result['haystack'], $result['found'] ) - 40 > 0
						? strpos( $result['haystack'], $result['found'] ) - 40
						: 0,
					strlen( $result['found'] ) + 80
				)),
				'needle'        => $result['needle'],
			);
		}
		
		return isset( $out ) ? $out : array();
	}
	
	/**
	 * Check given DOMDocument for drive by download attack
	 *
	 * @return array
	 */
	private function check__for_driveByDownload(){
		
		// Getting JS tags to check
		$xpath   = new \DOMXPath( $this->dom );
		$iframes = $xpath->evaluate( "/html//iframe" );
		
		$url_exceptions = $this->except_urls
			? $this->home_url . '|' . implode( '|', $this->except_urls )
			: $this->home_url;
		
		$results = array();
		foreach($iframes as $iframe){
			$results = array_merge(
				$results,
				$this->check__for_anything(
					$iframe,
					'#^http[s]?://(?!([a-zA-Z0-9-]*\.)*(' . $url_exceptions . ')).*#',
					'regexp'
				)
			);
		}
		
		foreach ( $results as $result ){
			
			$out[] = array(
				'type'           => 'dbd',
				'line'           => $result['haystack_original'] instanceof \DOMElement
					? $result['haystack_original']->getLineNo() - 1
					: 0,
				'found'          => htmlentities( $result['found'] ),
				'found_extended' => htmlentities( substr(
					$this->content,
					strpos( $this->content, $result['found'] ) - 40 > 0
						? strpos( $this->content, $result['found'] ) - 40
						: 0,
					strlen( $result['found'] ) + 80
				)),
				'needle'        => $result['needle'],
			);
		}
		
		return isset( $out ) ? $out : array();
		
	}
	
	/**
	 * Check given DOMDocument for JS signatures
	 *
	 * @return array
	 */
	private function check__for_signatures__js(){
		
		if( ! $this->js_tags ){
			// Getting JS tags to check
			$xpath = new \DOMXPath($this->dom);
			$this->js_tags = $xpath->evaluate( "/html//script" );
		}
		
		$results = $this->check__for_anything(
			$this->js_tags,
			$this->signatures_js
		);
		
		foreach ( $results as $result ){
			$out[] = array(
				'type'           => 'signatures',
				'line'           => $result['haystack_original'] instanceof \DOMElement
					? $result['haystack_original']->getLineNo()
					: 0,
				'found'          => htmlentities( $result['found'] ),
				'found_extended' => htmlentities( substr(
					$result['haystack'],
					strpos( $result['haystack'], $result['found'] ) - 40 > 0
						? strpos( $result['haystack'], $result['found'] ) - 40
						: 0,
					strlen( $result['found'] ) + 80
				)),
				'needle'        => $result['needle'],
			);
		}
		
		return isset( $out ) ? $out : array();
	}
	
	/**
	 * * Check given content for HTML signatures
	 *
	 * @return array
	 */
	private function check__for_signatures__html(){

		/* @ToDo We need to check the Dom Node instead the string to get line number
		$xpath = new \DOMXPath($this->dom);
		$html_hode = $xpath->evaluate( "/html" );
		*/

		$results = $this->check__for_anything(
			$this->content,
			$this->signatures_html
		);
		
		foreach ( $results as $result ){
			$out[] = array(
				'type'           => 'signatures',
				'line'           => $result['haystack_original'] instanceof \DOMElement
					? $result['haystack_original']->getLineNo()
					: 0,
				'found'          => htmlentities( $result['found'] ),
				'found_extended' => htmlentities( substr(
					$result['haystack'],
					strpos( $result['haystack'], $result['found'] ) - 40 > 0
						? strpos( $result['haystack'], $result['found'] ) - 40
						: 0,
					strlen( $result['found'] ) + 80
				)),
				'needle'        => $result['needle'],
			);
		}
		
		return isset( $out ) ? $out : array();
	}
	
	/**
	 * Universal method to check any type of threat
	 *
	 * @param array|string|\DOMElement $haystacks
	 * @param array|string $needles
	 * @param string $search_type
	 *
	 * @return array
	 */
	private function check__for_anything( $haystacks, $needles, $search_type = 'string' ){
		
		$haystacks = is_string($haystacks) ? array($haystacks) : $haystacks;
		$needles   = is_string($needles)   ? array($needles)   : $needles;
		
		if( $haystacks instanceof \DOMElement && $haystacks->tagName === 'iframe'){
			$iframe = $haystacks;
			$haystacks = array(
				$iframe->getAttribute('src'),
				$iframe->getAttribute('data-src'),
				$iframe->getAttribute('data-frame-src'),
			);
		}
		
		foreach($haystacks as $key => $haystack){
			
			// Getting text value for haystack
			$haystack = $haystack instanceof \DOMElement
				? $haystack->nodeValue
				: $haystack;
			
			foreach($needles as $needle){
				
				$signature = null;
				// If $needle is a signature
				if( is_array( $needle ) ){
					
					$signature = $needle;
					
					// Getting type of search needle
					$search_type = preg_match( '@^/.*/$@', $needle['body'] ) || preg_match( '@^#.*#$@', $needle['body'] )
						? 'regexp'
						: $search_type;
						
					// Gettin the body
					$needle = $needle['body'];
					
				}
				
				switch($search_type){
					
					// Check with strings
					case 'string':
						$pos = strpos($haystack, $needle);
						if($pos !== false){
							$out[] = array(
								'haystack_original' => isset( $iframe ) ? $iframe : $haystacks[$key],
								'haystack'  => $haystack,
								'found'     => substr( $haystack, $pos, strlen( $needle ) ),
								'needle'    => $signature,
							);
						}
						break;
					
					// Check with regular expression
					case 'regexp':
						if(preg_match($needle, $haystack, $matches)){
							$out[] = array(
								'haystack_original' => isset( $iframe ) ? $iframe : $haystacks[$key],
								'haystack'  => $haystack,
								'found'     => $matches[0],
								'needle'    => $signature,
							);
						}
						break;
				}
			}
		}
		
		return isset( $out ) ? $out : array();
	}
	
	/**
	 * Get $this->result
	 *
	 * @return array
	 */
	public function getResult() {
		return $this->result;
	}
	
	/**
	 * Set $this->content and it's derivatives
	 *
	 * @param string $content
	 *
	 * @return ScannerFrontend_scanContent
	 */
	public function setContent( $content = '' ) {
		$this->content = $content;
		
		$this->dom = new \DOMDocument();
		@$this->dom->loadHTML( $this->content );
		
		return $this;
	}
	
	/**
	 * @param string $home_url
	 *
	 * @return ScannerFrontend_scanContent
	 */
	public function setHomeUrl( $home_url ) {
		$this->home_url = parse_url( $home_url, PHP_URL_HOST );
		
		return $this;
	}
	
	/**
	 * @param $signatures
	 *
	 * @return ScannerFrontend_scanContent
	 */
	public function setSignatures( $signatures ) {
		
		// Spplit signatures in two groups
		foreach( $signatures as $signature ){
			
			if( $signature['type'] === 'CODE_HTML' )
				$this->signatures_html[] = $signature;
			
			if( $signature['type'] === 'CODE_JS' )
				$this->signatures_js[] = $signature;
			
		}
		
		return $this;
	}
	
	/**
	 * @param array $except_urls
	 *
	 * @return ScannerFrontend_scanContent
	 */
	public function setExceptUrls( $except_urls ) {
		
		$except_urls = (array) $except_urls;
		
		foreach ($except_urls as &$except_url){
				if( preg_match( '#https?://#', $except_url ) ){
				$except_url = parse_url( $except_url, PHP_URL_HOST );
				$except_url = preg_replace( '#.*?([a-zA-Z0-9-]+\.[a-zA-Z0-9-]+)$#', '$1', $except_url );
			}
		}
		
		$this->except_urls = $except_urls;
		
		return $this;
	}
	
}