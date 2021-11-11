<?php

use CleantalkSP\SpbctWP\Helper as Helper;

class SpbcScaner
{
	public $path         = ''; // Main path
	public $path_lenght  = 0;
	
	/** @var array Description Extensions to check */
	public $ext             = array();
	/** @var array Exception for extensions */
	public $ext_except      = array();
	
	/** @var array Exception for files paths */
	public $files_except    = array();
	
	/** @var array Exception for directories */
	public $dirs_except     = array(); 
	
	/** @var array Mandatory check for files paths */
	public $files_mandatory = array(); 
	
	/** @var array Mandatory check for directories */
	public $dirs_mandatory  = array();
	
	public $files = array();
	public $dirs  = array();
	
	public $files_count = 0;
	public $dirs_count  = 0;
	
	private $file_start = 0;
	private $file_curr  = 0;
	private $file_max   = 1000000;
	
	function __construct($path, $rootpath, $params = array('count' => true))
	{
		// INITILAZING PARAMS
		
		// Main directory
		$path = realpath($path);
		if(!is_dir($path))     die("Scan '$path' isn't directory");
		if(!is_dir($rootpath)) die("Root '$rootpath' isn't directory");
		$this->path_lenght = strlen($rootpath);
		
		// Processing filters		
		$this->ext          = !empty($params['extensions'])            ? $this->filter_params($params['extensions'])             : array();
		$this->ext_except   = !empty($params['extensions_exceptions']) ? $this->filter_params($params['extensions_exceptions'])  : array();
		$this->files_except = !empty($params['file_exceptions'])       ? $this->filter_params($params['file_exceptions'])        : array();
		$this->dirs_except  = !empty($params['dir_exceptions'])        ? $this->filter_params($params['dir_exceptions'])         : array();
		
		// Mandatory files and dirs
		$this->files_mandatory = !empty($params['files_mandatory']) ? $this->filter_params($params['files_mandatory']) : array();
		$this->dirs_mandatory  = !empty($params['dirs_mandatory'])  ? $this->filter_params($params['dirs_mandatory'])  : array();
		
		// Initilazing counters
		$this->file_start =   isset($params['offset']) ? $params['offset'] : 0;
		$this->file_max   =   isset($params['offset']) && isset($params['amount']) ? $params['offset'] + $params['amount'] : 1000000;
		
		// DO STUFF
		
		// Only count files
		if(!empty($params['count'])){
			$this->count_files__mandatory($this->files_mandatory);
			$this->count_files_in_dir($path);
			return;
		}
		// Getting files and dirs considering filters
		$this->get_files__mandatory($this->files_mandatory);
		$this->get_file_structure($path);
		// Files
		$this->files_count = count($this->files);
		$this->file__details($this->files, $this->path_lenght);
		
		// Directories
		// $this->dirs[]['path'] = $path;
		// $this->dirs_count = count($this->dirs);
		// $this->dir__details($this->dirs, $this->path_lenght);

		
	}
	
	/**
	 * * Function coverting icoming parametrs to array even if it is a string like 'some, example, string'
	 *
	 * @param $filter
	 *
	 * @return array|null
	 */
	public function filter_params($filter)
	{
		if(!empty($filter)){
			if(!is_array($filter)){
				if(strlen($filter)){
					$filter = explode(',', $filter);
				}
			}
			foreach($filter as $key => &$val){
				$val = trim($val);
			}
			return $filter;
		}else{
			return null;
		}
	}
	
	/**
	 * Counts given mandatory files
	 * 
	 * @param array $files Files to count
	 */
	public function count_files__mandatory($files){
		foreach($files as $file){
			if(is_file($file))
				$this->files_count++;
		}
	}
	
	/**
	 * Count files in directory
	 * 
	 * @param string $main_path Path to count files in
	 */
    public function count_files_in_dir($main_path)
    {
        try{
            foreach(
                new FilesystemIterator(
                    $main_path,
                    FilesystemIterator::CURRENT_AS_PATHNAME | FilesystemIterator::KEY_AS_FILENAME
                ) as $file_name => $path
            ){
        
                if( is_dir( $path ) ){
            
                    // Directory names filter
                    foreach( $this->dirs_except as $dir_except ){
                        if( strpos( $path, $dir_except ) ){
                            continue( 2 );
                        }
                    }
            
                    $this->count_files_in_dir( $path );
                }else{
            
                    // Extensions filter
                    if( $this->ext_except || $this->ext ){
                        $tmp = explode( '.', $path );
                        if(
                            ( $this->ext_except && in_array( $tmp[ count( $tmp ) - 1 ], $this->ext_except, true ) ) ||
                            ( $this->ext && ! in_array( $tmp[ count( $tmp ) - 1 ], $this->ext, true ) )
                        ){
                            continue;
                        }
                    }
            
                    // Filenames exception filter
                    if( ! empty( $this->files_except ) && in_array( $file_name, $this->files_except, true ) ){
                        continue;
                    }
            
                    $this->files_count ++;
                }
            }
        }catch(Exception $e){
        
        }
    }
    
    /**
	 * Getting mandatory files
	 * 
	 * @param array $files Files to get
	 */
	public function get_files__mandatory($files){
		foreach($files as $file){
			if(is_file($file)){
				$this->files[]['path'] = $file;
				$this->file_curr++;
			}
		}
	}
	
	/**
	 * Get all files from directory
	 * 
	 * @param string $main_path Path to get files from
	 * @return void
	 */
	public function get_file_structure($main_path)
	{
		if(is_dir($main_path) && $this::dir_is_empty($main_path)) {
			return;
		}

		try {
			$it = new FilesystemIterator($main_path, FilesystemIterator::CURRENT_AS_PATHNAME | FilesystemIterator::KEY_AS_FILENAME);

			foreach( $it as $file_name => $path ){

				// Return if file limit is reached
				if($this->file_curr >= $this->file_max)
					return;

				if(is_file($path)){

					// Extensions filter
					if( $this->ext_except || $this->ext ){
						$tmp = explode( '.', $path );
						if(
							( $this->ext_except && in_array( $tmp[ count( $tmp ) - 1 ], $this->ext_except, true ) ) ||
							( $this->ext && ! in_array( $tmp[ count( $tmp ) - 1 ], $this->ext, true ) )
						){
							continue;
						}
					}

					// Filenames exception filter
					if( ! empty( $this->files_except ) && in_array( $file_name, $this->files_except, true ) ){
						continue;
					}

					$this->file_curr++;

					// Skip if start is not reached
					if($this->file_curr-1 < $this->file_start)
						continue;

					$this->files[]['path'] = $path;

				}elseif(is_dir($path)){

					// Directory names filter
					foreach( $this->dirs_except as $dir_except ){
						if( strpos( $path, $dir_except ) ){
							continue( 2 );
						}
					}

					$this->get_file_structure($path);
					if($this->file_curr > $this->file_start)
						$this->dirs[]['path'] = $path;

				}elseif(is_link($path)){
					error_log('LINK FOUND: ' . $path);
				}
			}
		} catch (\Exception $exception) {
			return;
		}
	}
	
	/**
	 * Getting file details like last modified time, size, permissions
	 *  
	 * @param array $file_list Array of abolute paths to files
	 * @param int $path_offset Length of CMS root path
	 */
	public function file__details($file_list, $path_offset)
	{
		foreach($file_list as $key => $val){
			// Cutting file's path, leave path from CMS ROOT to file
			$this->files[$key]['path']  = substr(self::is_windows() ? str_replace('/', '\\', $val['path']) : $val['path'], $path_offset);
			$this->files[$key]['mtime'] = filemtime($val['path']);
			$this->files[$key]['perms'] = substr(decoct(fileperms($val['path'])), 3);
			$this->files[$key]['size']  = filesize($val['path']);
			
			// Fast hash
			$this->files[$key]['fast_hash']  = md5($this->files[$key]['path']);
			
			// Full hash
			$this->files[$key]['full_hash'] = is_readable($val['path'])
				? md5_file($val['path'])
				: 'unknown';
		}
	}

	/**
	 * Getting dir details
	 * 
	 * @param array $dir_list Array of abolute paths to directories
	 * @param int $path_offset Length of CMS root path
	 */
	public function dir__details($dir_list, $path_offset)
	{
		foreach($dir_list as $key => $val){
			$this->dirs[$key]['path']  = substr(self::is_windows() ? str_replace('/', '\\', $val['path']) : $val['path'], $path_offset);
			$this->dirs[$key]['mtime'] = filemtime($val['path']);
			$this->dirs[$key]['perms'] = substr(decoct(fileperms($val['path'])), 2);
		}
	}

	/**
	 * Getting real hashs of CMS core files
	 *
	 * @param string $cms CMS name
	 * @param string $version CMS version
	 * @return array Array with all CMS files hashes or Error Array
	 */
	static function get_hashes($cms, $version)
	{
		$file_path = 'https://cleantalk-security.s3.amazonaws.com/cms_checksums/'.$cms.'/'.$version.'/'.$cms.'_'.$version.'.json.gz';
		
		if( Helper::http__request__get_response_code($file_path) == 200) {

			$gz_data = Helper::http__request__get_content($file_path);

			if(empty($gz_data['error'])) {

				if ( function_exists( 'gzdecode' ) ) {

					$data = gzdecode( $gz_data );

					if ( $data !== false ) {

						$result = json_decode($data, true);
						$result = $result['data'];

						if(count($result['checksums']) == $result['checksums_count']){
							return $result;
						}else
							return array('error' => 'FILE_DOESNT_MATHCES');

					} else {
						return array( 'error' => 'COULDNT_UNPACK' );
					}
				} else {
					return array( 'error' => 'Function gzdecode not exists. Please update your PHP to version 5.4' );
				}
			}
		}else
			return array('error' =>'Remote file not found or WordPress version is not supported. Yo could try again later (few hours). Contact tech support if it repeats.');
	}

	/**
	 * Getting real hashs of plugin's or theme's files
	 * 
	 * @param string $cms CMS name
	 * @param string $type Plugin type (plugin|theme)
	 * @param string $plugin Plugin name
	 * @param string $version Plugin version
	 * @return array Array with all CMS files hashes or Error Array
	 */
	static function get_hashes__plug($cms, $type, $plugin, $version)
	{
		
		$file_path = 'https://s3-us-west-2.amazonaws.com/cleantalk-security/extensions_checksums/'.$cms.'/'.$type.'s/'.$plugin.'/'.$version.'.csv.gz';
		
		if( Helper::http__request__get_response_code( $file_path ) == 200 ) {

			$gz_data = Helper::http__request__get_content($file_path);

			if(empty($gz_data['error'])) {

				if ( function_exists( 'gzdecode' ) ) {

					$data = gzdecode( $gz_data );

					if ( $data !== false ) {

						$lines = Helper::buffer__parse__csv($data);

						if( count( $lines ) > 0 ) {

							$result = array();

							foreach( $lines as $hash_info ) {

								if(empty($hash_info)) continue;

								preg_match('/.*\.(\S*)$/', $hash_info[0], $matches);
								$ext      = isset($matches[1]) ? $matches[1] : '';
								if(!in_array($ext, array('php','html'))) continue;

								$result[] = $hash_info;

							}

							if(count($result)){
								return $result;
							}else
								return array('error' =>'BAD_HASHES_FILE__PLUG');

						}else
							return array('error' => 'Empty hashes file');
					}else
						return array( 'error' => 'COULDNT_UNPACK' );
				}else
					return array( 'error' => 'Function gzdecode not exists. Please update your PHP to version 5.4' );
			}else
				return $gz_data;
		}else
			return array('error' =>'REMOTE_FILE_NOT_FOUND_OR_VERSION_IS_NOT_SUPPORTED__PLUG');
	}
	
	public static function get_hashes__signature($last_signature_update)
	{
		$version_file_url = 'https://s3-us-west-2.amazonaws.com/cleantalk-security/security_signatures/version.txt';
				
		if( Helper::http__request__get_response_code($version_file_url) == 200) {
			
			$latest_signatures = Helper::http__request__get_content($version_file_url);
			
			if( empty( $latest_signatures['error'] ) && strtotime($latest_signatures)){
			
				if(strtotime($last_signature_update) < strtotime($latest_signatures)){
					
					// _v2 since 2.31 version
					$file_url = 'https://s3-us-west-2.amazonaws.com/cleantalk-security/security_signatures/security_signatures_v2.csv.gz';
					
					if( Helper::http__request__get_response_code($file_url) == 200) {

						$gz_data = Helper::http__request__get_content($file_url);
						
						if(empty($gz_data['error'])){
							
							if(function_exists('gzdecode')){
								
								$buffer = gzdecode($gz_data);

								if($buffer !== false){
									
									// Set map for file
									$map = strpos( $file_url, '_mapped' ) !== false
										? Helper::buffer__csv__get_map( $buffer ) // Map from file
										: array( 'id', 'name', 'body', 'type', 'attack_type', 'submitted', 'cci' ); // Default map

									$out = array();
									while( $buffer ){
										$out[] = Helper::buffer__csv__pop_line_to_array( $buffer, $map );
									}

									return $out;
								}else
									return array('error' => 'COULDNT_UNPACK');
							}else
								return array('error' => 'Function gzdecode not exists. Please update your PHP to version 5.4');
						}else
							return $gz_data;
					}else
						return array('error' =>'NO_FILE');
				}else
					return array('error' =>'UP_TO_DATE');
			}else
				return array('error' =>'WRONG_VERSION_FILE');
		}else
			return array('error' =>'NO_VERSION_FILE');
	}

	/**
	 * Getting real hashs of approved files
	 * 
	 * @param string $cms CMS name
	 * @param string $type Type - approved/rejected
	 * @return array Array with all files hashes or Error Array
	 */
	public static function get_hashes__approved_files($cms, $type, $version) {
		
		$file_path = 'https://cleantalk-security.s3-us-west-2.amazonaws.com/extensions_checksums/'.$cms.'/'.$type.'/'.$version.'.csv.gz';
		
		if( Helper::http__request__get_response_code( $file_path ) == 200 ) {

			$gz_data = Helper::http__request__get_content($file_path);

			if(empty($gz_data['error'])) {

				if ( function_exists( 'gzdecode' ) ) {

					$data = gzdecode( $gz_data );

					if ( $data !== false ) {

						$lines = Helper::buffer__parse__csv($data);

						if( count( $lines ) > 0 ) {

							$result = array();

							foreach( $lines as $hash_info ) {

								if(empty($hash_info)) continue;

								preg_match('/.*\.(\S*)$/', $hash_info[0], $matches);
								$ext      = isset($matches[1]) ? $matches[1] : '';
								if(!in_array($ext, array('php','html'))) continue;

								$result[] = $hash_info;

							}

							if(count($result)){
								return $result;
							}else
								return array('error' =>'BAD_HASHES_FILE');

						} else {
							return array('error' => 'Empty hashes file');
						}

					} else {
						return array( 'error' => 'COULDNT_UNPACK' );
					}
				} else {
					return array( 'error' => 'Function gzdecode not exists. Please update your PHP to version 5.4' );
				}
			}
		}else
			return array('error' =>'REMOTE_FILE_NOT_FOUND');		
	}
	
	/**
	 * Scanning file
	 *
	 * @param string $root_path Path to CMS's root folder
	 * @param array $file_info Array with files data (path, real_full_hash, source_type, source, version), other is optional
	 * @param null|string $file_original
	 *
	 * @return array|false
	 */
	public static function file__scan__differences( $root_path, $file_info, $file_original = null )
	{		
		if(file_exists($root_path.$file_info['path'])){
			
			if(is_readable($root_path.$file_info['path'])){
				
				
				$file_original = $file_original
					? $file_original
					: self::file__get_original( $file_info );
					
				$file = file($root_path.$file_info['path']);

				// @todo Add proper comparing mechanism
				// Comparing files strings
				for($difference = array(), $row = 0; !empty($file[$row]); $row++){
					if(isset($file[$row]) || isset($file_original[$row])){
						if(!isset($file[$row]))          $file[$row] = '';
						if(!isset($file_original[$row])) $file_original[$row] = '';
						if(strcmp(trim($file[$row]), trim($file_original[$row])) != 0){
							$difference[] = $row+1;
						}
					}
				}
				
				return $difference;
				
			}else
				$output = array('error' => 'NOT_READABLE');
		}else
			$output = array('error' => 'NOT_EXISTS');
		
		return !empty($output) ? $output : false;
		
	}
	
	/**
	 * Scan file thru malware sinatures
	 * 
	 * @param string $root_path Path to CMS's root folder
	 * @param array $file_info Array with files data (path, real_full_hash, source_type, source, version), other is optional
	 * @param array $signatures Set of signatures
	 * 
	 * @return array|false False or Array of found bad sigantures
	 */
	public static function file__scan__for_signatures($root_path, $file_info, $signatures)
	{
		if(file_exists($root_path.$file_info['path'])){
			
			if(is_readable($root_path.$file_info['path'])){
				
				$verdict = array();
				foreach ((array)$signatures as $signature){
					
					if( $signature['type'] === 'FILE' ) {
						if ( $file_info['full_hash'] === $signature['body'] ) {
							$verdict['SIGNATURES'][1][] = $signature['id'];
						}
					}
					
					if( in_array( $signature['type'], array('CODE_PHP', 'CODE_JS', 'CODE_HTML' ) ) ) {
						
						$file_content = file_get_contents( $root_path . $file_info['path'] );
						$is_regexp = preg_match( '@^/.*/$@', $signature['body'] ) || preg_match( '@^#.*#$@', $signature['body'] );
						
						if(
							( $is_regexp   && preg_match( $signature['body'], $file_content ) ) ||
							( ! $is_regexp && ( strripos( $file_content, stripslashes( $signature['body'] ) ) !== false || strripos( $file_content, $signature['body'] ) !== false) )
						){
							$line_number = self::file__get_string_number_with_needle( $root_path . $file_info['path'], $signature['body'], $is_regexp );
							$verdict['SIGNATURES'][ $line_number ][] = $signature['id'];
						}
						
					}
				}
				// Removing signatures from the previous result
				$file_info['weak_spots'] = ! empty( $file_info['weak_spots'] ) ? json_decode( $file_info['weak_spots'], true ) : array();
				if( isset( $file_info['weak_spots']['SIGNATURES'] ) )
					unset( $file_info['weak_spots']['SIGNATURES'] );
				
				$verdict = Helper::array_merge__save_numeric_keys__recursive($file_info['weak_spots'], $verdict);
				
				// Processing results
				if(!empty($verdict)){
					$output['weak_spots'] = $verdict;
					$output['severity']   = 'CRITICAL';
					$output['status']     = 'INFECTED';
				}else{
					$output['weak_spots'] = null;
					$output['severity']   = null;
					$output['status']     = 'OK';
				}
				
			}else
				$output = array('error' => 'NOT_READABLE');
		}else
			$output = array('error' => 'NOT_EXISTS');
		
		return $output;
	}
	
	/**
	 * Scan file thru heuristic
	 * 
	 * @param string $root_path Path to CMS's root folder
	 * @param array $file_info Array with files data (path, real_full_hash, source_type, source, version), other is optional
	 * 
	 * @return array|false False or Array of found bad constructs sorted by severity
	 */
	public static function file__scan__heuristic($root_path, $file_info)
	{
        $scanner = new SpbcScannerH(array( 'path' => $root_path.$file_info['path'] ));
        
        if ( !empty( $scanner -> error ) ){
            return array(
                'weak_spots' => null,
                'severity'   => null,
                'status'     => 'OK',
                'includes' => array(),
            );
            return $scanner -> error;
        }
        $scanner -> process_file();
        
        // Saving only signatures from the previous result
        $file_info['weak_spots'] = !empty($file_info['weak_spots']) ? json_decode($file_info['weak_spots'], true) : array();
        $file_info['weak_spots'] = isset( $file_info['weak_spots']['SIGNATURES'] )
            ? array( 'SIGNATURES' => $file_info['weak_spots']['SIGNATURES'] )
            : array();
        
        $verdict = Helper::array_merge__save_numeric_keys__recursive($file_info['weak_spots'], $scanner->verdict);
        
        $output['includes'] = $scanner->includes;
        
        // Processing results
        if(!empty($verdict)){
            $output['weak_spots'] = $verdict;
            $output['severity']   = array_key_exists('CRITICAL', $verdict) ? 'CRITICAL' : (array_key_exists('DANGER', $verdict) ? 'DANGER' : 'SUSPICIOUS');
            $output['status']     = array_key_exists('CRITICAL', $verdict) ? 'INFECTED' : 'OK';
        }else{
            $output['weak_spots'] = null;
            $output['severity']   = null;
            $output['status']     = 'OK';
        }
		
		return $output;
	}
	
	/**
	 * Get original file's content
	 *
	 * @param array $file_info Array with files data (path, real_full_hash, source_type, source), other is optional
	 *
	 * @return string
	 */
	public static function file__get_original($file_info)
	{
		$file_info['path'] = str_replace('\\', '/', $file_info['path']); // Replacing win slashes to Orthodox slashes =) in case of Windows
		
		switch( $file_info['source_type'] ){
			case 'PLUGIN':
				$file_info['path'] = preg_replace('@/wp-content/plugins/.*?/(.*)$@i', '$1',$file_info['path']);
				$url_path = 'https://plugins.svn.wordpress.org/'.$file_info['source'].'/tags/'.$file_info['version'].'/'.$file_info['path'];
				break;
			case 'THEME':
				$file_info['path'] = preg_replace('@/wp-content/themes/.*?/(.*)$@i', '$1',$file_info['path']);
				$url_path = 'https://themes.svn.wordpress.org/'.$file_info['source'].'/'.$file_info['version'].'/'.$file_info['path'];
				break;
			default:
				$url_path = 'http://cleantalk-security.s3.amazonaws.com/cms_sources/'.$file_info['source'].'/'.$file_info['version'].$file_info['path'];
				break;
		}
		
		if( Helper::http__request__get_response_code($url_path) == 200 ){
			$out = Helper::http__request__get_content($url_path);
		}else
			$out = array('error' => 'Couldn\'t get original file');
		
		
		return $out;
	}
	
	/**
	 * Checks if the current system is Windows or not
	 * 
	 * @return boolean 
	 */
	static function is_windows(){
		return strpos(strtolower(php_uname('s')), 'windows') !== false ? true : false;
	}
	
	/**
	 * Returns number of string with a given char position
	 *
	 * @param string $file_path   String to search in
	 * @param int $signature_body Character position
	 * @param bool $is_regexp     Flag. Is signature is regular expression?
	 *
	 * @return int String number
	 */
	static function file__get_string_number_with_needle($file_path, $signature_body, $is_regexp = false){
		
		$file = file( $file_path );
		$out = 0;
		
		foreach( $file as $number => $line ){
			if(
				( $is_regexp   && preg_match( $signature_body, $line ) ) ||
				( ! $is_regexp && strripos( $line, stripslashes( $signature_body ) ) !== false )
			){
				$out = $number;
			}
		}
		
		return $out;
	}

	/**
	 * Check dir is empty
	 *
	 * @param $dir
	 * @return bool
	 */
	static function dir_is_empty($dir) {
		if (is_dir($dir)) {
			if ($handle = opendir($dir)) {
				while (false !== ($entry = readdir($handle))) {
					if ($entry !== "." && $entry !== "..") {
						closedir($handle);
						return false;
					}
				}
				closedir($handle);				
			}
		}
		return true;
	}
}
