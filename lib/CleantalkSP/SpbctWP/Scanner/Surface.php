<?php

namespace CleantalkSP\SpbctWP\Scanner;

use CleantalkSP\SpbctWP\Helper as Helper;

class Surface
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
	
	private $output_file_details = array();
	
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
		
        $this->output_file_details = !empty($params['output_file_details']) ? $this->filter_params($params['output_file_details']) : array();
		
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
		
		if( $this->output_file_details ){
      
		    foreach( $this->files as &$file ){
		        
                $file_tmp = array();
		        foreach( $this->output_file_details as $detail ){
		            $file_tmp[ $detail ] = $file[ $detail ];
                }
                $file = $file_tmp;
		        
            } unset( $file );
        }
		
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
                @new \FilesystemIterator(
                    $main_path,
                    \FilesystemIterator::CURRENT_AS_PATHNAME | \FilesystemIterator::KEY_AS_FILENAME
                ) as $file_name => $path
            ){
            	// Skip bad paths
                if( ! $file_name || ! $path ){
                	continue;
                }
            	
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
        }catch(\Exception $e){
        
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
			$it = new \FilesystemIterator($main_path, \FilesystemIterator::CURRENT_AS_PATHNAME | \FilesystemIterator::KEY_AS_FILENAME);

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
            
            // This order is important!!!
			$this->files[$key]['path']  = substr(self::is_windows() ? str_replace('/', '\\', $val['path']) : $val['path'], $path_offset);
			$this->files[$key]['size']  = filesize($val['path']);
			$this->files[$key]['perms'] = substr(decoct(fileperms($val['path'])), 3);
			$this->files[$key]['mtime'] = filemtime($val['path']);
			
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
	 * Checks if the current system is Windows or not
	 * 
	 * @return boolean 
	 */
	static function is_windows(){
		return strpos(strtolower(php_uname('s')), 'windows') !== false ? true : false;
	}
	
	/**
	 * Check dir is empty
	 *
	 * @param $dir
	 * @return bool
	 */
	static function dir_is_empty($dir) {
		$handle = opendir($dir);
		while (false !== ($entry = readdir($handle))) {
			if ($entry !== "." && $entry !== "..") {
				closedir($handle);
				return false;
			}
		}
		closedir($handle);

		return true;
	}
}
