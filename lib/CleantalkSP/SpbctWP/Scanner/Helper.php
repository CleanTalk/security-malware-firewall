<?php


namespace CleantalkSP\SpbctWP\Scanner;

use CleantalkSP\SpbctWP;

class Helper
{
    
    /**
     * Getting real hashs of CMS core files
     *
     * @param string $cms CMS name
     * @param string $version CMS version
     * @return array Array with all CMS files hashes or Error Array
     */
    public static function getHashesForCMS($cms, $version)
    {
        $file_path = 'https://cleantalk-security.s3.amazonaws.com/cms_checksums/'.$cms.'/'.$version.'/'.$cms.'_'.$version.'.json.gz';
        
        if( SpbctWP\Helper::http__request__get_response_code($file_path) == 200) {
            
            $gz_data = SpbctWP\Helper::http__request__get_content($file_path);
            
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
	        return $gz_data;
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
    public static function getHashesForModules($cms, $type, $plugin, $version)
    {
        
        $file_path = 'https://s3-us-west-2.amazonaws.com/cleantalk-security/extensions_checksums/'.$cms.'/'.$type.'s/'.$plugin.'/'.$version.'.csv.gz';
        
        if( SpbctWP\Helper::http__request__get_response_code( $file_path ) == 200 ) {
            
            $gz_data = SpbctWP\Helper::http__request__get_content($file_path);
            
            if(empty($gz_data['error'])) {
                
                if ( function_exists( 'gzdecode' ) ) {
                    
                    $data = gzdecode( $gz_data );
                    
                    if ( $data !== false ) {
                        
                        $lines = SpbctWP\Helper::buffer__parse__csv($data);
                        
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
    
    public static function getSignatures($last_signature_update)
    {
        $version_file_url = 'https://s3-us-west-2.amazonaws.com/cleantalk-security/security_signatures/version.txt';
        
        if( SpbctWP\Helper::http__request__get_response_code($version_file_url) == 200) {
            
            $latest_signatures = SpbctWP\Helper::http__request__get_content($version_file_url);
            
            if( empty( $latest_signatures['error'] ) && strtotime($latest_signatures)){
                
                if(strtotime($last_signature_update) < strtotime($latest_signatures)){
                    
                    // _v2 since 2.31 version
                    $file_url = 'https://s3-us-west-2.amazonaws.com/cleantalk-security/security_signatures/security_signatures_v2.csv.gz';
                    
                    if( SpbctWP\Helper::http__request__get_response_code($file_url) == 200) {
                        
                        $gz_data = SpbctWP\Helper::http__request__get_content($file_url);
                        
                        if(empty($gz_data['error'])){
                            
                            if(function_exists('gzdecode')){
                                
                                $buffer = gzdecode($gz_data);
                                
                                if($buffer !== false){
                                    
                                    // Set map for file
                                    $map = strpos( $file_url, '_mapped' ) !== false
                                        ? SpbctWP\Helper::buffer__csv__get_map( $buffer ) // Map from file
                                        : array( 'id', 'name', 'body', 'type', 'attack_type', 'submitted', 'cci' ); // Default map
                                    
                                    $out = array();
                                    while( $buffer ){
                                        $out[] = SpbctWP\Helper::buffer__csv__pop_line_to_array( $buffer, $map );
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
    public static function getHashesForApprovedFiles($cms, $type, $version) {
        
        $file_path = 'https://cleantalk-security.s3-us-west-2.amazonaws.com/extensions_checksums/'.$cms.'/'.$type.'/'.$version.'.csv.gz';
        
        if( SpbctWP\Helper::http__request__get_response_code( $file_path ) == 200 ) {
            
            $gz_data = SpbctWP\Helper::http__request__get_content($file_path);
            
            if(empty($gz_data['error'])) {
                
                if ( function_exists( 'gzdecode' ) ) {
                    
                    $data = gzdecode( $gz_data );
                    
                    if ( $data !== false ) {
                        
                        $lines = SpbctWP\Helper::buffer__parse__csv($data);
                        
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
                        }else
                            return array('error' => 'Empty hashes file');
                    }else
                        return array( 'error' => 'COULDNT_UNPACK' );
                }else
                    return array( 'error' => 'Function gzdecode not exists. Please update your PHP to version 5.4' );
            }
	        return $gz_data;
        }else
            return array('error' =>'REMOTE_FILE_NOT_FOUND');
    }
    
    /**
     * Scanning file
     *
     * @param string $root_path Path to CMS's root folder
     * @param array $file_info Array with files data (path, real_full_hash, source_type, source, version), other is optional
     * @param string $file_original
     *
     * @return array|false
     */
    public static function getDifferenceFromOriginal( $root_path, $file_info, $file_original = '' )
    {
        if(file_exists($root_path.$file_info['path'])){
            
            if(is_readable($root_path.$file_info['path'])){
                
                $file_original = $file_original ?: self::getOriginalFile($file_info);
                
                $file = file($root_path.$file_info['path']);
                
                // @todo Add proper comparing mechanism
                // Comparing files strings
                for($output = array(), $row = 0; !empty($file[$row]); $row++){
                    if(isset($file[$row]) || isset($file_original[$row])){
                        if(!isset($file[$row]))          $file[$row] = '';
                        if(!isset($file_original[$row])) $file_original[$row] = '';
                        if(strcmp(trim($file[$row]), trim($file_original[$row])) != 0){
                            $output[] = $row+1;
                        }
                    }
                }
            }else
                $output = array('error' => 'NOT_READABLE');
        }else
            $output = array('error' => 'NOT_EXISTS');
        
        return !empty($output) ? $output : false;
    }
    
    /**
     * Get original file's content
     *
     * @param array $file_info Array with files data (path, real_full_hash, source_type, source), other is optional
     *
     * @return string|array
     */
    public static function getOriginalFile($file_info)
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
    
        return (int) SpbctWP\Helper::http__request__get_response_code($url_path) === 200
            ? SpbctWP\Helper::http__request__get_content($url_path)
            : array('error' => "Couldn't get an original file");
    }
    
    /**
     * Returns number of string with a given char position
     *
     * @param string $file_path      String to search in
     * @param int    $signature_body Character position
     * @param bool   $is_regexp      Flag. Is signature is regular expression?
     *
     * @return int String number
     */
    public static function file__get_string_number_with_needle($file_path, $signature_body, $is_regexp = false){
        
        $file = file( $file_path );
        $out = 1;
        
        foreach( $file as $number => $line ){
            if(
                ( $is_regexp   && preg_match( $signature_body, $line ) ) ||
                ( ! $is_regexp && strripos( $line, stripslashes( $signature_body ) ) !== false )
            ){
                $out = $number + 1;
            }
        }
        
        return $out;
    }
}