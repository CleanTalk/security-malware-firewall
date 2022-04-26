<?php


namespace CleantalkSP\Common\Helpers;

/**
 * Class Data
 * Gather static functions to work with data in different ways
 *
 * @version       1.0.0
 * @package       CleantalkSP\Common\Helpers
 * @author        Cleantalk team (welcome@cleantalk.org)
 * @copyright (C) CleanTalk team (http://cleantalk.org)
 * @license       GNU/GPL: http://www.gnu.org/copyleft/gpl.html
 * @see           https://github.com/CleanTalk/security-malware-firewall
 */
class Data
{
	/**
	 * Function removing non UTF8 characters from array|string|object
	 * Recursive
     *
	 * @param array|object|string $data
	 *
	 * @return array|object|string
	 */
	public static function removeNonUTF8($data)
	{
		// Array || object
		if(is_array($data) || is_object($data)){
			foreach($data as $key => &$val){
				$val = static::removeNonUTF8($val); // Recursion
			}
			unset($val);
			
        //String
        }elseif( ! preg_match('//u', $data) ){
            $data = 'Nulled. Not UTF8 encoded or malformed.';
        }
		
		return $data;
	}
	
	/**
	 * Function convert anything to UTF8 and removes non UTF8 characters
     * Recursive
     *
     * @param array|object|string $obj
	 * @param string              $data_codepage
	 *
	 * @return mixed(array|object|string)
	 */
	public static function convertToUTF8($obj, $data_codepage = null)
	{
		// Array || object
		if(is_array($obj) || is_object($obj)){
			foreach($obj as $key => &$val){
				$val = static::convertToUTF8($val, $data_codepage); // Recursion
			}
			unset($val);
			
        //String
		}elseif(
            function_exists('mb_detect_encoding') &&
            function_exists('mb_convert_encoding') &&
		    ! preg_match('//u', $obj) // Check persistence of non-UTF8 characters
        ){
            $encoding = mb_detect_encoding($obj);
            $encoding = $encoding ?: $data_codepage;
            if($encoding){
                $obj = mb_convert_encoding($obj, 'UTF-8', $encoding);
            }
        }
		return $obj;
	}
    
    /**
     * Converts from UTF8
     * Recursive
     *
     * @param array|object|string $obj
     * @param string              $data_codepage
     *
     * @return mixed (array|object|string)
     */
    public static function convertFromUTF8($obj, $data_codepage = null)
    {
        // Array || object
        if( is_array($obj) || is_object($obj) ){
            
            foreach( $obj as $key => &$val ){
                $val = self::convertFromUTF8($val, $data_codepage); // Recursion
            }
            unset($val);
            
        //String
        }elseif(
            $data_codepage !== null &&
            function_exists('mb_convert_encoding') &&
            preg_match('//u', $obj) // Check persistence of UTF8 characters
        ){
            $obj = mb_convert_encoding($obj, $data_codepage, 'UTF-8');
        }
        
        return $obj;
    }
	
	/**
	 * Checks if the string is valid JSON type
	 *
	 * @param string $string
	 *
	 * @return bool
	 */
	public static function isJSON($string)
	{
		return is_string($string) &&
               is_array(json_decode($string, true));
	}
	
    /**
	 * Get mime type from file or data
	 *
	 * @param string $data Path to file or data
	 * @param string $type Default mime type. Returns if function failed to detect type
	 *
	 * @return string
	 */
    public static function getMIMEType($data, $type = '')
    {
        // Clean input of null bytes
        $data = str_replace(chr(0), '', $data);
        
        if( ! empty($data) && @file_exists($data) ){
            $type = mime_content_type($data);
        }elseif( function_exists('finfo_open') ){
            $finfo = finfo_open(FILEINFO_MIME_TYPE);
            $type  = finfo_buffer($finfo, $data);
            finfo_close($finfo);
        }
        
        return $type;
    }

	/**
     * Recursively deletes the directory and its content
     *
     * @param $dir_path string The directory path to delete
     *
     * @return bool
     */
    public static function removeDirectoryRecursively($dir_path)
    {
        if( is_dir($dir_path) && is_writable($dir_path) ){
            
            $files = glob($dir_path . '/*');
            
            if( ! empty($files) ){
                
                foreach( $files as $file ){
                    
                    if( ! static::remove($file) ){
                        return false;
                    }
                    
                }
                
            }
            
            return rmdir($dir_path);
        }
        
        return true;
    }
    
    /**
     * Deletes any type of data (files, directories, links...)
     *
     * @param $path string The filesystem path to delete anything
     *
     * @return bool
     */
    public static function remove($path)
    {
        if( ! is_writable($path) ){
            return false;
        }
        
        if( is_file($path) ){
            return unlink($path);
        }
        
        if( is_dir($path) ){
            return self::removeDirectoryRecursively($path);
        }
        
        return true;
    }
    
    /**
     * Extract last part from URI or file path
     *
     * @param $url string
     *
     * @return string
     */
    public static function getFilenameFromUrl($url)
    {
        $url = parse_url($url, PHP_URL_PATH);
        $path_parts = explode('/', $url);
        
        return end($path_parts);
    }

}