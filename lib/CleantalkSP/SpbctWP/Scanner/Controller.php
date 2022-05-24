<?php


namespace CleantalkSP\SpbctWP\Scanner;

use CleantalkSP\Common;
use CleantalkSP\SpbctWP;
use CleantalkSP\Common\Helpers\Arr;

class Controller
{
    
    const FILE_MAX_SIZE = 524288; // 512 KB
    
    private static $statuses = array(
        'OK',
        'UNKNOWN',
        'MODIFIED',
        'INFECTED',
        'QUARANTINED',
        'APROVED',
    );
    
    private static $severities = array(
        'NONE',
        'SUSPICIOUS',
        'DANGER',
        'CRITICAL',
    );
    
    /**
     * Merges the scan results
     *
     * @param mixed ...$results
     *
     * @return array Merged results
     */
    public static function mergeResults( ...$results )
    {
        $out = array(
            'weak_spots' => null,
            'severity'   => null,
            'status'     => 'OK',
        );
        
        foreach( $results as $result ){
            
            foreach( $result as $key => $item ){
                
                if( empty( $item ) ){
                    continue;
                }
                
                switch( $key ){
                    
                    case 'weak_spots':
                        
                        foreach( $item as $severity => $line_nums ){
                            foreach( $line_nums as $line_num => $codes ){
                                foreach( $codes as $code ){
                                    $out['weak_spots'][ $severity ][ $line_num ][] = $code;
                                }
                            }
                        }
                        break;
                    
                    case 'severity':
                        $out['severity'] = array_search($item, self::$severities, true) > array_search($out['severity'], self::$severities, true)
                            ? $item
                            : $out['severity'];
                        break;
                    
                    case 'status':
                        $out['status'] = array_search($item, self::$statuses, true) > array_search($out['status'], self::$statuses, true)
                            ? $item
                            : $out['status'];
                        break;
                }
            }
        }
        
        return $out;
    }
    
    /**
     * @param int|string $file_size_or_path
     *
     * @return array|bool
     */
    public static function checkFileSize( $file_size_or_path ){
        
        $file_size = ! is_int( $file_size_or_path ) ? filesize($file_size_or_path) : $file_size_or_path;
        
        if( ! (int) $file_size ){
            return array( 'error' => 'FILE_SIZE_ZERO' );
        }
        
        if( (int) $file_size > self::FILE_MAX_SIZE ){
            return array( 'error' => 'FILE_SIZE_TO_LARGE' );
        }
        
        return true;
    }
    
    public static function scanFile($file_info, $root_path = null, &$signatures = null)
    {
        $signatures = $signatures ?: self::getSignatures();
        $root_path  = $root_path  ?: self::getRootPath();
        
        if(file_exists($root_path.$file_info['path'])){
            
            if(is_readable($root_path.$file_info['path'])){
                
                $heuristic_result = self::scanFileForHeuristic($file_info, $root_path);
                if( ! empty( $heuristic_result['error'] ) ){
                    return $heuristic_result;
                }
                
                $signature_result = self::scanFileForSignatures($file_info, $root_path,$signatures);
                if( ! empty( $signature_result['error'] ) ){
                    return $signature_result;
                }
                
                return self::mergeResults( $signature_result, $heuristic_result );
                
            }
    
            $output = array('error' => 'NOT_READABLE');
            
        }else{
            $output = array('error' => 'NOT_EXISTS');
        }
        
        return $output;
    }
    
    
    /**
     * Scan file against malware signatures
     *
     * @param array  $file_info  Array with files data (path, real_full_hash, source_type, source, version), other is optional
     * @param string $root_path  Path to CMS's root folder
     * @param array  $signatures Set of signatures
     *
     * @return array|false False or Array of found bad sigantures
     */
    public static function scanFileForSignatures($file_info, $root_path = null, &$signatures = null)
    {
        $signatures = $signatures ?: self::getSignatures();
        $root_path  = $root_path  ?: self::getRootPath();
        
        $output = array(
            'weak_spots' => null,
            'severity'   => null,
            'status'     => 'UNKNOWN',
        );
        
        if(file_exists($root_path.$file_info['path'])){
            
            if(is_readable($root_path.$file_info['path'])){
                
                $file_size_check = self::checkFileSize( $root_path.$file_info['path']);
                if( $file_size_check !== true ){
                    return $file_size_check;
                }
                
                $verdict = array();
                $file_content = file_get_contents( $root_path . $file_info['path'] );
                
                foreach ((array)$signatures as $signature){
                    
                    if( $signature['type'] === 'FILE' ) {
                        if( $file_info['full_hash'] === $signature['body'] ){
                            $verdict['SIGNATURES'][1][] = $signature['id'];
                        }
                    }
                    
                    if( in_array( $signature['type'], array('CODE_PHP', 'CODE_JS', 'CODE_HTML' ) ) ) {
                        
                        $is_regexp = SpbctWP\Helpers\Helper::isRegexp($signature['body']);
                        
                        if(
                            ( $is_regexp   && preg_match( $signature['body'], $file_content ) ) ||
                            ( ! $is_regexp && ( strripos( $file_content, stripslashes( $signature['body'] ) ) !== false || strripos( $file_content, $signature['body'] ) !== false) )
                        ){
                            $line_number = Helper::getNeedleStringNumberFromFile($root_path . $file_info['path'], $signature['body'], $is_regexp );
                            $verdict['SIGNATURES'][ $line_number ][] = $signature['id'];
                        }
                        
                    }
                }
                // Removing signatures from the previous result
                $file_info['weak_spots'] = ! empty( $file_info['weak_spots'] ) ? json_decode( $file_info['weak_spots'], true ) : array();
                if( isset( $file_info['weak_spots']['SIGNATURES'] ) ){
                    unset($file_info['weak_spots']['SIGNATURES']);
                }
                
                $verdict = Arr::mergeWithSavingNumericKeysRecursive($file_info['weak_spots'], $verdict);
                
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
                
            }else{
                $output['error'] = 'NOT_READABLE';
            }
        }else{
            $output['error'] = 'NOT_EXISTS';
        }
        
        return $output;
    }
    
    /**
     * Scan file against the heuristic
     *
     * @param array  $file_info Array with files data (path, real_full_hash, source_type, source, version), other is optional
     * @param string $root_path Path to CMS's root folder
     *
     * @return array|false False or Array of found bad constructs sorted by severity
     */
    public static function scanFileForHeuristic($file_info, $root_path = null)
    {
        $root_path = $root_path ?: self::getRootPath();
        
        $scanner = new Heuristic\Controller(array('path' => $root_path . $file_info['path'] ));
        
        if ( !empty( $scanner -> error ) ){
            return array(
                'weak_spots' => null,
                'severity'   => null,
                'status'     => 'OK',
                'includes' => array(),
            );
        }
        $scanner->processContent();
        
        // Saving only signatures from the previous result
        $file_info['weak_spots'] = !empty($file_info['weak_spots']) ? json_decode($file_info['weak_spots'], true) : array();
        $file_info['weak_spots'] = isset( $file_info['weak_spots']['SIGNATURES'] )
            ? array( 'SIGNATURES' => $file_info['weak_spots']['SIGNATURES'] )
            : array();
        
        $verdict = Arr::mergeWithSavingNumericKeysRecursive($file_info['weak_spots'], $scanner->verdict);
        
        $output['includes'] = $scanner->getIncludes();
        
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
     * Get signatures uploaded
     *
     * @return mixed
     */
    public static function getSignatures(){
        return SpbctWP\DB::getInstance()->fetch_all('SELECT * FROM '. SPBC_TBL_SCAN_SIGNATURES, ARRAY_A);
    }
    
    /**
     * Get root path of the CMS
     *
     * @param bool $end_slash
     *
     * @return string
     */
    public static function getRootPath($end_slash = false){
        return $end_slash ? ABSPATH : substr(ABSPATH, 0, -1);
    }
    
    public static function resetCheckResult()
    {
        return SpbctWP\DB::getInstance()->execute('DELETE FROM ' . SPBC_TBL_SCAN_FILES);
    }

}