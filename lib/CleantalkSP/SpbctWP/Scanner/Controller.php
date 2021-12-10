<?php


namespace CleantalkSP\SpbctWP\Scanner;

use CleantalkSP\Common;
use CleantalkSP\SpbctWP;

class Controller
{
    /**
     * Scan file thru malware sinatures
     *
     * @param string $root_path Path to CMS's root folder
     * @param array $file_info Array with files data (path, real_full_hash, source_type, source, version), other is optional
     * @param array $signatures Set of signatures
     *
     * @return array|false False or Array of found bad sigantures
     */
    public static function scanFileForSignatures($root_path, $file_info, $signatures)
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
                            $line_number = Helper::file__get_string_number_with_needle( $root_path . $file_info['path'], $signature['body'], $is_regexp );
                            $verdict['SIGNATURES'][ $line_number ][] = $signature['id'];
                        }
                        
                    }
                }
                // Removing signatures from the previous result
                $file_info['weak_spots'] = ! empty( $file_info['weak_spots'] ) ? json_decode( $file_info['weak_spots'], true ) : array();
                if( isset( $file_info['weak_spots']['SIGNATURES'] ) )
                    unset( $file_info['weak_spots']['SIGNATURES'] );
                
                $verdict = Common\Helper::array_merge__save_numeric_keys__recursive($file_info['weak_spots'], $verdict);
                
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
    public static function scanFileForHeuristic($root_path, $file_info)
    {
        $scanner = new Heuristic\Controller(array('path' => $root_path . $file_info['path'] ));
        
        if ( !empty( $scanner -> error ) ){
            return array(
                'weak_spots' => null,
                'severity'   => null,
                'status'     => 'OK',
                'includes' => array(),
            );
            return $scanner -> error;
        }
        $scanner->processContent();
        
        // Saving only signatures from the previous result
        $file_info['weak_spots'] = !empty($file_info['weak_spots']) ? json_decode($file_info['weak_spots'], true) : array();
        $file_info['weak_spots'] = isset( $file_info['weak_spots']['SIGNATURES'] )
            ? array( 'SIGNATURES' => $file_info['weak_spots']['SIGNATURES'] )
            : array();
        
        $verdict = Common\Helper::array_merge__save_numeric_keys__recursive($file_info['weak_spots'], $scanner->verdict);
        
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
    
}