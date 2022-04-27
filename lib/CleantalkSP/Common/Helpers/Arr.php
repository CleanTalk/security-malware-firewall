<?php

namespace CleantalkSP\Common\Helpers;

/**
 * Class Arr
 * Gather static functions designed to ease work with arrays
 *
 * @version       1.0.0
 * @package       CleantalkSP\Common\Helpers
 * @author        Cleantalk team (welcome@cleantalk.org)
 * @copyright (C) 2014 CleanTalk team (http://cleantalk.org)
 * @license       GNU/GPL: http://www.gnu.org/copyleft/gpl.html
 * @see           https://github.com/CleanTalk/security-malware-firewall
 */
class Arr {
    /**
     * @param array $arr
     *
     * @return bool
     */
    public static function reindex( &$arr )
    {
        if( ! count( $arr ) ){
            return false;
        }
        
        for( $reindex_key = 0, $key = 0, $max_key = max( array_keys( $arr ) ); $key <= $max_key; $key++ ){
            
            if( isset( $arr[ $key ] ) ){
                
                if( $reindex_key === $key ){
                    $reindex_key++;
                    continue;
                }
                
                $arr[ $reindex_key++ ] = $arr[ $key ];
                unset( $arr[ $key ] );
            }
        }
        
        return true;
    }
    
    /**
     * Merging arrays without reseting numeric keys
     *
     * @param array $arr1 One-dimentional array
     * @param array $arr2 One-dimentional array
     *
     * @return array Merged array
     */
    public static function mergeWithSavingNumericKeys($arr1, $arr2)
    {
        foreach($arr2 as $key => $val){
            $arr1[$key] = $val;
        }
        return $arr1;
    }
    
    /**
     * Merging arrays without reseting numeric keys recursive
     *
     * @param array $arr1 One-dimentional array
     * @param array $arr2 One-dimentional array
     *
     * @return array Merged array
     */
    public static function mergeWithSavingNumericKeysRecursive($arr1, $arr2)
    {
        foreach($arr2 as $key => $val){
            // Array | array => array
            if(isset($arr1[$key]) && is_array($arr1[$key]) && is_array($val)){
                $arr1[$key] = self::mergeWithSavingNumericKeysRecursive($arr1[$key], $val);
                // Scalar | array => array
            }elseif(isset($arr1[$key]) && !is_array($arr1[$key]) && is_array($val)){
                $tmp = $arr1[$key] =
                $arr1[$key] = $val;
                $arr1[$key][] = $tmp;
                // array  | scalar => array
            }elseif(isset($arr1[$key]) && is_array($arr1[$key]) && !is_array($val)){
                $arr1[$key][] = $val;
                // scalar | scalar => scalar
            }else{
                $arr1[$key] = $val;
            }
        }
        return $arr1;
    }
    
    /**
     * Modifies the array $array. Paste $insert on $position
     *
     * @param array      $array
     * @param int|string $position
     * @param mixed      $insert
     */
    public static function insert( &$array, $position, $insert ){
        if( is_int( $position ) ){
            array_splice( $array, $position, 0, $insert );
        }else{
            $pos   = array_search( $position, array_keys( $array ) );
            $array = array_merge(
                array_slice( $array, 0, $pos ),
                $insert,
                array_slice( $array, $pos )
            );
        }
    }
}