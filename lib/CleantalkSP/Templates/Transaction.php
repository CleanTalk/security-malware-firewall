<?php


namespace CleantalkSP\Templates;


trait Transaction
{
    /**
     * Performs transaction
     *
     * @param string $option_name
     * @param int    $halt_time in microseconds. Default is 100000 === 100ms.
     *
     * @return bool
     */
    public static function performTransaction($option_name, $halt_time = 100000)
    {
        $tid = mt_rand(0, mt_getrandmax());
        
        self::saveTID($option_name, $tid);
        
        usleep($halt_time);
        
        return $tid === self::getTID($option_name);
    }
    
    /**
     * Save the transaction ID
     *
     * @param string $option_name
     * @param int    $tid
     *
     * @return bool
     */
    public static function saveTID($option_name, $tid)
    {
        return update_option($option_name, $tid);
    }
    
    /**
     * Get the transaction ID
     *
     * @param string $option_name
     *
     * @return bool|mixed|void
     */
    public static function getTID($option_name)
    {
        return get_option($option_name, false);
    }
}