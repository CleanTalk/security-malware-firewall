<?php


namespace CleantalkSP\SpbctWP\Counters;

use CleantalkSP\SpbctWP\Helpers\Helper;

class FirewallCounter extends \CleantalkSP\Common\Counter {
    
    static $instance;
    
    protected static $default_time_interval__insert = 3600;
    protected static $default_time_interval__get    = 86400;
    
    protected $option_name = 'spbc_counter__firewall';
    
    protected $structure = array(
        'pass' => 0,
        'deny' => 0,
    );
    
    protected function initCounters(){
        $this->current_interval_name__insert = Helper::getTimeIntervalStart(static::$default_time_interval__insert );
        $this->current_interval_name__get    = Helper::getTimeIntervalStart(static::$default_time_interval__get );
        $this->data                          = get_option( $this->option_name, array() );
    }
    
    protected function setCounters(){
        update_option( $this->option_name, $this->data );
    }
}