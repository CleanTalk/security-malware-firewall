<?php


namespace CleantalkSP\Common;

abstract class Counter {
    
    use \CleantalkSP\Templates\Singleton;
    
    protected static $default_time_interval__insert = 3600;
    protected static $default_time_interval__get    = 86400;
    
    protected $structure = array();
    protected $data      = array();
    protected $current_interval_name__insert;
    protected $current_interval_name__get;
    
    public function init(){
        static::initCounters();
    }
    
    abstract protected function initCounters();
    abstract protected function setCounters();
    
    public static function increment( $name, $increment = 1, $save_flag = true ){
        static::getInstance()->incrementCounter( $name, $increment, $save_flag );
    }
    
    public static function get( $name ){
        return static::getInstance()->getCounter( $name );
    }
    
    protected function getCounter( $name, $out = 0 ){
        foreach( $this->data as $interval_name => $data ){
            if( $this->current_interval_name__get <= $interval_name && isset( $data[ $name ] )){
                $out += $data[ $name ];
            }
        }
        
        return $out;
    }
    
    protected function incrementCounter( $name, $increment, $save_flag ){
        
        // Default structure if interval isn't set
        if( ! isset( $this->data[ $this->current_interval_name__insert ] ) ){
            $this->data[ $this->current_interval_name__insert ] = array();
        }
    
        if( ! isset( $this->data[ $this->current_interval_name__insert ][ $name ] ) ){
            $this->data[ $this->current_interval_name__insert ][ $name ] = 0;
        }
        
        // Increasing counter
        $this->data[ $this->current_interval_name__insert ][ $name ] += $increment;
        
        // Deleting excessive oldest interval. But only one.
        if( count( $this->data ) > self::$default_time_interval__get / self::$default_time_interval__insert ){
            unset( $this->data[ min( array_keys( $this->data ) ) ] );
        }
        
        $save_flag && $this->setCounters();
    }
}