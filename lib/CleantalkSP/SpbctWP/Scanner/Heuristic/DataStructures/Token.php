<?php

namespace CleantalkSP\SpbctWP\Scanner\Heuristic\DataStructures;

use CleantalkSP\SpbctWP\Scanner\Heuristic\TokenGroups;

/**
 * @property string     $type
 * @property string|int $value
 * @property int        $line
 * @property int        $key
 * @property int        $length
 */

class Token extends \SplFixedArray
{
    public function __construct( $type, $value, $line, $key = null, $size = 4 )
    {
        parent::__construct( $size );
        
        $this[0] = $type;
        $this[1] = $value;
        $this[2] = $line;
        $this[3] = $key;
    }
    
    public function isTypeOf( $group )
    {
        return in_array( $this->type, TokenGroups::$$group, true ) &&
               ! $this->isEmpty();
               
    }

    public function isValueIn($values_to_compare){
        return in_array($this->value, $values_to_compare, true);
    }
    
    public function isEmpty()
    {
        return ! $this->type && ! $this->value && ! $this->line;
    }
    
    public function __isset( $name )
    {
         switch( $name ){
            case 'type':
                return isset($this[0]);
            case 'value':
                return isset($this[1]);
            case 'line':
                return isset($this[2]);
            case 'key':
                return isset($this[3]);
        }
        
        return false;
    }
    
    public function __set( $name, $value )
    {
         switch( $name ){
            case 'type':
                $this[0] = $value;
            break;
            case 'value':
                $this[1] = $value;
            break;
            case 'line':
                $this[2] = $value;
            case 'key':
                $this[3] = $value;
            break;
        }
    }
    
    public function __get( $name )
    {
        switch( $name ){
            case 'type':
                return $this[0];
            case 'value':
                return $this[1];
            case 'line':
                return $this[2];
            case 'key':
                return isset($this[3]) ? $this[3] : null;
            case 'value_length':
                return strlen($this[1]);
        }
    }
}