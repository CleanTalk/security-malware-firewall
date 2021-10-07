<?php

namespace CleantalkSP\Common;

use CleantalkSP\Variables\Request;

class RemoteCalls
{
    
    /**
     * State object
     *
     * @var \CleantalkSP\SpbctWP\State
     */
    protected $state;
    
    /**
     * Daughter class name
     *
     * @var string
     */
    protected $class_name;
    
    const COOLDOWN = 10;

    /**
     * Checking if the current request is the Remote Call
     *
     * @return bool
     */
    public static function check(){

        return
            Request::get( 'spbc_remote_call_token' ) &&
            Request::get( 'spbc_remote_call_action' ) &&
            in_array( Request::get( 'plugin_name' ), array( 'security', 'spbc' ) );
    }

    /**
     * Execute corresponding method of RemoteCalls if exists
     *
     * @return void|string
     */
    public function perform(){

        $action = strtolower( Request::get( 'spbc_remote_call_action' ) );
        $token  = strtolower( Request::get( 'spbc_remote_call_token' ) );
        $method = 'action__' . $action;
        
        if( isset( $this->state->remote_calls[ $action ] ) ){

            $cooldown = isset( $this->state->remote_calls[ $action ]['cooldown'] ) ? $this->state->remote_calls[ $action ]['cooldown'] : self::COOLDOWN;

            // Return OK for test remote calls
            if( Request::get( 'test' ) ){
                die( 'OK' );
            }

            if( time() - $this->state->remote_calls[ $action ]['last_call'] >= $cooldown ){

                $this->state->remote_calls[ $action ]['last_call'] = time();
                $this->state->save( 'remote_calls' );

                // Check API key
                if( $token == strtolower( md5( $this->state->api_key ) ) ){

                    // Flag to let plugin know that Remote Call is running.
                    $this->state->rc_running = true;

                    if( method_exists( $this->class_name, $method ) ){

                        // Perform action from a daughter class
                        $out = static::filter_before_action();
                        if( ! $out ){
                            
                            // Every remote call action handler should implement output or
                            // If out is empty(), the execution will continue
                            $out = static::$method();
                            
                        }
                        
                    }else
                        $out = 'FAIL '.json_encode(array('error' => 'UNKNOWN_ACTION_METHOD'));
                }else
                    $out = 'FAIL '.json_encode(array('error' => 'WRONG_TOKEN'));
            }else
                $out = 'FAIL '.json_encode(array('error' => 'TOO_MANY_ATTEMPTS'));
        }else
            $out = 'FAIL '.json_encode(array('error' => 'UNKNOWN_ACTION'));
            
        if( $out )
            die( $out );
    }
    
    /**
     * @return null
     */
    protected static function filter_before_action(){
        return null;
    }
}
