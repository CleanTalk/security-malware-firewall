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
    public function process(){

        $action = strtolower( Request::get( 'spbc_remote_call_action' ) );
        $token  = strtolower( Request::get( 'spbc_remote_call_token' ) );
        $method = 'action__' . $action;
        
        if( isset( $this->state->remote_calls[ $action ] ) ){

            $cooldown = isset( $this->state->remote_calls[ $action ]['cooldown'] )
                ? $this->state->remote_calls[ $action ]['cooldown']
                : self::COOLDOWN;

            // Return OK for test remote calls
            if( Request::get( 'test' ) ){
                die( 'OK' );
            }

            if( time() - $this->state->remote_calls[ $action ]['last_call'] >= $cooldown ){

                $this->state->remote_calls[ $action ]['last_call'] = time();
                $this->state->save( 'remote_calls', true, false );

                // Check API key
                if(
                	$token === strtolower( md5( $this->state->api_key ) ) ||
                	$token === strtolower( hash( 'sha256', $this->state->api_key ) )
                ){

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
                        
                    }else{
                        $out = 'FAIL ' . json_encode(array('error' => 'UNKNOWN_ACTION_METHOD'));
                    }
                }else{
                    $out = 'FAIL ' . json_encode(array('error' => 'WRONG_TOKEN'));
                }
            }else{
                $out = 'FAIL ' . json_encode(array('error' => 'TOO_MANY_ATTEMPTS'));
            }
        }else{
            $out = 'FAIL ' . json_encode(array('error' => 'UNKNOWN_ACTION'));
        }
            
        if( $out ){
            die($out);
        }
    }
    
    /**
     * @return false
     */
    protected static function filter_before_action(){
        return false;
    }
    
    public static function buildParameters($rc_action, $plugin_name, $api_key, $additional_params)
    {
        return array_merge(
            array(
                'spbc_remote_call_token'  => md5($api_key),
                'spbc_remote_call_action' => $rc_action,
                'plugin_name'             => $plugin_name,
            ),
            $additional_params
        );
    }
    
    /**
     * Performs remote call to the current website
     *
     * @param string $host
     * @param string $rc_action
     * @param string $plugin_name
     * @param string $api_key
     * @param array  $params
     * @param array  $patterns
     * @param bool   $do_check Perform check before main remote call or not
     *
     * @return bool|string[]
     */
    public static function perform($host, $rc_action, $plugin_name, $api_key, $params, $patterns = array(), $do_check = true)
    {
        $params = static::buildParameters($rc_action, $plugin_name, $api_key, $params);
        
        if( $do_check ){
            $result__rc_check_website = static::performTest($host, $params, $patterns);
            if( ! empty($result__rc_check_website['error']) ){
                return $result__rc_check_website;
            }
        }
        
        $http = new \CleantalkSP\Common\HTTP\Request();
        
        return $http
            ->setUrl($host)
            ->setData($params)
            ->setPresets($patterns)
            ->request();
    }
    
    /**
     * Performs test remote call to the current website
     * Expects 'OK' string as good response
     *
     * @param string $host
     * @param array  $params
     * @param array  $patterns
     *
     * @return array|bool|string
     */
    public static function performTest($host, $params, $patterns = array() )
    {
        // Delete async pattern to get the result in this process
        $key = array_search( 'async', $patterns, true );
        if( $key ){
            unset( $patterns[ $key ] );
        }
        
        // Adding test flag
        $params = array_merge($params, array('test' => 'test' ) );
    
        // Perform test request
        $http   = new \CleantalkSP\Common\HTTP\Request();
        $result = $http
            ->setUrl($host)
            ->setData($params)
            ->setPresets($patterns)
            ->request();
        
        // Considering empty response as error
        if( $result === '' ){
            $result = array( 'error' => 'WRONG_SITE_RESPONSE TEST ACTION : ' . $params['spbc_remote_call_action'] . ' ERROR: EMPTY_RESPONSE' );
            
        // Wrap and pass error
        }elseif( ! empty( $result['error'] ) ){
            $result = array( 'error' => 'WRONG_SITE_RESPONSE TEST ACTION: ' . $params['spbc_remote_call_action'] . ' ERROR: ' . $result['error'] );
            
            // Expects 'OK' string as good response otherwise - error
        }elseif( is_string($result) && ! preg_match( '@^.*?OK$@', $result ) ){
            $result = array(
                'error' => 'WRONG_SITE_RESPONSE ACTION: ' . $params['spbc_remote_call_action'] . ' RESPONSE: ' . '"' . htmlspecialchars(substr(
                        ! is_string( $result )
                            ? print_r( $result, true )
                            : $result,
                        0,
                        400
                    ) )
                           . '"'
            );
        }
        
        return $result;
    }
}
