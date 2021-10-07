<?php

namespace CleantalkSP\SpbctWP;

/**
 * CleanTalk Security Cron class
 *
 * @package       Security Plugin by CleanTalk
 * @subpackage    Cron
 * @Version       2.0.1
 * @author        Cleantalk team (welcome@cleantalk.org)
 * @copyright (C) 2014 CleanTalk team (http://cleantalk.org)
 * @license       GNU/GPL: http://www.gnu.org/copyleft/gpl.html
 *
 */
class Cron extends \CleantalkSP\Common\Cron
{
    const CRON_OPTION_NAME  = 'spbc_cron';
    const ID_OPTION         = 'spbc_cron_id';
    const LAST_START_OPTION = 'spbc_cron_last_start';
    
    // Interval in seconds for restarting the task
    const TASK_EXECUTION_MIN_INTERVAL = 120;
    const CRON_EXECUTION_MIN_INTERVAL = 120;
    
    public $tasks; // Array with tasks
    public $tasks_to_run; // Array with tasks which should be run now
    public $tasks_completed; // Result of executed tasks
    
    
    /**
     * Cron constructor.
     * Getting tasks option.
     */
    public function __construct()
    {
        $this->tasks = self::getTasks();
        
        parent::__construct( self::TASK_EXECUTION_MIN_INTERVAL, self::CRON_EXECUTION_MIN_INTERVAL );
    }
    
    /**
     * Getting all tasks
     *
     * @return array
     */
    public static function getTasks()
    {
        $tasks = get_option( self::CRON_OPTION_NAME );
        
        return is_array( $tasks ) ? $tasks : array();
    }
    
    protected function getCronLastStart()
    {
        return get_option( self::LAST_START_OPTION, 0 );
    }
    
    protected function setCronLastStart()
    {
        return update_option( self::LAST_START_OPTION, time() );
    }
    
    /**
     * Saves Cron ID
     */
    protected function saveID()
    {
        update_option( self::ID_OPTION, $this->id );
    }
    
    /**
     * Saves Cron ID
     */
    protected function isIDmMatch()
    {
        return get_option( self::ID_OPTION ) === $this->id;
    }
    
    /**
     * Getting single task
     *
     * @param string $task
     *
     * @return array|false
     */
    public static function getTask( $task )
    {
        $tasks = self::getTasks();
        
        return isset( $tasks[ $task ] ) ? $tasks[ $task ] : false;
    }
    
    /**
     * Save option with tasks
     *
     * @param array $tasks
     *
     * @return bool
     */
    public function saveTasks( $tasks = array() )
    {
        return update_option( self::CRON_OPTION_NAME, $tasks );
    }
    
    /**
     * Adding new cron task
     *
     * @param string $task
     * @param string $handler
     * @param int    $period
     * @param null   $first_call
     * @param array  $params
     *
     * @return bool
     */
    public static function addTask( $task, $handler, $period, $first_call = null, $params = array() )
    {
        $first_call = $first_call ?: time() + $period;
        
        $tasks = self::getTasks();
        
        if( isset( $tasks[ $task ] ) ){
            return false;
        }
        
        // Task entry
        $tasks[ $task ] = array(
            'handler'    => $handler,
            'next_call'  => $first_call,
            'period'     => $period,
            'params'     => $params,
            'processing' => false,
            'last_call'  => 0,
        );
        
        return update_option( self::CRON_OPTION_NAME, $tasks );
    }
    
    /**
     * Removing cron task
     *
     * @param $task
     *
     * @return bool
     */
    public static function removeTask( $task )
    {
        $tasks = self::getTasks();
        
        if( ! isset( $tasks[ $task ] ) ){
            return false;
        }
        
        unset( $tasks[ $task ] );
        
        return update_option( self::CRON_OPTION_NAME, $tasks );
    }
    
    /**
     * @param string $task
     * @param string $handler
     * @param int    $period
     * @param null   $first_call
     * @param array  $params
     *
     * @return bool
     */
    public static function updateTask( $task, $handler, $period, $first_call = null, $params = array() )
    {
        self::removeTask( $task );
        
        return self::addTask( $task, $handler, $period, $first_call, $params );
    }
}
