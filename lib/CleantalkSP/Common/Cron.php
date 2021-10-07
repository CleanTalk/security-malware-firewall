<?php


namespace CleantalkSP\Common;


abstract class Cron
{
    public $id;
    
    public $tasks = array(); // Array with tasks
    public $tasks_to_run = array(); // Array with tasks which should be run now
    public $tasks_completed = array(); // Result of executed tasks
    
    // Currently selected task
    public $task;
    private $handler;
    private $period;
    private $next_call;
    private $processing;
    private $last_call;
    private $params;
    
    private $task_execution_min_interval;
    private $cron_execution_min_interval;
    
    abstract protected function getCronLastStart();
    abstract protected function setCronLastStart();
    abstract protected function saveID();
    abstract protected function isIDmMatch();
    
    /**
     * Cron constructor.
     * Getting tasks option.
     *
     * @param int $task_execution_min_interval Seconds
     * @param int $cron_execution_min_interval Seconds
     */
    public function __construct( $task_execution_min_interval, $cron_execution_min_interval )
    {
        $this->task_execution_min_interval = $task_execution_min_interval;
        $this->cron_execution_min_interval = $cron_execution_min_interval;
        
        $this->tasks = static::getTasks();
        $this->id    = mt_rand( 0, mt_getrandmax() );
    }
    
    public function execute()
    {
        $this->isItTimeToRun() &&
        $this->areThereTasksToRun() &&
        $this->commitTransaction() &&
        $this->runTasks();
    }
    
    public function isItTimeToRun()
    {
        return
            self::isBlockingTimeEnd( $this->getCronLastStart(), $this->cron_execution_min_interval ) &&
            $this->setCronLastStart();
    }
    
    /**
     * Getting tasks which should be run
     *
     * @return bool|array
     */
    public function areThereTasksToRun()
    {
        // No tasks to run
        if( empty( $this->tasks ) ){
            return false;
        }
        
        $original_tasks = $this->tasks;
        foreach( $this->tasks as $task => &$task_data ){
            
            // Update glitched tasks
            if( $task_data['processing'] === true && self::isBlockingTimeEnd( $task_data['last_call'], $this->task_execution_min_interval ) ){
                $task_data['processing'] = false;
                $task_data['last_call']  = 0;
            }
            
            if( $task_data['processing'] === false && $task_data['next_call'] <= time() ){
                
                $task_data['processing'] = true;
                $task_data['last_call']  = time();
                
                $this->tasks_to_run[] = $task;
            }
        }
        unset( $task_data );
        
        // Save tasks only if they were changed
        ! $this->compareSetOfTasks( $original_tasks, $this->tasks ) && static::saveTasks( $this->tasks );
        
        return (bool) $this->tasks_to_run;
    }
    
    public function commitTransaction()
    {
        $this->saveID();
        usleep(10000); // 10 ms
        
        return $this->isIDmMatch();
    }
    
    /**
     * Run all tasks from $this->tasks_to_run.
     * Saving all results to (array) $this->tasks_completed
     *
     * @return void
     */
    public function runTasks()
    {
        global $spbc;
        
        foreach( $this->tasks_to_run as $task ){
            $this->selectTask( $task );
            
            if( function_exists( $this->handler ) ){
                $result = call_user_func_array( $this->handler, isset( $this->params ) ? $this->params : array() );
                
                if( empty( $result['error'] ) ){
                    $this->tasks_completed[ $task ] = true;
                    $spbc->error_delete( $task, 'save_data', 'cron' );
                }else{
                    $this->tasks_completed[ $task ] = false;
                    $spbc->error_add( $task, $result, 'cron' );
                }
            }else{
                $this->tasks_completed[ $task ] = false;
                $spbc->error_add( $task, $this->handler . '_IS_NOT_EXISTS', 'cron' );
            }
            
            $this->saveTask( $task );
        }
        
        //* Merging executed tasks with updated during execution
        $tasks = static::getTasks();
        
        foreach( $tasks as $task => $task_data ){
            // Task where added during execution
            if( ! isset( $this->tasks[ $task ] ) ){
                $this->tasks[ $task ] = $task_data;
                continue;
            }
            
            // Task where updated during execution
            if( $task_data !== $this->tasks[ $task ] ){
                $this->tasks[ $task ] = $task_data;
                continue;
            }
            
            // Setting next call depending on results
            if( isset( $this->tasks[ $task ], $this->tasks_completed[ $task ] ) ){
                $this->tasks[ $task ]['next_call'] = $this->tasks_completed[ $task ]
                    ? time() + $this->tasks[ $task ]['period']
                    : time() + round( $this->tasks[ $task ]['period'] / 4 );
            }
            
            if( empty( $this->tasks[ $task ]['next_call'] ) || $this->tasks[ $task ]['next_call'] < time() ){
                $this->tasks[ $task ]['next_call'] = time() + $this->tasks[ $task ]['period'];
            }
        }
        
        // Task where deleted during execution
        $tmp = $this->tasks;
        foreach( $tmp as $task => $task_data ){
            if( ! isset( $tasks[ $task ] ) ){
                unset( $this->tasks[ $task ] );
            }
        }
        
        //*/ End of merging
        
        static::saveTasks( $this->tasks );
    }
    
    /**
     * Select task in private properties for comfortable use
     *
     * @param $task
     */
    private function selectTask( $task )
    {
        $this->task       = $task;
        $this->handler    = $this->tasks[ $task ]['handler'];
        $this->period     = $this->tasks[ $task ]['period'];
        $this->next_call  = $this->tasks[ $task ]['next_call'];
        $this->processing = $this->tasks[ $task ]['processing'];
        $this->last_call  = $this->tasks[ $task ]['last_call'];
        $this->params     = isset( $this->tasks[ $task ]['params'] ) ? $this->tasks[ $task ]['params'] : array();
    }
    
    /**
     * Save task in private properties for comfortable use
     *
     * @param null $task
     */
    private function saveTask( $task = null )
    {
        $task = $task ?: $this->task;
    
        $this->tasks[ $task ]['handler']    = $this->handler;
        $this->tasks[ $task ]['period']     = $this->period;
        $this->tasks[ $task ]['next_call']  = $this->next_call;
        $this->tasks[ $task ]['params']     = $this->params;
        $this->tasks[ $task ]['processing'] = $this->processing;
        $this->tasks[ $task ]['last_call']  = $this->last_call;
    }
    
    /**
     * Checks if the blocking time is end
     *
     * @param int $last_execution_time
     * @param int $blocking_period
     *
     * @return bool
     */
    public static function isBlockingTimeEnd( $last_execution_time, $blocking_period )
    {
        return time() - $last_execution_time > $blocking_period;
    }
    
    /**
     * Compare sets of tasks
     *
     * @param array $set1 Array with N tasks inside
     * @param array $set2 Array with N tasks inside
     *
     * @return bool
     */
    private function compareSetOfTasks( $set1, $set2 )
    {
        foreach( $set1 as $name => $details ){
            if( $set1[ $name ] !== $set2[ $name ] ){
                return false;
            }
        }
        
        return true;
    }
}