<?php


namespace CleantalkSP\Common;


abstract class Queue {
    
    /**
     * @var string Holds option prefix for system/DB/Storage
     */
    protected static $option_prefix = '';
    
    /**
     * @var Queue name
     */
    private $name;
    
    /**
     * @var Queue option name
     */
    protected $option_name;
    
    /**
     * @var string Name of remote call
     */
    public $rc_name = '';
    
	public $queue;
	public $unstarted_stage;
    
    /**
     * Process identifier
     *
     * @var int
     */
    private $pid;
    
    public function __construct( $queue_name, $remote_call_action = '' )
	{
        $this->rc_name     = $remote_call_action;
        $this->pid         = mt_rand(0, mt_getrandmax());
        $this->option_name = static::$option_prefix . $queue_name . '_queue';
	    
		$queue = $this->getQueue();
		if( $queue !== false && isset( $queue['stages'] ) ) {
			$this->queue = $queue;
		} else {
			$this->queue = array(
				'started' => time(),
				'finished' => '',
				'stages' => array(),
			);
		}
	}
    
    /**
     * Abstract
     *
     * Get the queue from DB or whatever
     *
     * @return mixed
     */
	abstract public function getQueue();
    
    /**
     * Abstract
     *
     * Refreshes the $this->queue from the DB or whatever
     *
     * @return mixed
     */
    abstract public function refreshQueue();
	
    /**
     * Abstract
     *
     * Save the current state of queue in DB or whatever
     *
     * @param array|null $queue
     *
     * @return mixed
     */
	abstract public function saveQueue( $queue = null );
    
    /**
     * Adding stage to the queue and saving it to DB
     *
     * @param string $stage_name
     * @param array  $args
     * @param int    $accepted_tries
     */
	public function addStage( $stage_name, $args = array(), $accepted_tries = 3 )
	{
        $this->queue['stages'][] = array(
            'name'   => $stage_name,
            'status' => 'NULL',
            'tries'  => '0',
            'accepted_tries'  => $accepted_tries,
            'args'   => $args,
            'pid'    => null,
        );
		$this->saveQueue();
	}
    
    /**
     * Performs current stage of the queue
     * Tries it 3 times for the stage
     * Then calling a remote call for the next stage
     *
     * @return bool|string|string[]
     */
	public function executeStage()
	{
	    global $spbc;
        
        $stage_to_execute = null;
	    
	    if( $this->hasUnstartedStages() ){
	        
            $this->queue['stages'][ $this->unstarted_stage ]['status'] = 'IN_PROGRESS';
            $this->queue['stages'][ $this->unstarted_stage ]['pid']    = $this->pid;
            
            $this->saveQueue();
            
            usleep( 1000 );
            
            $this->refreshQueue();
            
            if( $this->queue['stages'][ $this->unstarted_stage ]['pid'] !== $this->pid ){
                return true;
            }
        
            $stage_to_execute = &$this->queue['stages'][ $this->unstarted_stage ];
        }
	    
	    if( $stage_to_execute ){
	        
            if( is_callable( $stage_to_execute['name'] ) ){
    
                ++ $stage_to_execute['tries'];
    
                if( ! empty( $stage_to_execute['args'] ) ){
                    $result = $stage_to_execute['name']( $stage_to_execute['args'] );
                }else{
                    $result = $stage_to_execute['name']();
                }
    
                if( isset( $result['error'] ) ){
                    $stage_to_execute['status'] = 'NULL';
                    $stage_to_execute['error'][]  = $result['error'];
                    if( isset( $result['update_args']['args'] ) ){
                        $stage_to_execute['args'] = $result['update_args']['args'];
                    }
                    $this->saveQueue();
                    $accepted_tries = isset($stage_to_execute['accepted_tries']) ? $stage_to_execute['accepted_tries'] : 3;
                    if( $stage_to_execute['tries'] >= $accepted_tries ){
                        $stage_to_execute['status'] = 'FINISHED';
                        $this->saveQueue();
            
                        return $result;
                    }
        
                    return \CleantalkSP\SpbctWP\RemoteCalls::performToHost(
                        $this->rc_name,
                        array(
                            'updating_id' => $spbc->fw_stats['updating_id'],
                            'stage'       => 'Repeat ' . $stage_to_execute['name']
                        ),
                        array( 'async' )
                    );
                }
    
                if( isset( $result['next_stage'] ) ){
                    $this->addStage(
                        $result['next_stage']['name'],
                        isset( $result['next_stage']['args'] ) ? $result['next_stage']['args'] : array(),
                        isset($result['next_stage']['accepted_tries']) ? $result['next_stage']['accepted_tries'] : 3
                    );
                }
    
                if( isset( $result['next_stages'] ) && count( $result['next_stages'] ) ){
                    foreach( $result['next_stages'] as $next_stage ){
                        $this->addStage(
                            $next_stage['name'],
                            isset( $next_stage['args'] ) ? $next_stage['args'] : array(),
                            isset($result['next_stage']['accepted_tries']) ? $result['next_stage']['accepted_tries'] : 3
                        );
                    }
                }
    
                $stage_to_execute['status'] = 'FINISHED';
                $this->saveQueue();
    
                return $result;
            }
        
            return array('error' => $stage_to_execute['name'] . ' is not a callable function.');
        }
	    
	    return true;
	}
    
    public function isQueueInProgress()
    {
        return
            count( $this->queue['stages'] ) &&
            (
                in_array( 'NULL', array_column( $this->queue['stages'], 'status' ), true ) ||
                in_array( 'IN_PROGRESS', array_column( $this->queue['stages'], 'status' ), true )
            );
    }
    
    /**
     * Checks if the queue is over
     *
     * @return bool
     */
    public function isQueueFinished()
    {
        return ! $this->isQueueInProgress();
    }
    
    /**
     * Checks if the queue is over
     *
     * @return bool
     */
    public function hasUnstartedStages()
    {
        if( count( $this->queue['stages'] ) > 0 ){
            $this->unstarted_stage = array_search('NULL', array_column( $this->queue['stages'], 'status' ), true );
            return is_int( $this->unstarted_stage );
        }
        
        return false;
    }
    
}