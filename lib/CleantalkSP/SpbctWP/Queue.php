<?php


namespace CleantalkSP\SpbctWP;


class Queue extends \CleantalkSP\Common\Queue {
 
    protected static $option_prefix = 'spbc_';
    
    /**
     * Clears the queue in the database
     *
     * @return bool
     */
    public function clearQueue()
    {
        $this->queue = array(
            'started' => time(),
            'finished' => '',
            'stages' => array(),
        );
        
        return delete_option( $this->option_name );
    }
	
    /**
     * Get the queue from DB
     *
     * @return mixed
     */
	public function getQueue()
	{
		return get_option( $this->option_name );
	}
    
    /**
     * Save the current state of queue in DB or whatever
     *
     * @param array|null $queue
     *
     * @return mixed
     */
	public function saveQueue( $queue = null )
	{
		return update_option( $this->option_name, $queue ?: $this->queue, false );
	}
    
    /**
     * Refreshes the $this->queue from the DB
     *
     * @param array|null $queue
     *
     * @return mixed
     */
    public function refreshQueue( $queue = null )
    {
        $this->queue = $this->getQueue();
    }
}