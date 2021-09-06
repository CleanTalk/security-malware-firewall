<?php


namespace CleantalkSP\SpbctWP;


class Queue extends \CleantalkSP\Common\Queue {

	const QUEUE_NAME = 'spbc_fw_update_queue';
    
    /**
     * Clears the queue in the database
     *
     * @return bool
     */
    public static function clearQueue()
    {
        return delete_option( self::QUEUE_NAME );
    }
	
    /**
     * Get the queue from DB
     *
     * @return mixed
     */
	public function getQueue()
	{
		return get_option( self::QUEUE_NAME );
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
		return update_option( self::QUEUE_NAME, $queue ?: $this->queue );
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