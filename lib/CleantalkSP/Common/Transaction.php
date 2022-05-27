<?php


namespace CleantalkSP\Common;


abstract class Transaction
{
    use \CleantalkSP\Templates\Multiton;
    
    abstract protected function setOption($option_name, $value);
    abstract protected function getOption($option_name, $default);
    
    /**
     * Time needed to perform an action
     *
     * @var int
     */
    private $action_time = 5;
    
    /**
     * Transaction ID option name
     *
     * @var string
     */
    private $tid_option_name;
    
    /**
     * @var string Option name with a start time of a transaction
     */
    private $start_time_option_name;
    
    /**
     * Alternative constructor
     *
     * @param int    $action_time Seconds to perform action
     * @param string $name        Transaction name
     */
    protected function init($name, $action_time)
    {
        $this->action_time            = (int) $action_time;
        $this->tid_option_name        = 'spbc_transaction__' . $name . '_id';
        $this->start_time_option_name = 'spbc_transaction__' . $name . '_start_time';
    }
    
    /**
     * Wrapper for self::getInstance()
     *
     * @param string $transaction_name Name of the instance
     * @param int    $action_time_s
     *
     * @return Transaction
     */
    public static function get($transaction_name, $action_time_s = 5 )
    {
        return static::getInstance($transaction_name, array($transaction_name, $action_time_s));
    }
    
    /**
     * Performs transaction. Set transaction timer.
     *
     * @return int|false|null
     *      <p>- Integer transaction ID on success.</p>
     *      <p>- false for duplicated request.</p>
     *      <p>- null on error.</p>
     */
    public function perform()
    {
        if( $this->isTransactionInProcess() === true ){
            return false;
        }
        
        $time_ms = microtime(true);
        if( ! $this->setTransactionTimer() ){
            return null;
        }
        $halt_time = microtime(true) - $time_ms;
        
        $tid = mt_rand(0, mt_getrandmax());
        $this->saveTID($tid);
        usleep( $halt_time + 1000.0 );
        
        return $tid === $this->getTID()
            ? (int) $tid
            : false;
    }
    
    /**
     * Save the transaction ID
     *
     * @param int    $tid
     *
     * @return bool
     */
    private function saveTID($tid)
    {
        return $this->setOption($this->tid_option_name, $tid);
    }
    
    /**
     * Get the transaction ID
     *
     * @return int|false
     */
    public function getTID()
    {
        return $this->getOption($this->tid_option_name, false);
    }
    
    /**
     * Shows if the transaction progress
     *
     * @return bool
     */
    private function isTransactionInProcess()
    {
        return time() - $this->getOption($this->start_time_option_name, 0) < $this->action_time;
    }
    
    /**
     * Set the time when transaction started
     *
     * @return mixed
     */
    private function setTransactionTimer()
    {
        return $this->setOption($this->start_time_option_name, time());
    }
    
    /**
     * Clears the transaction timer
     *
     * @return mixed
     */
    public function clearTransactionTimer()
    {
        return $this->setOption($this->start_time_option_name, 0);
    }
}