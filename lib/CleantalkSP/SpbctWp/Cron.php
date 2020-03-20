<?php

namespace CleantalkSP\SpbctWp;

/*
 * 
 * CleanTalk Security Cron class
 * 
 * @package Security Plugin by CleanTalk
 * @subpackage Cron
 * @Version 2.0
 * @author Cleantalk team (welcome@cleantalk.org)
 * @copyright (C) 2014 CleanTalk team (http://cleantalk.org)
 * @license GNU/GPL: http://www.gnu.org/copyleft/gpl.html
 *
 */

class Cron
{
	public $tasks = array(); // Array with tasks
	public $tasks_to_run = array(); // Array with tasks which should be run now
	public $tasks_completed = array(); // Result of executed tasks
	
	// Currently selected task
	public  $task;
	private $handler;
	private $period;
	private $next_call;
	private $params;
	
	// Option name with cron data
	const CRON_OPTION_NAME = 'spbc_cron';	
	
	// Getting tasks option
	public function __construct()
	{
		$this->tasks = self::getTasks();
	}
	
	static public function getTasks(){
		$tasks = get_option(self::CRON_OPTION_NAME);
		return empty($tasks) ? array() : $tasks;
	}
	
	// Adding new cron task
	static public function addTask($task, $handler, $period, $first_call = null, $params = array())
	{
		// First call time() + preiod
		$first_call = !$first_call ? time() + $period : $first_call;
		
		$tasks = self::getTasks();
		
		if(isset($tasks[$task])) return false;
		
		// Task entry
		$tasks[$task] = array(
			'handler' => $handler,
			'next_call' => $first_call,
			'period' => $period,
			'params' => $params,
		);
		
		return update_option(self::CRON_OPTION_NAME, $tasks);
	}
	
	// Removing cron task
	static public function removeTask($task)
	{		
		$tasks = self::getTasks();
		
		if(!isset($tasks[$task])) return false;
		
		unset($tasks[$task]);
		
		return update_option(self::CRON_OPTION_NAME, $tasks);
	}
	
	// Updates cron task, create task if not exists
	static public function updateTask($task, $handler, $period, $first_call = null, $params = array()){
		self::removeTask($task);
		self::addTask($task, $handler, $period, $first_call, $params);
	}
	
	// Getting tasks which should be run. Putting tasks that should be run to $this->tasks_to_run
	public function checkTasks()
	{
		if(empty($this->tasks))
			return true;
		
		foreach($this->tasks as $task => $task_data){
			
			if($task_data['next_call'] <= time())
				$this->tasks_to_run[] = $task;
			
		}unset($task, $task_data);
		
		return $this->tasks_to_run;
	}
	
	// Run all tasks from $this->tasks_to_run. Saving all results to (array) $this->tasks_completed
	public function runTasks()
	{
		global $spbc;
		
		if(empty($this->tasks_to_run))
			return true;
		
		foreach($this->tasks_to_run as $task){
			
			$this->selectTask($task);
			
			if(function_exists($this->handler)){
				
				$result = call_user_func_array($this->handler, isset($this->params) ? $this->params : array());
				
				if(empty($result['error'])){
					$this->tasks_completed[$task] = true;
					$spbc->error_delete($task, 'save_data', 'cron');
				}else{
					$this->tasks_completed[$task] = false;
					$spbc->error_add($task, $result, 'cron');
				}
				
			}else{
				$this->tasks_completed[$task] = false;
				$spbc->error_add($task, $this->handler.'_IS_NOT_EXISTS', 'cron');
			}
			
			$this->saveTask($task);
			
		}unset($task);
		
		//* Merging executed tasks with updated during execution
			$tasks = $this->getTasks();
			
			foreach($tasks as $task => $task_data){
			
				// Task where added during execution
				if(!isset($this->tasks[$task])){
					$this->tasks[$task] = $task_data;
					continue;
				}
				
				// Task where updated during execution
				if($task_data !== $this->tasks[$task]){
					$this->tasks[$task] = $task_data;
					continue;
				}
				
				// Setting next call depending on results
				if(isset($this->tasks[$task], $this->tasks_completed[$task])){
					$this->tasks[$task]['next_call'] = $this->tasks_completed[$task]
						? time() + $this->tasks[$task]['period']
						: time() + round($this->tasks[$task]['period']/4);
				}

				if(empty($this->tasks[$task]['next_call']) || $this->tasks[$task]['next_call'] < time()){
					$this->tasks[$task]['next_call'] = time() + $this->tasks[$task]['period'];
				}
				
			} unset($task, $task_data);
			
			// Task where deleted during execution
			$tmp = $this->tasks;
			foreach($tmp as $task => $task_data){
				if(!isset($tasks[$task]))
					unset($this->tasks[$task]);
			} unset($task, $task_data);
		
		//*/ End of merging
		
		$this->saveTasks();
	}
	
	// Select task in private properties for comfortable use.
	private function selectTask($task)
	{
		$this->task      = $task;
		$this->handler   = $this->tasks[$task]['handler'];
		$this->period    = $this->tasks[$task]['period'];
		$this->next_call = $this->tasks[$task]['next_call'];
		$this->params    = isset($this->tasks[$task]['params']) ? $this->tasks[$task]['params'] : array();
	}
	
	// Save task in private properties for comfortable use
	private function saveTask($task)
	{
		$task = $this->task;
		
		$this->tasks[$task]['handler']   = $this->handler;
		$this->tasks[$task]['period']    = $this->period;
		$this->tasks[$task]['next_call'] = $this->next_call;
		$this->tasks[$task]['params']    = $this->params;
	}
	
	// Save option with tasks
	private function saveTasks()
	{
		update_option(self::CRON_OPTION_NAME, $this->tasks);
	}
}
