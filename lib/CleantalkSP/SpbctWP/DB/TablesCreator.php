<?php

namespace CleantalkSP\SpbctWP\DB;

use CleantalkSP\SpbctWP\DB;

class TablesCreator
{
    /**
     * @var DB
     */
    private $db;
    
    public function __construct()
    {
        $this->db = DB::getInstance();
    }
    
    /**
     * Create all plugin tables from Schema
     *
     * @throws \Exception
     */
    public function createAllTables()
    {
        $tables_names = SQLSchema::getAllTableNames();
        foreach($tables_names as $tables_name){
            $this->createTable( $tables_name );
        }
    }
    
    /**
     * Create Table by table name
     *
     * @param string $table_name
     *
     * @throws \Exception
     */
    public function createTable( $table_name )
    {
        $schema = SQLSchema::getByName( $table_name );
        
        $sql = 'CREATE TABLE IF NOT EXISTS `' . $table_name . '` (';
    
        // Add columns to request
        foreach( $schema['columns'] as $column ){
            
            // Giving the column default parameters
            $column = array_merge(array('null' => 'yes', 'default' => '', 'extra' => ''), $column);
            
            $sql .= '`' . $column['field'] . '`'
                . ' ' . $column['type']
                . ( $column['null'] === 'no' ? ' NOT NULL'                      : ' NULL' )
                . ( $column['default']       ? ' DEFAULT ' . $column['default'] : '' )
                . ( $column['extra']         ? ' ' . $column['extra']           : '' )
                .",\n";
            
        }
    
        // Add index to request
        foreach( $schema['indexes'] as $index ){
            $sql .= $index['type'] . ' ' . $index['name'] . ' ' . $index['body'] . ",\n";
        }
    
        $sql = substr($sql, 0, -2) . ');';
        
        $result = $this->db->execute($sql);
        if ($result === false) {
            $errors[] = "Failed.\nQuery: $sql\nError: " . $this->db->get_last_error();
        }

        // @todo make logger
        // Logging errors
        if (!empty($errors)) {
            spbc_log($errors);
        }
    }
}
