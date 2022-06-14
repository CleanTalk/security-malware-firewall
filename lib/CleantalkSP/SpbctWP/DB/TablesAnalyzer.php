<?php

namespace CleantalkSP\SpbctWP\DB;

use CleantalkSP\SpbctWP\DB;

class TablesAnalyzer
{
    /**
     * @var array Tables which aren't exist
     */
    private $table_not_exists = array();

    /**
     * @var array Tables which exist
     */
    private $exist_tables = array();
    
    /**
     * @var bool Multisite is On
     */
    private $multisite;
    
    /**
     * @var DB
     */
    private $db;
    
    public function __construct()
    {
        $this->db        = DB::getInstance();
        $this->multisite = is_multisite();
        
        $this->checkingCurrentScheme();
    }
    
    /**
     * Checking the existence of tables and non-existent tables
     * Filled fields of class
     */
    private function checkingCurrentScheme()
    {
        global $wpdb;
    
        $blog_table_names   = \CleantalkSP\SpbctWP\DB\SQLSchema::getBlogTableNames();
        $common_table_names = \CleantalkSP\SpbctWP\DB\SQLSchema::getCommonTableNames();
        
        // Multisite
        if( $this->multisite ){
            
            $sites = get_sites();
            
            foreach( $sites as $site ){
                
                switch_to_blog($site->blog_id);
                
                foreach( $blog_table_names as $blog_table_name ){
                    
                    $table_name = $wpdb->prefix . $blog_table_name;
    
                    if( ! $this->db->isTableExists($table_name) ){
                        $this->table_not_exists[] = $table_name;
                    }else{
                        $this->exist_tables[] = $table_name;
                    }
                }
            }
            switch_to_blog(get_main_site_id());
        }
    
        foreach( array_merge($common_table_names, $blog_table_names) as $_table_name ){
            
            $table_name = $wpdb->prefix . $_table_name;
            
            if( ! $this->db->isTableExists($table_name) ){
                $this->table_not_exists[] = $table_name;
            }else{
                $this->exist_tables[] = $table_name;
            }
        }
    
        $this->exist_tables     = array_unique($this->exist_tables);
        $this->table_not_exists = array_unique($this->table_not_exists);
    }

    /**
     * Get non-exists tables
     */
    public function getNotExistingTables()
    {
        return $this->table_not_exists;
    }
    
    /**
     * @return array
     */
    public function getExistingTables()
    {
        return $this->exist_tables;
    }
}
