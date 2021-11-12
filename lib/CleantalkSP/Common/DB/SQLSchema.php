<?php

namespace CleantalkSP\Common\DB;

class SQLSchema
{
    
    /**
     * Schema table prefix
     */
    private static $schema_prefix = 'spbc_';
    
    /**
     * Preprocess requested scheme name
     * Allows both to use prefix (spbc_) or not
     *
     * @param string $name
     *
     * @return string
     */
    private static function processSchemaName( $name ){
        return strpos( $name, self::$schema_prefix ) !== false
            ? preg_replace('/.*?spbc_(.+)/', '$1', $name)
            : $name;
    }
    
    /**
     * Searches and returns schema
     *
     * @param string $table Name of called table
     *
     * @return array      Schema
     */
    public static function getByName( $table )
    {
        $schemas__all = static::getAll();
        $table        = static::processSchemaName($table);

        if( array_key_exists( $table, $schemas__all ) ) {
            return $schemas__all[$table];
        }
    }


    /**
     * Searches and returns schema of common type
     *
     * @param null|string $table         Name of called table
     * @return array                     Array of schemas
     * @throws \Exception                Throws if calling un-existed schema
     */
    public static function getAllCommon( $table = null )
    {
        return static::$schemas__common;
    }

    /**
     * Searches and returns schema of blog type
     *
     * @param null|string $table         Name of called table
     * @return array                     Array of schemas
     * @throws \Exception                Throws if calling un-existed schema
     */
    public static function getAllBlog( $table = null )
    {
        return static::$schemas__blog;
    }
    
    /**
     * Returns all schemas of all types
     */
    public static function getAll()
    {
        return array_merge(static::$schemas__common, static::$schemas__blog);
    }
    
    /**
     * Return all tables names with schema prefix added.
     * Wrapper for self::getBlogTableNames() and self::getCommonTableNames()
     *
     * @param bool $with_schema_prefix
     *
     * @return array
     */
    public static function getAllTableNames( $with_schema_prefix = true )
    {
        return array_merge(
            self::getBlogTableNames( $with_schema_prefix ),
            self::getCommonTableNames( $with_schema_prefix )
        );
    }
    
    
    /**
     * Return all tables names with schema prefix added.
     *
     * @param bool $with_schema_prefix
     *
     * @return array
     */
    public static function getBlogTableNames( $with_schema_prefix = true )
    {
        $table_names = array_keys( static::$schemas__blog );
        
        if( $with_schema_prefix ){
            foreach( $table_names as &$table_name ){
                $table_name = self::getSchemaPrefix() . $table_name;
            }
        }
        
        return $table_names;
    }
    
    /**
     * Return all tables names with schema prefix added.
     *
     * @param bool $with_schema_prefix
     *
     * @return array
     */
    public static function getCommonTableNames( $with_schema_prefix = true )
    {
        $table_names = array_keys( static::$schemas__common );
        
        if( $with_schema_prefix ){
            foreach( $table_names as &$table_name ){
                $table_name = self::getSchemaPrefix() . $table_name;
            }
        }
        
        return $table_names;
    }
    
    /**
     * Return scheme prefix
     *
     * @return string
     */
    public static function getSchemaPrefix()
    {
        return self::$schema_prefix;
    }
    
    /**
     * Return standard column fields for scheme
     *
     * @return string[]
     */
    public static function getFieldStandard()
    {
        return static::$field_standard;
    }
    
}