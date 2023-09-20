<?php

/**
 * Autoloader for \CleantalkSP\* classes
 *
 * @param string $class
 *
 * @return void
 */

spl_autoload_register(function ($class) {

    // Register class auto loader
    // Custom modules1
    if ( strpos($class, 'CleantalkSP') !== false ) {
        $class      = str_replace('CleantalkSP\Common\Scanner\HeuristicAnalyser\\', DIRECTORY_SEPARATOR, $class);
        $class_file = dirname(__DIR__) . $class . '.php';
        if ( file_exists($class_file) ) {
            require_once($class_file);
        }
    }
});
