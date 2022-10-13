<?php

namespace CleantalkSP\SpbctWP\Scanner\UnsafePermissionsModule;

use CleantalkSP\Templates\Singleton;

/**
 * We store a list of files and folders from which we check permission
 */
class UnsafePermissionsContainer
{
    use Singleton;

    private static $list = array(
        'files' => array(
            '/.htaccess' => '644',
            '/index.php' => '644',
            '/wp-config.php' => '644'
        ),
        'dirs'  => array(
            '/wp-admin' => '755',
            '/wp-includes' => '755',
            '/wp-content' => '755',
            '/wp-content/themes' => '755',
            '/wp-content/plugins' => '755',
            '/wp-content/uploads' => '755',
        )
    );

    /**
     * Get files
     */
    public static function getFiles()
    {
        return self::$list['files'];
    }

    /**
     * Get files
     */
    public static function getDirs()
    {
        return self::$list['dirs'];
    }
}
