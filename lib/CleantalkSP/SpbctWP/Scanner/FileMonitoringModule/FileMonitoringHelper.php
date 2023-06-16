<?php

namespace CleantalkSP\SpbctWP\Scanner\FileMonitoringModule;

class FileMonitoringHelper
{
    public static function getThemeFunctionsPaths()
    {
        $theme_functions_paths = array();
        $theme_dir_path = ABSPATH . 'wp-content/themes';
        $theme_dirs_and_files = scandir($theme_dir_path);

        if (!empty($theme_dirs_and_files)) {
            foreach ($theme_dirs_and_files as $element) {
                $current_theme_dir_path = $theme_dir_path . '/' . $element;
                if (!in_array($element, array('.', '..')) && is_dir($current_theme_dir_path)) {
                    $theme_functions_path = $current_theme_dir_path . '/functions.php';
                    if (file_exists($theme_functions_path)) {
                        $theme_functions_paths[] = '/wp-content/themes/' . $element . '/functions.php';
                    }
                }
            }
        }

        return $theme_functions_paths;
    }
}
