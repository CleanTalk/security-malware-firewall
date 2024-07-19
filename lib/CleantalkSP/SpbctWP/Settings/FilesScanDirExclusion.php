<?php

namespace CleantalkSP\SpbctWP\Settings;

use CleantalkSP\SpbctWP\Helpers\CSV;

class FilesScanDirExclusion
{
    private $DIR_EXCLUSION_FILE_NAME = 'spbct_directory_exclusions.txt';

    private $instance_dir_separator = '/';

    public function __construct()
    {
        global $spbc;

        $this->instance_dir_separator = $spbc->is_windows ? '\\' : '/';
    }

    public function dirExclusionsView($exclusions)
    {
        $dirs = CSV::parseNSV($exclusions);
        $result = [];

        foreach ($dirs as $key => $dir) {
            if (substr($dir, -strlen($this->DIR_EXCLUSION_FILE_NAME)) === $this->DIR_EXCLUSION_FILE_NAME) {
                $parsed_url = parse_url($dir);
                if (isset($parsed_url['scheme'])) {
                    $dir = preg_replace('#^' . $parsed_url['scheme'] . '://#', '', $dir);
                }
                $dirs[$key] = $dir;
            }
        }

        foreach ($dirs as $dir) {
            $dir = preg_replace('#\\\\+|\/+#', '/', $dir);
            $dir = trim($dir, "/");
            $dir = str_replace('/', $this->instance_dir_separator, $dir);
            $result[] = $dir;
        }

        return implode("\n", $result);
    }

    public function dirExclusions($exclusions)
    {
        $dirs = CSV::parseNSV($exclusions);
        $result = [];

        $upload_urls = [];
        foreach ($dirs as $key => $dir) {
            if (substr($dir, -strlen($this->DIR_EXCLUSION_FILE_NAME)) === $this->DIR_EXCLUSION_FILE_NAME) {
                $upload_urls[] = $dir;
                unset($dirs[$key]);
            }
        }

        $upload_dirs = $this->getUploadDirs($upload_urls);

        $upload_dirs = array_filter($upload_dirs, function ($dir) {
            return $dir !== '';
        });

        $dirs = array_merge($dirs, $upload_dirs);
        $dirs = array_unique($dirs);

        foreach ($dirs as $dir) {
            $dir = preg_replace('#\\\\+|\/+#', '/', $dir);
            $dir = trim($dir, "/");
            $dir = str_replace('/', $this->instance_dir_separator, $dir);
            $result[] = $dir;
        }

        return implode("\n", $result);
    }

    private function getUploadDir($url)
    {
        if (parse_url($url, PHP_URL_SCHEME) === null) {
            $url = 'http://' . $url;
        }

        $context = stream_context_create([
        'http' => [
            'timeout' => 5 // Timeout in seconds
            ]
        ]);
        $file_content = @file_get_contents($url, false, $context);

        if ($file_content === false) {
            return false;
        }

        return CSV::parseNSV($file_content);
    }

    private function getUploadDirs($urls)
    {
        $results = [];
        $upload_dirs_stat = [];

        foreach ($urls as $url) {
            $results[$url] = $this->getUploadDir($url);
        }

        foreach ($results as $dir => $dir_content) {
            if ($dir_content === false) {
                $upload_dirs_stat[$dir] = __('Unable to download content.', 'security-malware-firewall');
                unset($results[$dir]);
                continue;
            }

            $dir_content = array_filter($dir_content, function ($dir) {
                return $dir !== '';
            });

            $upload_dirs_stat[$dir] = count($dir_content);
        }

        update_option('spbc_upload_dirs_stat', $upload_dirs_stat);

        $upload_dirs_merged = [];
        foreach ($results as $dir) {
            $upload_dirs_merged = array_merge($upload_dirs_merged, array_values($dir));
        }

        return $upload_dirs_merged;
    }
}
