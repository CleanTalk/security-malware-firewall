<?php

namespace CleantalkSP\SpbctWP\Scanner;

class Surface
{
    /**
     * Main path
     * @var string
     * @psalm-suppress PossiblyUnusedProperty
     */
    public $path = '';

    public $path_lenght = 0;

    /**
     * Description Extensions to check
     * @var array
     */
    public $ext = array();

    /**
     * Exception for extensions
     * @var array
     */
    public $ext_except = array();

    /**
     * Exception for files paths
     * @var array
     */
    public $files_except = array();

    /**
     * Exception for directories
     * @var array
     */
    public $dirs_except = array();

    /**
     * Mandatory check for files paths
     * @var array
     */
    public $files_mandatory = array();

    /**
     * Mandatory check for directories
     * @var array
     * @psalm-suppress PossiblyUnusedProperty
     */
    public $dirs_mandatory = array();

    public $files = array();
    public $dirs = array();

    public $files_count = 0;

    /**
     * @var int
     * @psalm-suppress PossiblyUnusedProperty
     */
    public $dirs_count = 0;

    private $file_start = 0;
    private $file_curr = 0;
    private $file_max = 1000000;
    /**
     * @var array|null
     * @psalm-suppress UnusedProperty
     */
    private $output_file_details;

    public function __construct($path, $rootpath, $params = array('count' => true))
    {
        // INITILAZING PARAMS

        // Main directory
        $path = realpath($path);
        if ( ! is_dir($path) ) {
            die("Scan '$path' isn't directory");
        }
        if ( ! is_dir($rootpath) ) {
            die("Root '$rootpath' isn't directory");
        }
        $this->path_lenght = strlen($rootpath);

        // Processing filters
        $this->ext          = ! empty($params['extensions']) ? $this->filterParams($params['extensions']) : array();
        $this->ext_except   = ! empty($params['extensions_exceptions']) ? $this->filterParams(
            $params['extensions_exceptions']
        ) : array();
        $this->files_except = ! empty($params['file_exceptions']) ? $this->filterParams(
            $params['file_exceptions']
        ) : array();
        $this->dirs_except  = ! empty($params['dir_exceptions']) ? $this->filterParams(
            $params['dir_exceptions']
        ) : array();

        // Mandatory files and dirs
        $this->files_mandatory = ! empty($params['files_mandatory']) ? $this->filterParams(
            $params['files_mandatory']
        ) : array();
        $this->dirs_mandatory  = ! empty($params['dirs_mandatory']) ? $this->filterParams(
            $params['dirs_mandatory']
        ) : array();

        // Initilazing counters
        $this->file_start = isset($params['offset']) ? $params['offset'] : 0;
        $this->file_max   = isset($params['offset']) && isset($params['amount']) ? $params['offset'] + $params['amount'] : 1000000;

        $this->output_file_details = ! empty($params['output_file_details']) ? $this->filterParams(
            $params['output_file_details']
        ) : array();

        // DO STUFF

        // Only count files
        if ( ! empty($params['count']) ) {
            $this->countFilesMandatory($this->files_mandatory);
            $this->countFilesInDir($path);

            return;
        }
        // Getting files and dirs considering filters
        $this->getFilesMandatory($this->files_mandatory);
        $this->getFileStructure($path);
        // Files
        $this->files_count = count($this->files);
        $this->fileDetails($this->files, $this->path_lenght);

        if ( $this->output_file_details ) {
            foreach ( $this->files as &$file ) {
                $file_tmp = array();
                foreach ( $this->output_file_details as $detail ) {
                    $file_tmp[$detail] = $file[$detail];
                }
                $file = $file_tmp;
            }
            unset($file);
        }

        // Directories
        // $this->dirs[]['path'] = $path;
        // $this->dirs_count = count($this->dirs);
        // $this->dir__details($this->dirs, $this->path_lenght);
    }

    /**
     * * Function coverting icoming parametrs to array even if it is a string like 'some, example, string'
     *
     * @param $filter
     *
     * @return array|null
     */
    public function filterParams($filter)
    {
        if ( ! empty($filter) ) {
            if ( ! is_array($filter) ) {
                if ( strlen($filter) ) {
                    $filter = explode(',', $filter);
                }
            }
            foreach ( $filter as $_key => &$val ) {
                $val = trim($val);
            }

            return $filter;
        }

        return null;
    }

    /**
     * Counts given mandatory files
     *
     * @param array $files Files to count
     */
    public function countFilesMandatory($files)
    {
        foreach ( $files as $file ) {
            if ( is_file($file) ) {
                $this->files_count++;
            }
        }
    }

    /**
     * Count files in directory
     *
     * @param string $main_path Path to count files in
     */
    public function countFilesInDir($main_path)
    {
        try {
            foreach (
                @new \FilesystemIterator(
                    $main_path,
                    \FilesystemIterator::CURRENT_AS_PATHNAME | \FilesystemIterator::KEY_AS_FILENAME
                ) as $file_name => $path
            ) {
                // Skip bad paths
                if ( ! $file_name || ! $path ) {
                    continue;
                }

                if ( $file_name === ".." || $file_name === "." ) {
                    continue;
                }

                $path = (string) $path;

                if ( is_dir($path) ) {
                    // Directory names filter
                    foreach ( $this->dirs_except as $dir_except ) {
                        if ( strpos($path, $dir_except) ) {
                            continue(2);
                        }
                    }

                    $this->countFilesInDir($path);
                } else {
                    // Extensions filter
                    if ( $this->ext_except || $this->ext ) {
                        $tmp = explode('.', $path);
                        if (
                            ($this->ext_except && in_array($tmp[count($tmp) - 1], $this->ext_except, true)) ||
                            ($this->ext && ! in_array($tmp[count($tmp) - 1], $this->ext, true))
                        ) {
                            continue;
                        }
                    }

                    // Filenames exception filter
                    if ( ! empty($this->files_except) && in_array($file_name, $this->files_except, true) ) {
                        continue;
                    }

                    $this->files_count++;
                }
            }
        } catch ( \Exception $e ) {
        }
    }

    /**
     * Getting mandatory files
     *
     * @param array $files Files to get
     */
    public function getFilesMandatory($files)
    {
        foreach ( $files as $file ) {
            if ( is_file($file) ) {
                $this->files[]['path'] = $file;
                $this->file_curr++;
            }
        }
    }

    /**
     * Get all files from directory
     *
     * @param string $main_path Path to get files from
     *
     * @return void
     */
    public function getFileStructure($main_path)
    {
        if ( is_dir($main_path) && $this::dirIsEmpty($main_path) ) {
            return;
        }

        try {
            $it = new \FilesystemIterator(
                $main_path,
                \FilesystemIterator::CURRENT_AS_PATHNAME | \FilesystemIterator::KEY_AS_FILENAME
            );

            foreach ( $it as $file_name => $path ) {
                if ( ! $path ) {
                    continue;
                }

                if ( $file_name === ".." || $file_name === "." ) {
                    continue;
                }

                $path = (string) $path;

                // Return if file limit is reached
                if ( $this->file_curr >= $this->file_max ) {
                    return;
                }

                if ( is_file($path) ) {
                    // Extensions filter
                    if ( $this->ext_except || $this->ext ) {
                        $tmp = explode('.', $path);
                        if (
                            ($this->ext_except && in_array($tmp[count($tmp) - 1], $this->ext_except, true)) ||
                            ($this->ext && ! in_array($tmp[count($tmp) - 1], $this->ext, true))
                        ) {
                            continue;
                        }
                    }

                    // Filenames exception filter
                    if ( ! empty($this->files_except) && in_array($file_name, $this->files_except, true) ) {
                        continue;
                    }

                    $this->file_curr++;

                    // Skip if start is not reached
                    if ( $this->file_curr - 1 < $this->file_start ) {
                        continue;
                    }

                    $this->files[]['path'] = $path;
                } elseif ( is_dir($path) ) {
                    // Directory names filter
                    foreach ( $this->dirs_except as $dir_except ) {
                        if ( strpos($path, $dir_except) ) {
                            continue(2);
                        }
                    }

                    $this->getFileStructure($path);
                    if ( $this->file_curr > $this->file_start ) {
                        $this->dirs[]['path'] = $path;
                    }
                } elseif ( is_link($path) ) {
                    error_log('LINK FOUND: ' . $path);
                }
            }
        } catch ( \Exception $exception ) {
            return;
        }
    }

    /**
     * Getting file details like last modified time, size, permissions
     *
     * @param array $file_list Array of abolute paths to files
     * @param int $path_offset Length of CMS root path
     */
    public function fileDetails($file_list, $path_offset)
    {
        global $wpdb, $spbc;

        foreach ( $file_list as $key => $val ) {
            // Cutting file's path, leave path from CMS ROOT to file

            // This order is important!!!
            $this->files[$key]['path']  = substr(
                $spbc->is_windows ? str_replace('/', '\\', $val['path']) : $val['path'],
                $path_offset
            );
            $this->files[$key]['size']  = filesize($val['path']);
            $this->files[$key]['perms'] = substr(decoct(fileperms($val['path'])), 3);
            $mtime = @filemtime($val['path']);
            if ( empty($mtime) ) {
                clearstatcache($val['path']);
                $mtime = @filemtime($val['path']);
                if ( empty($mtime) ) {
                    $mtime = @filectime($val['path']);
                    if ( empty($mtime) ) {
                        $mtime = time();
                    }
                }
            }

            $this->files[$key]['mtime'] = $mtime;

            // Fast hash
            $this->files[$key]['fast_hash'] = md5($this->files[$key]['path']);
            $fast_hash                      = $this->files[$key]['fast_hash'];

            // Full hash
            /**
             * Added SQL query to get the full hash of the file from the database.
             * If full hashes does not match, then the file is resaved with LF line ends
             */
            if ( ! is_readable($val['path']) ) {
                $this->files[$key]['full_hash'] = 'unknown';
                continue;
            }

            $current_file_full_hash = md5_file($val['path']);

            $sql = $wpdb->prepare(
                'SELECT `full_hash` FROM ' . SPBC_TBL_SCAN_FILES . ' WHERE `fast_hash` = %s',
                $fast_hash
            );

            $db_full_hash = $wpdb->get_var($sql);

            if ( $db_full_hash && $current_file_full_hash !== $db_full_hash ) {
                $current_file_content  = file_get_contents($val['path']);
                $current_file_eol_type = spbc_PHP_logs__detect_EOL_type($val['path']);

                if ( $current_file_content ) {
                    $file_content = $current_file_content;

                    // LF
                    if ( $current_file_eol_type === 'LF' ) {
                        $file_content = str_replace(array("\r\n", "\r", "\n"), "\r\n", $current_file_content);
                    }
                    // CRLF
                    if ( $current_file_eol_type === 'CRLF' ) {
                        $file_content = str_replace(array("\r\n", "\r", "\n"), "\n", $current_file_content);
                    }

                    $file_content_hash = md5($file_content);

                    // All fine, changed EOL
                    if ( $file_content_hash === $db_full_hash ) {
                        $this->files[$key]['full_hash'] = $file_content_hash;
                        continue;
                    }
                }
            }

            $this->files[$key]['full_hash'] = $current_file_full_hash;
        }
    }

    /**
     * Getting dir details
     *
     * @param array $dir_list Array of abolute paths to directories
     * @param int $path_offset Length of CMS root path
     *
     * @psalm-suppress PossiblyUnusedMethod
     */
    public function dirDetails($dir_list, $path_offset)
    {
        global $spbc;

        foreach ( $dir_list as $key => $val ) {
            $this->dirs[$key]['path']  = substr(
                $spbc->is_windows ? str_replace('/', '\\', $val['path']) : $val['path'],
                $path_offset
            );
            $this->dirs[$key]['mtime'] = filemtime($val['path']);
            $this->dirs[$key]['perms'] = substr(decoct(fileperms($val['path'])), 2);
        }
    }


    /**
     * Check dir is empty
     *
     * @param $dir
     *
     * @return bool
     */
    public static function dirIsEmpty($dir)
    {
        //return false if permission denied
        $handle = @opendir($dir);
        if ( false === $handle ) {
            return false;
        }

        while ( false !== ($entry = readdir($handle)) ) {
            if ( $entry !== "." && $entry !== ".." ) {
                closedir($handle);

                return false;
            }
        }
        closedir($handle);

        return true;
    }
}
