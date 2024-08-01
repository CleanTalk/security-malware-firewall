<?php

namespace CleantalkSP\SpbctWP\Scanner;

use Exception;
use CleantalkSP\SpbctWP\Helpers\HTTP;
use CleantalkSP\Common\RemoteCalls;

class DirectoryScan
{
    /**
     * Root path
     *
     * @var string
     */
    private $root;

    /**
     * Path to directory to scan
     *
     * @var string
     */
    private $directory;

    /**
     * @var array
     */
    public $results = array();

    /**
     * Files collected from the directory
     *
     * @var array
     */
    private $files;

    /**
     * Additional parameters for file collector
     * @var array
     */
    private $params;

    /**
     * DirectoryScan constructor.
     *
     * @param string $directory Path to directory to scan
     * @param string $root Root path
     * @param array $params Additional parameters for file collector
     */
    public function __construct($directory, $root, $params = null)
    {
        $this->directory = realpath($directory);
        $this->root      = realpath($root);
        $this->params    = $params;
    }

    /**
     * Collecting files from the specified directory
     *
     * @set $this->files
     * @throws Exception
     */
    public function setElements()
    {
        $file_scanner = new Surface(
            $this->directory,
            $this->root,
            array_merge(
                array(
                    'extensions'            => 'php, html, htm, php2, php3, php4, php5, php6, php7, phtml, shtml, phar, js, odf',
                    'extensions_exceptions' => array('jpg', 'jpeg', 'png', 'gif', 'css', 'txt', 'zip', 'xml', 'json'),
                ),
                $this->params
            )
        );

        if ( ! $file_scanner->has_errors ) {
            throw new Exception('Scanner. Files collection. Directory scan internal error.', 0);
        }

        if ( ! $file_scanner->output_files_count ) {
            throw new Exception('Scanner. Files collection. No files to scan.', 0);
        }

        $this->files = $file_scanner->output_files_count;
    }

    public function setFiles($files)
    {
        $this->files = $files;
    }

    /**
     * Performs scan
     * Wrapper for scanInMultipleThreads() and scanInSingleThread()
     * Puts the results in $this->results
     *
     * @param bool $multi_thread
     *
     * @return array
     */
    public function scan($multi_thread = false)
    {
        if ( $multi_thread ) {
            $this->scanInMultipleThreads();
        } else {
            $this->scanInSingleThread();
        }

        return $this->results;
    }

    /**
     * Scan all files from $this->files in multiple threads using curl_multi and remoteCalls
     *
     * Put the results in $this->results
     */
    private function scanInMultipleThreads()
    {
        global $spbc;

        // Gathering files in packs, compile URLs
        for (
            $pack_size = 5, $url_pack = array(), $file_pack = array(), $i = 0, $i_max = count($this->files) - 1;
            $i <= $i_max;
            $i++
        ) {
            $file        = $this->files[$i];
            $file_pack[] = $file;

            if ( $i === $i_max || count($file_pack) === $pack_size ) {
                $url_pack[] = HTTP::appendParametersToURL(
                    get_option('home'),
                    RemoteCalls::buildParameters(
                        'scanner__check_dir',
                        'spbc',
                        $spbc->api_key,
                        array('file_infos' => $file_pack)
                    )
                );
                $file_pack  = array();
            }
        }

        $http         = new \CleantalkSP\Common\HTTP\Request();
        $http_results = $http
            ->setUrl($url_pack)
            ->addCallback(__CLASS__ . '::scanInMultipleThreadsCallback')
            ->request();

        foreach ( $http_results as $http_result ) {
            if ( isset($http_result['error']) ) {
                $this->results[] = $http_result;
            } else {
                $this->results = array_merge($this->results, $http_result);
            }
        }
    }

    /**
     * @param string $response_content
     * @param string $url
     *
     * @return array
     */
    public static function scanInMultipleThreadsCallback($response_content, $_url)
    {

        $response_content = json_decode($response_content, true);
        if ( $response_content === null ) {
            return array('error' => 'BAD_JSON');
        }

        if ( ! empty($response_content['error']) ) {
            $response_content = array('error' => $response_content['error']);
        }

        return $response_content;
    }

    /**
     * Scan all files from $this->files in a single thread right now
     * Put the results in $this->results
     */
    private function scanInSingleThread()
    {
        $signatures         = Controller::getSignatures();
        $signatures_scanner = new \CleantalkSP\Common\Scanner\SignaturesAnalyser\Controller();

        foreach ( $this->files as $file ) {
            $file_to_check = new \CleantalkSP\Common\Scanner\SignaturesAnalyser\Structures\FileInfo(
                $file['path'],
                $file['full_hash']
            );

            $sign_result = $signatures_scanner->scanFile($file_to_check, $this->root, $signatures);

            // @ToDo have to get rid of this unnecessary merge. but it will require a lot of changes.
            // @ToDo $sign_result is an instance of Verdict, but client code expects an array.
            $result = Controller::mergeResults($sign_result, []);
            $this->results = array_merge($this->results, $result);
            $this->results['path'] = $file['path'];
        }
    }
}
