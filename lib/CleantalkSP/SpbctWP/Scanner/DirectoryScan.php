<?php


namespace CleantalkSP\SpbctWP\Scanner;


use \Exception;
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
                    'extensions'            => 'php, html, htm',
                    'extensions_exceptions' => array('jpg', 'jpeg', 'png', 'gif', 'css', 'txt', 'zip', 'xml', 'json'),
                ),
                $this->params
            )
        );
    
        if( ! $file_scanner->files_count ){
            throw new Exception('Scanner. Files collection. No files to scan.','');
        }
        
        $this->files = $file_scanner->files;
    }
    
    /**
     * Performs scan
     * Wrapper for scanInMultipleThreads() and scanInSingleThread()
     * Puts the results in $this->results
     *
     * @param bool $multi_thread
     *
     * @throws Exception
     *
     * @return array
     */
    public function scan( $multi_thread = false )
    {
        if( $multi_thread ){
            $this->scanInMultipleThreads();
        }else{
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
        for(
            $pack_size = 5, $url_pack = array(), $file_pack = array(), $i = 0, $i_max = count($this->files) - 1;
            $i <= $i_max;
            $i++
        ){
            
            $file        = $this->files[ $i ];
            $file_pack[] = $file;
            
            if( $i === $i_max || count( $file_pack ) === $pack_size ){
                
                $url_pack[] = HTTP::appendParametersToURL(
                    get_option( 'home' ),
                    RemoteCalls::buildParameters(
                        'scanner__check_file',
                        'spbc',
                        $spbc->api_key,
                        array( 'file_infos' => $file_pack )
                    )
                );
                $file_pack = array();
            }
        }
        
        $http         = new \CleantalkSP\Common\HTTP\Request();
        $http_results = $http
            ->setUrl($url_pack)
            ->addCallback(__CLASS__ . '::scanInMultipleThreadsCallback')
            ->request();
        
        foreach( $http_results as $http_result ){
            if( isset( $http_result['error'] ) ){
                $this->results[] = $http_result;
            }else{
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
    public static function scanInMultipleThreadsCallback( $response_content, $url )
    {
        $response_content = preg_replace('@^(OK|FAIL)\s@', '', $response_content );
        
        $response_content = json_decode($response_content, true);
        if( $response_content === null ){
            return array('error' => 'BAD_JSON');
        }
        
        if( ! empty( $response_content['error'] ) ){
            $response_content = array('error' => $response_content['error']);
        }
        
        return $response_content;
    }
    
    /**
     * Scan all files from $this->files in a single thread right now
     * Put the results in $this->results
     *
     * @throws Exception
     */
    private function scanInSingleThread(){
    
        $signatures = Controller::getSignatures();
        
        foreach( $this->files as $file ){
    
            $signature_result = Controller::scanFile($file, $this->root, $signatures);
            if( ! empty( $sign_result['error'] ) ){
                $sign_result = array();
                throw new Exception('Signature scanner. ' . $sign_result['error'],'');
            }
    
            $heuristic_result = Controller::scanFileForHeuristic($file);
            if( ! empty( $heur_result['error'] ) ){
                $heur_result = array();
                throw new Exception('Heuristic scanner. ' . $heur_result['error'],'');
            }
    
            $result = Controller::mergeResults( $signature_result, $heuristic_result );
            
            $this->results = array_merge($this->results, $result);
            error_log("scanInSingleThread:\n" . var_export($result, true));
        }
    }
    
    /**
     * @return array
     */
    public function getResults()
    {
        return $this->results;
    }
    
}