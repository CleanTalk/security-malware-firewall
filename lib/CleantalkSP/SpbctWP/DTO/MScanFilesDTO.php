<?php

namespace CleantalkSP\SpbctWP\DTO;

use CleantalkSP\Templates\DTO;

class MScanFilesDTO extends DTO
{
    public $method_name = 'security_pscan_files';

    public $path_to_sfile = 'default path';
    public $attached_sfile = 'default file text';
    public $md5sum_sfile = 'default md5sum_sfile text';
    public $dangerous_code = array('DEFAULT DANGEROUS CODE' => array('1' => array('default')));
    public $version = 'default version';
    public $source = 'default source';
    public $source_type = 'default source_type';
    public $source_status = 'default source_status';
    public $real_hash = 'default real_hash';
    public $client_php_version = 'default client_php_version';
    public $auto_send_type = 'default auto_send_type';
    public $current_scanner_settings = 'default current_scanner_settings';
    public $plugin_heuristic_checked  = 'default plugin_heuristic_checked';
    public $plugin_signatures_checked  = 'default plugin_signatures_checked';

    public function __construct($data)
    {
        parent::__construct($data);

        $not_empty = array(
            'path_to_sfile',
            'attached_sfile',
            'md5sum_sfile'
        );

        foreach ( $not_empty as $param ) {
            if ( empty($this->$param) ) {
                throw new \InvalidArgumentException('MScanFilesDTO: param "' . $param . '" is empty.');
            }
        }

        // make weak_spots values unique
        if ( empty($this->dangerous_code) ||
            (isset($this->dangerous_code[0]) && $this->dangerous_code[0] === 'NULL')
        ) {
            $this->dangerous_code = '{}';
        } else if ( is_array($this->dangerous_code) ) {
            foreach ($this->dangerous_code as $_type => &$ws_strings_arr) {
                if ( is_array($ws_strings_arr) ) {
                    foreach ($ws_strings_arr as $_key => &$value) {
                        $value = array_unique($value);
                    }
                    unset($value);
                }
            }
            unset($ws_strings_arr);
            $this->dangerous_code = json_encode($this->dangerous_code);
        }
    }
}
