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
    }
}
