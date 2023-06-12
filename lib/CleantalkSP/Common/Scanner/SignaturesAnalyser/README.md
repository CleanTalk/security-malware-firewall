# CleanTalk security scanner - Signatures Analysing module

## Install
```
composer require cleantalk/spbct-signatures-analyser
```

## Using
```php
<?php

// Require composer autoloader
require_once 'vendor/autoload.php';

use CleantalkSP\Common\Scanner\SignaturesAnalyser\Controller;
use CleantalkSP\Common\Scanner\SignaturesAnalyser\Structures\FileInfo;

$file_path = '/bad/index.php';
$root_dir_patn = __DIR__;
$sigantures = []; // Get signatures from the cloud

// Instantiate the scanner module
$signatures_scanner = new Controller();

// Prepare files information
$file_to_check = new FileInfo(
    $file_path,
    'full_hash'
);

// $res will contain the scanning result
$res = $signatures_scanner->scanFile($file_to_check, $root_dir_patn, $sigantures);

var_dump($res); // $res will contain the scanning result
```
