# CleanTalk security scanner - Heuristic Analysing module

## Install
```
composer require cleantalk/spbct-heuristic-analyser
```

## Using
```php
<?php

// Require composer autoloader
require_once 'vendor/autoload.php';

use CleantalkSP\Common\Scanner\HeuristicAnalyser\Controller;
use CleantalkSP\Common\Scanner\HeuristicAnalyser\Structures\FileInfo;

$file_path = '/bad/index.php';
$root_dir_patn = __DIR__;

// Instantiate the scanner module
$heuristic_scanner = new Controller();

// Prepare files information
$file_to_check = new FileInfo($file_path);


$res = $heuristic_scanner->scanFile($file_to_check, $root_dir_patn);

var_dump($res); // $res will contain the scanning result
var_dump($heuristic_scanner->final_code); // $final_code will contain the de-obfuscated code
```
