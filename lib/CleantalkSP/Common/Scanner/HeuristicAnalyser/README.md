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

// MyModel class need to be extended \CleantalkSP\Common\Scanner\HeuristicAnalyser\Model\Model
$my_model = new myMoodel();

// Instantiate the scanner module
$heuristic_scanner = new Controller($my_model);

// Prepare files information
$file_to_check = new FileInfo(
    'name_of_the_file.php',
    'full_hash'
);

// $res will contain the scanning result
$res = $heuristic_scanner->scanFile($file_to_check);
```
