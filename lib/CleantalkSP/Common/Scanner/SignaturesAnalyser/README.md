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

// MyModel class need to be extended \CleantalkSP\Common\Scanner\SignaturesAnalyser\Model\Model
$my_model = new myMoodel();

// Instantiate the scanner module
$signatures_scanner = new Controller($my_model);

// Prepare files information
$file_to_check = new FileInfo(
    'name_of_the_file.php',
    'full_hash'
);

// $res will contain the scanning result
$res = $signatures_scanner->scanFile($file_to_check);
```
