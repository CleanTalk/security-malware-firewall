<?php

namespace CleantalkSP\Common\Scanner\SignaturesAnalyser\Model;

abstract class Model
{
    /**
     * @return array
     */
    abstract public function getSignatures();

    /**
     * @return string
     */
    abstract public function getRootPath();
}
