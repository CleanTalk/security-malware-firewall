<?php

namespace CleantalkSP\SpbctWP\Scanner\ScanningStagesModule\Stages;

abstract class ScanningStageAbstract
{
    /** @psalm-suppress PossiblyUnusedMethod */
    public function __construct($stage_data = array())
    {
        if (is_array($stage_data) && !empty($stage_data)) {
            foreach ($stage_data as $param => $value) {
                $this->$param = $value;
            }
        }
    }

    /** @psalm-suppress PossiblyUnusedMethod */
    public function set($param, $value)
    {
        $this->$param = $value;
    }

    /** @psalm-suppress PossiblyUnusedMethod */
    public function increase($param, $value)
    {
        $this->$param += $value;
    }

    /** @psalm-suppress PossiblyUnusedMethod */
    public function decrease($param, $value)
    {
        $this->$param -= $value;
    }

    /** @psalm-suppress PossiblyUnusedMethod */
    public function merge($param, $array)
    {
        foreach ($array as $key => $value) {
            $this_param = $this->$param;
            if (isset($this_param[$key])) {
                $this_param[$key] += $value;
            } else {
                $this_param[$key] = $value;
            }
            $this->$param = $this_param;
        }
    }
}
