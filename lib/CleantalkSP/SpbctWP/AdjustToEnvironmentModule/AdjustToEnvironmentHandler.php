<?php

namespace CleantalkSP\SpbctWP\AdjustToEnvironmentModule;

use CleantalkSP\SpbctWP\AdjustToEnvironmentModule\AdjustToEnv\AdjustToEnvW3TotalCache;
use CleantalkSP\SpbctWP\AdjustToEnvironmentModule\Exceptions\ExceptionReverseAdjustClassNotExists;

class AdjustToEnvironmentHandler
{
    /**
     * Option name to store info what we changed
     */
    const OPTION_NAME = 'spbc_adjust_to_env';

    /**
     * Set of adjust classes
     * @var array
     */
    const SET_OF_ADJUST = [
        'w3tc' => AdjustToEnvW3TotalCache::class,
    ];

    /**
     * Info what we changed
     * @var array
     */
    private $info;

    /**
     * Constructor
     */
    public function __construct()
    {
        $this->info = self::getInfoWhatWeChanged();
    }

    /**
     * Run
     * @return void
     */
    public function handle()
    {
        foreach ( self::SET_OF_ADJUST as $_env_name => $class ) {
            $adjust = new $class($this->info);
            $adjust->run();
            $this->info = $adjust->getUpdatedInfo();
        }

        $this->saveInfoWhatWeChanged();
    }

    /**
     * Run one adjust
     * @param string $class
     * @return void
     * @throws ExceptionReverseAdjustClassNotExists
     */
    public function handleOne($class)
    {
        if (!class_exists($class)) {
            throw new ExceptionReverseAdjustClassNotExists();
        }

        $adjust = new $class($this->info);
        $adjust->runOne();
        $this->info = $adjust->getUpdatedInfo();

        $this->saveInfoWhatWeChanged();
    }

    /**
     * Reverse the adjustments made by the adjust() method
     * @param string $class
     * @return void
     * @throws ExceptionReverseAdjustClassNotExists
     */
    public function reverseAdjust($class)
    {
        if (!class_exists($class)) {
            throw new ExceptionReverseAdjustClassNotExists();
        }

        $adjust = new $class($this->info);
        $adjust->doReverseAdjust();
        $this->info = $adjust->getUpdatedInfo();

        $this->saveInfoWhatWeChanged();
    }

    /**
     * Get info what we changed
     * @return array
     */
    public static function getInfoWhatWeChanged()
    {
        return get_option(self::OPTION_NAME, []);
    }

    /**
     * Save info what we changed
     * @return void
     */
    public function saveInfoWhatWeChanged()
    {
        update_option(self::OPTION_NAME, $this->info);
    }
}
