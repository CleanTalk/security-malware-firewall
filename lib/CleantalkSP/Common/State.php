<?php

namespace CleantalkSP\Common;

/*
 *
 * CleanTalk Security State class
 *
 * @package Security Plugin by CleanTalk
 * @subpackage State
 * @Version 2.0
 * @author Cleantalk team (welcome@cleantalk.org)
 * @copyright (C) 2014 CleanTalk team (http://cleantalk.org)
 * @license GNU/GPL: http://www.gnu.org/copyleft/gpl.html
 *
 */

/**
 * @property mixed data
 * @property mixed settings
 * @property mixed network_settings
 * @property mixed network_data
 * @property mixed errors
 * @property mixed fw_stats
// * @property mixed fw_stats
 */
abstract class State
{
    /**
     * Array of options to store in object
     * @var array
     */
    protected $options;
    public $is_network;
    /** @psalm-suppress PossiblyUnusedProperty */
    public $is_mainsite;
    public $errors;
    /** @psalm-suppress PossiblyUnusedProperty */
    public $doing_cron = false;
    /** @psalm-suppress PossiblyUnusedProperty */
    public $option_prefix = '';
    public $storage = array();

    /**
     * Additional action with options
     * Set something depending on something
     *
     * Adding some dynamic properties
     *
     * Read code for details
     *
     * @return void
     */
    abstract protected function init();

    /**
     * Wrapper for CMS
     * Getting the option from the database
     *
     * @param $option_name
     *
     * @return bool|mixed|void
     */
    abstract protected function getOption($option_name);

    /**
     * Saving given option to DB
     *
     * @param string $option_name
     * @param bool $use_perfix
     * @param bool $autoload
     */
    abstract public function save($option_name, $use_perfix = true, $autoload = true);

    /**
     * Delete given option form DB and State
     *
     * @param $option_name
     * @param bool $use_prefix
     * @psalm-suppress PossiblyUnusedMethod
     */
    abstract public function deleteOption($option_name, $use_prefix = false);

    public function __construct($option_prefix, $options = array('settings'), $is_network = false, $is_mainsite = true)
    {
        $this->option_prefix = $option_prefix;
        $this->options       = $options;
        $this->is_network    = $is_network;
        $this->is_mainsite   = $is_mainsite;

        $this->setOptions();
        $this->init();
    }

    /**
     * Get options from the database
     * Set it to object
     */
    private function setOptions()
    {
        // Additional options for WPMS
        if ($this->is_network) {
            $this->options[] = 'network_settings';
            $this->options[] = 'network_data';
        }

        foreach ($this->options as $option_name) {
            $option = $this->getOption($option_name);

            $default_option_name = 'default_' . $option_name;

            $option = is_array($option) && isset($this->$default_option_name)
                ? array_merge($this->$default_option_name, $option)
                : $this->$default_option_name;

            $this->$option_name = is_array($option) ? new \ArrayObject($option) : $option;
        }
    }

    /**
     * Get an option from the database and to the object storage
     *
     * @param $option_name
     */
    private function getOptionForDynamicCalls($option_name)
    {
        $option = $this->getOption($option_name);
        $this->$option_name = is_array($option)
            ? new \ArrayObject($option)
            : $option;
    }

    /**
     * Saving all the options in State
     *
     * @return void
     * @psalm-suppress PossiblyUnusedMethod
     */
    public function saveAll()
    {
        foreach ($this->storage as $option_name => $_option_value) {
            if (property_exists($this, 'default_' . $option_name)) {
                $this->save($option_name);
            }
        }
    }

    /**
     * Prepares an adds an error to the plugin's data
     *
     * @param string type
     * @param mixed array || string
     * @returns null
     */
    public function error_add($type, $error, $major_type = null, $set_time = true, $custom_timestamp = null) // phpcs:ignore PSR1.Methods.CamelCapsMethodName.NotCamelCaps
    {
        $error = is_array($error) && isset($error['error'])
            ? $error['error']
            : $error;

        // Exceptions
        if (($type == 'send_logs'          && $error == 'NO_LOGS_TO_SEND') ||
            ($type == 'send_firewall_logs' && $error == 'NO_LOGS_TO_SEND') ||
            $error == 'LOG_FILE_NOT_EXISTS'
        ) {
            return;
        }

        $error = array(
            'error'      => $error,
            'error_time' => $set_time
                ? isset($custom_timestamp)
                    ? $custom_timestamp
                    : time()
                : null,
        );

        if (!empty($major_type)) {
            $this->errors[$major_type][$type] = $error;
        } else {
            $this->errors[$type] = $error;
        }

        $this->save('errors', true, false);
    }

    /**
     * Set or deletes an error depends of the first bool parameter
     *
     * @param              $add_error
     * @param string|array $error Error string
     * @param string       $type
     * @param null         $major_type
     * @param bool         $set_time
     * @param bool         $save_flag
     */
    public function error_toggle($add_error, $type, $error, $major_type = null, $set_time = true, $save_flag = true) // phpcs:ignore PSR1.Methods.CamelCapsMethodName.NotCamelCaps
    {
        if ($add_error) {
            $this->error_add($type, $error, $major_type, $set_time);
        } else {
            $this->error_delete($type, $save_flag, $major_type);
        }
    }

    /**
     * Deletes an error from the plugin's data
     *
     * @param string $type
     * @param bool   $save_flag
     * @param string $major_type
     *
     * @return void
     */
    public function error_delete($type, $save_flag = false, $major_type = null) // phpcs:ignore PSR1.Methods.CamelCapsMethodName.NotCamelCaps
    {
        $types = is_string($type) ? explode(' ', $type) : $type;

        foreach ($types as $val) {
            if ($major_type && isset($this->errors[$major_type][$val])) {
                unset($this->errors[$major_type][$val]);
            } elseif (isset($this->errors[$val])) {
                unset($this->errors[$val]);
            }
        }

        // Save if flag is set and there are changes
        if ($save_flag) {
            $this->save('errors');
        }
    }

    /**
     * Deletes all errors from the plugin's data
     *
     * @param bool $save_flag
     *
     * @return void
     * @psalm-suppress PossiblyUnusedMethod
     */
    public function error_delete_all($save_flag = false) // phpcs:ignore PSR1.Methods.CamelCapsMethodName.NotCamelCaps
    {
        $this->errors = new \ArrayObject($this->default_errors);
        if ($save_flag) {
            $this->save('errors');
        }
    }

    public function __set($name, $value)
    {
        $this->storage[$name] = $value;
    }

    /**
     * Dynamically get options in order:
     * 1. Trying to get it from the storage (options like data, settings, fw_stats and so on)
     * 2. Trying to get it from the storage['data']
     * 3. Trying to get it from the storage['network_data']
     * 4. Trying to get it from the storage['settings']
     * 5. Trying to get it from the storage['network_settings']
     * 6. Trying to get it from the DB by name
     *
     * @param $name
     *
     * @return mixed
     */
    public function &__get($name)
    {
        // First check in storage
        if (isset($this->storage[$name])) {
            $out = $this->storage[ $name ];

        // Then in data
        } elseif (isset($this->storage['data'][$name])) {
            $this->$name = $this->storage['data'][$name];
            $out         = $this->storage['data'][$name];

        // Then in network data
        } elseif (isset($this->storage['network_data'][$name])) {
            $this->$name = $this->storage['network_data'][$name];
            $out         = $this->storage['network_data'][$name];

        // Then in settings
        } elseif (isset($this->storage['settings'][$name])) {
            $this->$name = $this->storage['settings'][$name];
            $out         = $this->storage['settings'][$name];

        // Then in network settings
        } elseif (isset($this->storage['network_settings'][$name])) {
            $this->$name = $this->storage['network_settings'][$name];
            $out         = $this->storage['network_settings'][$name];

        // Otherwise try to get it from db settings table
        // it will be arrayObject || scalar || null
        } else {
            $this->getOptionForDynamicCalls($name);
            $out = $this->storage[$name];
        }

        return $out;
    }

    public function __isset($name)
    {
        return isset($this->storage[$name]);
    }

    public function __unset($name)
    {
        unset($this->storage[$name]);
    }

    /**
     * @return bool|array
     * @psalm-suppress PossiblyUnusedMethod
     */
    protected function is_windows() // phpcs:ignore PSR1.Methods.CamelCapsMethodName.NotCamelCaps
    {
        if ( !function_exists('php_uname') ) {
            if ( defined('PHP_OS') ) {
                $result = strpos(strtolower(PHP_OS), 'win') !== false ? true : false;
            } else {
                $result = array('error' => 'Function php_uname and PHP_OS are unavailable');
            }
        } else {
            $result = strpos(strtolower(php_uname('s')), 'windows') !== false ? true : false;
        }
        return $result;
    }
}
