<?php

namespace CleantalkSP\SpbctWP\DB;

use Exception;

/**
 * The class translates the array of data stored in the option into a set of classes and in the opposite direction.
 */
class DbDataConverter
{
    private $option_name;
    private $collection = array();

    public function __construct($option_name)
    {
        $this->option_name = $option_name;
    }

    /**
     * Loading data from DB and filling collection
     *
     * @return $this
     */
    public function loadCollection()
    {
        $collection = get_option($this->option_name, true);

        if (is_array($collection) && !empty($collection)) {
            foreach ($collection as $class_name => $class_data) {
                $this->collection[] = $this->createObject($class_name, $class_data);
            }
        }

        return $this;
    }

    /**
     * @param $class_name
     * @param $class_data
     *
     * @return ObjectForOptionsInterface
     * @throws Exception
     */
    public function createObject($class_name, $class_data = array())
    {
        $object = new $class_name($class_data);
        if (!$object instanceof ObjectForOptionsInterface) {
            throw new Exception('Please, implement in the class ObjectForOptionsInterface');
        }
        $this->collection[] =  $object;

        return $object;
    }

    /**
     * @param $class
     *
     * @return mixed
     */
    public function getObject($class)
    {
        if ($this->collection) {
            foreach ($this->collection as $object) {
                if ($object instanceof $class) {
                    return $object;
                }
            }
        }

        $object = new $class();
        $this->collection[] = $object;

        return $object;
    }

    // Clearing data in DB
    public function reset()
    {
        update_option($this->option_name, array());
    }

    public function saveToDb()
    {
        $data_as_array = array();
        foreach ($this->collection as $object) {
            $data_as_array[$object->getName()] = $object->getData();
        }

        update_option($this->option_name, $data_as_array);
    }
}
