<?php


namespace CleantalkSP\DataStructures;

/**
 * Class ExtendedSplFixedArray
 *
 * Extends \SplFixedArray for purposes of heuristic scanner
 *
 * @version 1.0.0
 * @since   2.85
 */
class ExtendedSplFixedArray extends \SplFixedArray
{
	/**
     * Creates new \SplFixedArray from given \Iterable and \Countable object
     *
	 * @param array $array
	 * @param bool  $save_indexes
	 *
	 * @return ExtendedSplFixedArray
	 * @psalm-suppress MixedAssignment
	 */
	public static function createFromArray(array $array, $save_indexes = true)
	{
        $self = new self(count($array));
        if($save_indexes) {
            foreach($array as $key => $value) {
                $self[(int) $key] = $value;
            }
        } else {
            $i = 0;
            foreach (array_values($array) as $value) {
                $self[$i] = $value;
                $i++;
            }
        }
        
        return $self;
    }
	
	/**
     * Implementation of native PHP array_column for \SplFixedArray
     *
	 * @param int|string $column_to_get
	 *
	 * @return array|false
	 */
    public function getColumn($column_to_get)
	{
		$out = array();
		
        foreach( $this as $element ){
			if( isset( $element[ $column_to_get ]) ){
				$out[] = $element[ $column_to_get ];
			}
		}
		
		return $out;
	}
	
	/**
     * Reduce \SplFixedArray by recalculating size and reindex whole \SplFixedArray
     *
	 * @param \SplFixedArray $splFixedArray
	 *
	 * @return bool
	 */
	public static function reindex( $splFixedArray )
	{
		$new_key = 0;
		
		foreach( $splFixedArray as $key => $value ){
			
			if( $value === null ){
				continue;
			}
			
			if( $new_key !== $key ){
				$splFixedArray[ $new_key ] = $value;
				unset( $splFixedArray[ $key ] );
			}
			
			$new_key++;
		}
		
		// Set new size of \SplFixedArray
		$splFixedArray->setSize( $new_key );
		
		return true;
	}
	
	/**
     * Get slice of the current ExtendedSplFixedArray
     *
	 * @param int $start
	 * @param int $end
	 *
	 * @return ExtendedSplFixedArray
	 */
	public function slice( $start, $end ){
		
		for(
			$out = array(), $index = $start;
			$index <= $end;
			$index++
		){
			$out[] = $this[ $index ];
		}
		
		return self::createFromArray($out, false);
	}
    
    /**
     * Implementation of array_unshift for \SplFixedArray
     *
     * @param $first_elem
     *
     * @return ExtendedSplFixedArray
     */
    public function unshift($first_elem)
    {
        $temp_arr = $this->toArray();
        array_unshift($temp_arr, $first_elem);
        
        return self::createFromArray($temp_arr);
    }
}