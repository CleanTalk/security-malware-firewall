<?php

namespace CleantalkSP\SpbctWP\AdminBannersModule\AdminBanners;

use CleantalkSP\Common\Helpers\Helper;

abstract class AdminBannerAbstract
{
    public $prefix = 'spbc_';

    const HIDING_TIME = 14;

    /**
     * Banner Id = prefix _ NAME _ user_id
     *
     * @var string
     */
    protected $banner_id;

    public function getCurrentScreenId()
    {
        return get_current_screen()->id;
    }

    public function show()
    {
        if ( $this->needToShow() ) {
            $this->display();
        }
    }

    abstract protected function needToShow();

    abstract protected function display();

    /**
     * Has the date of the last show expired?
     *
     * @return bool
     */
    protected function isDismissed()
    {
        $dismissed_date = get_option($this->banner_id);

        if ( $dismissed_date !== false && Helper::dateValidate($dismissed_date) ) {
            $current_date   = date_create();
            $dismissed_date = date_create($dismissed_date);

            $diff = date_diff($current_date, $dismissed_date);

            if ( $diff->days <= static::HIDING_TIME ) {
                return true;
            }
        }

        return false;
    }
}
