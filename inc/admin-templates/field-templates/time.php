<?php

global $spbc;

echo '<input'
     . ' type="time"'
     . ' id="spbc_setting_' . $data['name'] . '"'
     . ' name="spbc_settings[' . $data['name'] . ']" ' . ($data['parent'] && ! $spbc->settings[ $data['parent'] ] ? ' disabled="disabled"' : '')
     . ' value="' . $data['value'] . '" '
     . ($data['required'] ? ' required="required"' : '')
     . '>';
