<?php global $spbc; ?>

<?php if ($data['title_first']) { ?>
    <label for="spbc_setting_<?php echo $data['name']; ?>" class="spbc_settings-field_title spbc_settings-field_title--<?php echo $data['type']; ?>"><?php echo $data['title']; ?></label>&nbsp;
<?php } ?>

<?php

echo '<input'
     . ' type="number"'
     . ' id="spbc_setting_' . $data['name'] . '"'
     . ' name="spbc_settings[' . $data['name'] . ']" ' . ($data['parent'] && ! $spbc->settings[ $data['parent'] ] ? ' disabled="disabled"' : '')
     . ' value="' . $data['value'] . '" '
     . ' min="' . $data['min'] . '" '
     . ' max="' . $data['max'] . '" '
     . ($data['required'] ? ' required="required"' : '')
     . '>';

?>

<?php if (! $data['title_first']) { ?>
    &nbsp;<label for="spbc_setting_<?php echo $data['name']; ?>" class="spbc_setting-field_title--<?php echo $data['type']; ?>"><?php echo $data['title']; ?></label>
<?php } ?>

<?php if (isset($data['description'])) { ?>
    <div class="spbc_settings_description"><?php echo $data['description']; ?></div>
<?php } ?>
