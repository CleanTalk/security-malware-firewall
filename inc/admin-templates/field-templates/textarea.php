<?php global $spbc; ?>

<?php if ($data['title_first']) { ?>
    <label for="spbc_setting_<?php echo $data['name']; ?>" class="spbc_settings-field_title spbc_settings-field_title--<?php echo $data['type']; ?>"><?php echo $data['title']; ?></label>
    <?php if (isset($data['long_description'])) { ?>
        <i setting="<?php echo $data['name']; ?>" class="spbc_long_description__show spbc-icon-help-circled"></i>
    <?php } ?>
    <br>

<?php } ?>

<?php

echo '<textarea'
     . ' id="spbc_setting_' . $data['name'] . '"'
     . ' name="spbc_settings[' . $data['name'] . ']" '
     . ($data['required'] ? ' required="required"' : '')
     . ($data['parent'] && ! $spbc->settings[ $data['parent'] ] ? ' disabled="disabled"' : '')
     . ' class="spbc_setting__textarea"'
     . ' >'
     . ($data['value'] ?: '')
     . '</textarea>';
?>

<?php if (! $data['title_first']) { ?>
    &nbsp;<label for="spbc_setting_<?php echo $data['name']; ?>" class="spbc_setting-field_title--<?php echo $data['type']; ?>"><?php echo $data['title']; ?></label>
<?php } ?>

<?php if (isset($data['description'])) { ?>
    <div class="spbc_settings_description"><?php echo $data['description']; ?></div>
<?php } ?>
