<?php

namespace CleantalkSP\SpbctWP\Scanner\UnsafePermissionsModule;

class UnsafePermissionsHandler
{
    public function handle()
    {
        global $spbc;

        $unsafe_permissions = new UnsafePermissionFunctions($spbc);
        $unsafe_permissions->handle();
    }
}
