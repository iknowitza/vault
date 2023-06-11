<?php

namespace Iknowitza\Vault;

use Illuminate\Support\Facades\Facade;

/**
 * @see \Iknowitza\Vault\Skeleton\SkeletonClass
 */
class VaultFacade extends Facade
{
    /**
     * Get the registered name of the component.
     *
     * @return string
     */
    protected static function getFacadeAccessor()
    {
        return 'vault';
    }
}
