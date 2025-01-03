<?php

declare(strict_types = 1);

namespace Phedrock\Authentication\Jwt\Algorithms;

use Phedrock\Authentication\Jwt\Algorithms\Base\Ecdsa;

class Es256K extends Ecdsa
{
    protected function getAlgorithmName(): string
    {
        return 'sha256';
    }
}