<?php

declare(strict_types = 1);

namespace Phedrock\Authentication\Jwt\Algorithms;

use Phedrock\Authentication\Jwt\Algorithms\Base\Hmac;

class Hs256 extends Hmac
{
    protected function getAlgorithmName(): string
    {
        return 'sha256';
    }
}