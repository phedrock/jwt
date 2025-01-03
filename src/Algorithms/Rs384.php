<?php

declare(strict_types = 1);

namespace Phedrock\Authentication\Jwt\Algorithms;

use Phedrock\Authentication\Jwt\Algorithms\Base\Hmac;

class Rs384 extends Hmac
{
    protected function getAlgorithmName(): string
    {
        return 'sha384';
    }
}