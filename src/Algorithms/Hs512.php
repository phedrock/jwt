<?php

declare(strict_types = 1);

namespace Phedrock\Authentication\Jwt\Algorithms;

use Phedrock\Authentication\Jwt\Algorithms\Base\Hmac;
class Hs512 extends Hmac
{
    protected function getAlgorithmName(): string
    {
        return 'sha512';
    }
}