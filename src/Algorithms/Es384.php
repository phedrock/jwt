<?php

declare(strict_types = 1);

namespace Phedrock\Authentication\Jwt\Algorithms;

use Phedrock\Authentication\Jwt\Algorithms\Base\Ecdsa;

class Es384 extends Ecdsa
{
    /**
     * @inheritDoc
     */
    protected function getAlgorithmName(): string
    {
        return 'sha384';
    }
}