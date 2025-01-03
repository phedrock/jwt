<?php

namespace Phedrock\Authentication\Jwt\Algorithms;

use Phedrock\Authentication\Jwt\Contracts\Algorithms\AlgorithmsInterface;
use Phedrock\Authentication\Jwt\Exceptions\InvalidAlgorithmNameException;

abstract class Hmac implements AlgorithmsInterface
{
    /**
     * @throws InvalidAlgorithmNameException
     */
    public function __construct()
    {
        ensure_support_algorithm($this->getAlgorithmName());
    }

    abstract protected function getAlgorithmName(): string;

    public function verify(string $data, string $signature, string $key): bool
    {
        return hash_equals($this->sign($data, $key), $signature);
    }

    public function sign(string $data, string $key): string
    {
        return hash_hmac($this->getAlgorithmName(), $data, $key, true);
    }
}