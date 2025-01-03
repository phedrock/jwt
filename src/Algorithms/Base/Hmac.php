<?php

declare(strict_types = 1);

namespace Phedrock\Authentication\Jwt\Algorithms\Base;

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

    /**
     * @param string $data
     * @param string $signature
     * @param string $key
     * @return bool
     */

    public function verify(string $data, string $signature, mixed $key): bool
    {
        return hash_equals($this->sign($data, $key), $signature);
    }

    /**
     * @param string $data
     * @param string $key
     * @return string
     */

    public function sign(string $data, mixed $key): string
    {
        return hash_hmac($this->getAlgorithmName(), $data, $key, true);
    }
}