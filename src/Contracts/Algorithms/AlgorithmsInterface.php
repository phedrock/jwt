<?php

declare(strict_types = 1);

namespace Phedrock\Authentication\Jwt\Contracts\Algorithms;

interface AlgorithmsInterface
{
    /**
     * @param string $data
     * @param mixed $key
     * @return string
     */
    public function sign(string $data, mixed $key): string;

    /**
     * @param string $data
     * @param string $signature
     * @param mixed $key
     * @return bool
     */
    public function verify(string $data, string $signature, mixed $key): bool;
}