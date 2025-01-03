<?php

namespace Phedrock\Authentication\Jwt\Contracts\Algorithms;

interface AlgorithmsInterface
{
    /**
     * @param string $data
     * @param string $key
     * @return string
     */
    public function sign(string $data, string $key): string;

    /**
     * @param string $data
     * @param string $signature
     * @param string $key
     * @return bool
     */
    public function verify(string $data, string $signature, string $key): bool;
}