<?php

declare(strict_types = 1);

namespace Phedrock\Authentication\Jwt\Algorithms;

use Phedrock\Authentication\Jwt\Contracts\Algorithms\AlgorithmsInterface;
use Phedrock\Authentication\Jwt\Exceptions\LibraryNotLoadedException;
use SodiumException;

class EdDsa implements AlgorithmsInterface
{

    /**
     * @throws LibraryNotLoadedException
     */
    public function __construct()
    {
        check_library_is_loaded("sodium");
    }

    /**
     * @param string $data
     * @param string $key
     * @return string
     * @throws SodiumException
     */
    public function sign(string $data, mixed $key): string
    {
        return sodium_crypto_sign_detached($data, $key);
    }

    /**
     * @param string $data
     * @param string $signature
     * @param mixed $key
     * @return bool
     * @throws SodiumException
     */
    public function verify(string $data, string $signature, mixed $key): bool
    {
        return sodium_crypto_sign_verify_detached($signature, $data, $key);
    }
}