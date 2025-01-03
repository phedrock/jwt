<?php

namespace Phedrock\Authentication\Jwt\Algorithms;

use Phedrock\Authentication\Jwt\Contracts\Algorithms\AlgorithmsInterface;
use Phedrock\Authentication\Jwt\Exceptions\{FailedRsaSignatureException, InvalidAlgorithmNameException, LibraryNotLoadedException};

abstract class Rsa implements AlgorithmsInterface
{
    /**
     * @throws InvalidAlgorithmNameException|LibraryNotLoadedException
     */
    public function __construct()
    {
        ensure_support_algorithm($this->getAlgorithmName());
        check_library_is_loaded("openssl");
    }

    /**
     * @return string
     */
    abstract protected function getAlgorithmName(): string;

    /**
     * @param string $data
     * @param string $key
     * @return string
     * @throws FailedRsaSignatureException
     */
    public function sign(string $data, string $key): string
    {
        if (!openssl_sign($data, $signature, $key, $this->getAlgorithmName())) {
            throw new FailedRsaSignatureException("Signing failed signature.");
        }
        return $signature;
    }

    /**
     * @param string $data
     * @param string $signature
     * @param string $key
     * @return bool
     */
    public function verify(string $data, string $signature, string $key): bool
    {
        return openssl_verify($data, $signature, $key, $this->getAlgorithmName()) === 1;
    }
}