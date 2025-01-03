<?php

declare(strict_types = 1);

namespace Phedrock\Authentication\Jwt\Algorithms;

use OpenSSLAsymmetricKey;
use OpenSSLCertificate;
use Phedrock\Authentication\Jwt\Contracts\Algorithms\AlgorithmsInterface;
use Phedrock\Authentication\Jwt\Exceptions\{FailedRsaSignatureException,
    InvalidAlgorithmNameException,
    LibraryNotLoadedException};

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
     * @param OpenSSLAsymmetricKey|OpenSSLCertificate $key
     * @return string
     * @throws FailedRsaSignatureException
     */
    public function sign(string $data, mixed $key): string
    {
        if (!openssl_sign($data, $signature, $key, $this->getAlgorithmName())) {
            throw new FailedRsaSignatureException("Signing failed signature.");
        }
        return $signature;
    }

    /**
     * @param string $data
     * @param string $signature
     * @param OpenSSLAsymmetricKey|OpenSSLCertificate $key
     * @return bool
     */
    public function verify(string $data, string $signature, mixed $key): bool
    {
        return openssl_verify($data, $signature, $key, $this->getAlgorithmName()) === 1;
    }
}