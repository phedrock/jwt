<?php

declare(strict_types = 1);

namespace Phedrock\Authentication\Jwt\Algorithms\Base;

use Exception;
use OpenSSLAsymmetricKey;
use OpenSSLCertificate;
use Phedrock\Authentication\Jwt\Contracts\Algorithms\AlgorithmsInterface;
use Phedrock\Authentication\Jwt\Exceptions\InvalidAlgorithmNameException;
use Phedrock\Authentication\Jwt\Exceptions\LibraryNotLoadedException;

abstract class Ecdsa implements AlgorithmsInterface
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
     * @throws Exception
     */
    public function sign(string $data, mixed $key): string
    {
        if (!openssl_sign($data, $signature, $key, $this->getAlgorithmName())) {
            throw new Exception('Failed to create signature');
        }
        return $this->convertDerToSignature($signature, openssl_get_key_size($key));
    }

    /**
     * @param string $der
     * @param int $keySize
     * @return string
     */
    private function convertDerToSignature(string $der, int $keySize): string
    {
        [$offset, $firstValue] = $this->parseDer($der, $this->parseDer($der)[0]);
        $secondValue = $this->parseDer($der, $offset)[1];

        $formatToFixedSize = fn(string $value): string =>
            str_pad(ltrim($value, "\x00"), $keySize, "\x00", STR_PAD_LEFT);

        return $formatToFixedSize($secondValue) . $formatToFixedSize($firstValue);
    }

    /**
     * @param string $der
     * @param int $startOffset
     * @return array
     */
    private function parseDer(string $der, int $startOffset = 0): array
    {
        $currentOffset = $startOffset;
        $currentOffset += 2;
        $r = substr($der, $currentOffset, ord($der[$currentOffset - 1]));
        $currentOffset += strlen($r);

        $currentOffset += 2;
        $s = substr($der, $currentOffset, ord($der[$currentOffset - 1]));

        return [$currentOffset + strlen($s), $r];
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