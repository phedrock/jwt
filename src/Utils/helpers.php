<?php

declare(strict_types = 1);

use Phedrock\Authentication\Jwt\Exceptions\InvalidAlgorithmNameException;
use Phedrock\Authentication\Jwt\Exceptions\LibraryNotLoadedException;
use Phedrock\Authentication\Jwt\Exceptions\OpenSSLKeyLoadException;

if (!function_exists('ensure_support_algorithm')) {
    /**
     * Ensures that the algorithm used exists in the list available for the language
     *
     * @param $algorithm
     * @return void
     * @throws InvalidAlgorithmNameException
     */
    function ensure_support_algorithm($algorithm): void
    {
        if (!in_array($algorithm, hash_algos(), true)) {
            throw new InvalidAlgorithmNameException(
                sprintf('Encryption algorithm "%s" is not supported on this system.', $algorithm)
            );
        }
    }
}

if (!function_exists('check_library_is_loaded')) {
    /**
     * Validates that the extension is loaded
     *
     * @param string $library
     * @return void
     * @throws LibraryNotLoadedException
     */
    function check_library_is_loaded(string $library): void
    {
        if (!extension_loaded($library)) {
            throw new LibraryNotLoadedException(
                sprintf('Unable to execute algorithm, library "%s" is not loaded.', $library)
            );
        }
    }
}

if (!function_exists('openssl_load_key')) {
    /**
     * @param string $filename
     * @return OpenSSLAsymmetricKey
     * @throws OpenSSLKeyLoadException
     */
    function openssl_load_key(string $filename): OpenSSLAsymmetricKey
    {
        $privateKey = openssl_pkey_get_private($filename) ?: openssl_pkey_get_public($filename);
        if (!$privateKey) {
            throw new OpenSSLKeyLoadException(
                sprintf('Unable to load private key: %s.', openssl_error_string())
            );
        }
        return $privateKey;
    }
}

if (!function_exists('openssl_get_key_size')) {
    function openssl_get_key_size(OpenSSLAsymmetricKey|OpenSSLCertificate $key): int
    {
        return openssl_pkey_get_details($key)['bits'] / 8;
    }
}