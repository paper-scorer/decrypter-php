<?php

declare(strict_types=1);

/**
 * PaperScorer Decrypter - PHP Version
 *
 * @package PaperScorer
 * @author  PaperScorer Team
 */

namespace PaperScorer\DecrypterPhp;

use InvalidArgumentException;
use RuntimeException;

/**
 * Decrypts encrypted payloads returned from the PaperScorer engine.
 *
 * The encrypted content is a base64-encoded string composed of three
 * concatenated segments:
 *   - Bytes  0–24:  IV (base64-encoded, decodes to 16 bytes)
 *   - Bytes 24–52:  Salt (base64-encoded)
 *   - Bytes 52+:    Ciphertext (base64-encoded)
 *
 * Key derivation: SHA-256(decryptKey + decodedSalt), truncated to 16 bytes.
 * Cipher: AES-128-CBC with OPENSSL_RAW_DATA.
 *
 * @package PaperScorer
 * @author  PaperScorer Team
 */
class Decrypter
{
    /** @var string The decryption key provided by PaperScorer */
    protected string $decryptKey;

    /** @var string|null The encrypted payload to decrypt */
    protected ?string $encryptedContent = null;

    /**
     * @param string $decryptKey The decryption key provided by PaperScorer
     *
     * @throws InvalidArgumentException If the decryption key is empty
     */
    public function __construct(string $decryptKey)
    {
        if ($decryptKey === '') {
            throw new InvalidArgumentException(
                'Missing the required parameter $decryptKey when creating a new Decrypter object.'
            );
        }

        $this->setDecryptKey($decryptKey);
    }

    /**
     * Decrypt and return the encrypted content as a string.
     *
     * @return string The decrypted content (typically JSON)
     *
     * @throws RuntimeException If encrypted content has not been set
     * @throws RuntimeException If decryption fails
     */
    public function decrypt(): string
    {
        if ($this->encryptedContent === null) {
            throw new RuntimeException(
                'Encrypted content must be set before calling decrypt().'
            );
        }

        // Extract the three base64-encoded segments from the payload
        $ivBase64 = substr($this->encryptedContent, 0, 24);
        $saltBase64 = substr($this->encryptedContent, 24, 28);
        $cipherTextBase64 = substr($this->encryptedContent, 52);

        // Derive a 16-byte AES key from the decrypt key and the decoded salt
        $secretKey = substr(
            hash('sha256', $this->decryptKey . base64_decode($saltBase64), true),
            0,
            16
        );

        $decryptedContent = openssl_decrypt(
            base64_decode($cipherTextBase64),
            'AES-128-CBC',
            $secretKey,
            OPENSSL_RAW_DATA,
            base64_decode($ivBase64)
        );

        if ($decryptedContent === false) {
            throw new RuntimeException(
                'Decryption failed. Verify that the decrypt key and encrypted content are correct.'
            );
        }

        return $decryptedContent;
    }

    /**
     * Set the decryption key.
     *
     * @param string $decryptKey The decryption key provided by PaperScorer
     *
     * @return void
     */
    public function setDecryptKey(string $decryptKey): void
    {
        $this->decryptKey = $decryptKey;
    }

    /**
     * Set the encrypted content to decrypt.
     *
     * @param string $encryptedContent The encrypted payload from PaperScorer
     *
     * @return void
     */
    public function setEncryptedContent(string $encryptedContent): void
    {
        $this->encryptedContent = $encryptedContent;
    }
}
