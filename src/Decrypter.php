<?php
/**
 * PaperScorer Decrypter - PHP Version
 *
 * @category Class
 * @package  PaperScorer
 * @author   PaperScorer Team
 */

namespace PaperScorer\DecrypterPhp;

/**
 * Decrypter Class Doc Comment
 *
 * @category Class
 * @package  PaperScorer
 * @author   PaperScorer Team
 */
class Decrypter {
    /**
     * @var DecryptionKey
     */
    protected $decryptKey = null;

    /**
     * @var EncryptedContent
     */
    protected $encryptedContent = null;

    /**
     * @param DecryptionKey $decryptKey
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(string $decryptKey = null)
    {
        if (!$decryptKey) {
            throw new \InvalidArgumentException(
                'Missing the required parameter $decryptKey when creating a new Decrypter object.'
            );
        }

        $this->setDecryptKey($decryptKey);
    }

    /**
     * Decrypting and returning the set encrypted content.
     *
     * @return string
     */
    public function decrypt(): string
    {
        // Setting the iv value.
        $ivParamsAsBase64 = substr($this->encryptedContent, 0, 24);
        // Setting the salt value.
        $saltAsBase64 = substr($this->encryptedContent, 24, 28);
        // Getting the cipher text.
        $cipherText = substr($this->encryptedContent, 52);

        // Setting the working key value.
        $key = $this->decryptKey . base64_decode($saltAsBase64);
        // Setting the encrypted key value.
        $secretKey = hash('sha256', $key, true);
        $secretKey = substr($secretKey, 0, 16);

        // Creating the decrypted content.
        $decryptedContent = openssl_decrypt(
            base64_decode($cipherText),
            'AES-128-CBC',
            $secretKey,
            OPENSSL_RAW_DATA,
            base64_decode($ivParamsAsBase64)
        );

        return $decryptedContent;
    }

    /**
     * Setting the decryption key
     *
     * @param  string $decryptKey (required)
     */
    public function setDecryptKey(string $decryptKey)
    {
        $this->decryptKey = $decryptKey;
    }

    /**
     * Setting the encrypted content
     *
     * @param  string $encryptedContent (required)
     */
    public function setEncryptedContent(string $encryptedContent)
    {
        $this->encryptedContent = $encryptedContent;
    }
}