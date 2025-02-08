# paper-scorer/decrypter-php

PaperScorer Decrypter

This PHP package is used to decrypt the response returned from the PaperScorer engine.

- Package version: 1.0.0

## Requirements

PHP 7.4.0 and later

## Installation & Usage
### Composer

This package can be easily installed using the following composer command:

`composer require paper-scorer/decrypter-php`

### Usage

Include and run the following code in your project:

```php
// This is the main include for the project.
use PaperScorer/DecrypterPhp/Decrypter;

// Creating a new decrypter object and setting the key.
// NOTE: The key is provided by PaperScorer.
$decrypter = new Decrypter($decryptKey);

// Setting the encrypted content sent from the PaperScorer engine.
$decrypter->setEncryptedContent($encryptedContent);

// Running the decrypter and getting the decrypted response.
// NOTE: The decrypted response will be a JSON string.
$decryptedResponse = $decrypter->decrypt();
```

## Contributing

We are always looking for updates to the package that will help the community. If you have an idea for an update, please create a pull request with your changes.

## Publishing

1. Update the CHANGELOG file
1. `git tag -a vX.X.X`
1. `git push --tags origin HEAD:master`
1. Log into [Packagist](https://packagist.org/packages/paper-scorer/decrypter-php) and click "Update"
