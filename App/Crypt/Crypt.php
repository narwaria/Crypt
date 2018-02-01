<?php

namespace App\Crypt;

use App\Crypt\lib\OpenSSL;

/**
 * Class OpenSSL used to encrypt and decrypt content.
 */
class Crypt {

  /**
   * Static function to encrypt the data.
   *
   * @param string $inputText
   *   String what want to encrypt.
   *
   * @param string $password
   *   Password string is used to encrypt string.
   *
   * @return string
   *   Return encrypted string.
   */
  public static function encrypt($inputText, $password) {
    return (new OpenSSL())->encrypt($inputText, $password);
  }

  /**
   * Static function to encrypt the data.
   *
   * @param string $inputText
   *   String what want to decrypt.
   *
   * @param string $password
   *   Password string is used to decrypt string.
   *
   * @return string
   *   Return decrypted string.
   */
  public static function decrypt($inputText, $password) {
    return (new OpenSSL())->decrypt($inputText, $password);
  }

}
