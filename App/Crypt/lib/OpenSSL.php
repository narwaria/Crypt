<?php
/**
 * @file
 * Contains \App\Crypt\lib\OpenSSL.
 *
 * Class OpenSSL is Used to encrypt or decrypt the text based on encrypt key.
 */

namespace App\Crypt\lib;

/**
 * Class OpenSSL used to encrypt and decrypt content.
 */
class OpenSSL {

  const METHOD = 'aes-256-cbc';

  private $pbkdfBase = '';
  private $pbkdfExtra = '';
  private $pbkdfExtracount = 0;
  private $pbkdfHashno = 0;
  private $pbkdfState = 0;
  private $iterations = 100;

  /**
   * Function is used to reset the values.
   */
  public function reset() {
    $this->pbkdfBase = '';
    $this->pbkdfExtra = '';
    $this->pbkdfExtracount = 0;
    $this->pbkdfHashno = 0;
    $this->pbkdfState = 0;
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
  public function decrypt($inputText, $password) {
    $this->reset();
    $salt = (string) mb_strlen($password);
    $key = $this->pbkdf1($password, $salt, 32);
    $iv = $this->pbkdf1($password, $salt, 16);
    $decrypted = openssl_decrypt(base64_decode($inputText), self::METHOD, $key, OPENSSL_RAW_DATA, $iv);
    return mb_convert_encoding($decrypted, 'UTF-8', 'UTF-16LE');
  }

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
  public function encrypt($inputText, $password) {
    $this->reset();
    $salt = (string) mb_strlen($password);
    $key = $this->pbkdf1($password, $salt, 32);
    $iv = $this->pbkdf1($password, $salt, 16);
    $textUTF = mb_convert_encoding($inputText, 'UTF-16LE');
    $encrypted = openssl_encrypt($textUTF, self::METHOD, $key, OPENSSL_RAW_DATA, $iv);
    return base64_encode($encrypted);
  }

  /**
   * This code reference from: https://stackoverflow.com/questions/36511731/decrypting-string-encrypted-in-c-sharp-with-rijndaelmanaged-class-using-php
   */
  private function pbkdf1($pass, $salt, $countBytes) {
    if ($this->pbkdfState == 0) {
      $this->pbkdfHashno = 0;
      $this->pbkdfState = 1;

      $key = $pass . $salt;
      $this->pbkdfBase = sha1($key, TRUE);
      for ($i = 2; $i < $this->iterations; $i++) {
        $this->pbkdfBase = sha1($this->pbkdfBase, TRUE);
      }
    }

    $result = '';

    if ($this->pbkdfExtracount > 0) {
      $rlen = strlen($this->pbkdfExtra) - $this->pbkdfExtracount;
      if ($rlen >= $countBytes) {
        $result = substr($this->pbkdfExtra, $this->pbkdfExtracount, $countBytes);
        if ($rlen > $countBytes) {
          $this->pbkdfExtracount += $countBytes;
        }
        else {
          $this->pbkdfExtra = NULL;
          $this->pbkdfExtracount = 0;
        }
        return $result;
      }
      $result = substr($this->pbkdfExtra, $rlen, $rlen);
    }

    $current = '';
    $clen = 0;
    $remain = $countBytes - strlen($result);
    while ($remain > $clen) {
      if ($this->pbkdfHashno == 0) {
        $current = sha1($this->pbkdfBase, TRUE);
      }
      elseif ($this->pbkdfHashno < 1000) {
        $num = sprintf('%d', $this->pbkdfHashno);
        $tmp = $num . $this->pbkdfBase;
        $current .= sha1($tmp, TRUE);
      }
      $this->pbkdfHashno++;
      $clen = strlen($current);
    }

    // $current now holds at least as many bytes as we need.
    $result .= substr($current, 0, $remain);

    // Save any left over bytes for any future requests.
    if ($clen > $remain) {
      $this->pbkdfExtra = $current;
      $this->pbkdfExtracount = $remain;
    }

    return $result;
  }

}
