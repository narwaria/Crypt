<?php

namespace App\Tests\Unit;

use App\Crypt\Crypt;

/**
 * Class OpenSSLTest is used to test class Crypt.php.
 *
 * Class extends to PHPUnit_framework_TestCase.
 * Class use PSR-4 autoload for test the unitTest.
 */
class OpenSSLTest extends \PHPUnit_Framework_TestCase {

  /**
   * Variable hold the credit card number.
   *
   * @var string
   */
  private $masterCardNumber = '5555555555554444';

  /**
   * Variable hold the Encription key.
   *
   * @var string
   */
  private $originEncriptKEY = "1111222233334444";

  /**
   * Variable hold the Wrong Encription key.
   *
   * @var string
   */
  private $wrongEncriptKEY = "134344234567890123";

  /**
   * Test check the encrypt key is valid or not.
   *
   * @group OpenSSL
   */
  public function testEncriptKeyValid() {
    $charLenght = strlen($this->originEncriptKEY);
    $this->assertGreaterThanOrEqual(16, $charLenght);
    $this->assertLessThanOrEqual(32, $charLenght);
  }

  /**
   * Test check the value is not equal after Encrypt.
   *
   * @group OpenSSL
   */
  public function testEncryptValueIsDifferent() {
    $encryptMasterCardNumber = Crypt::encrypt($this->masterCardNumber, $this->originEncriptKEY);
    $this->assertNotEquals($encryptMasterCardNumber, $this->masterCardNumber);
  }

  /**
   * Test check the value is not equal after Encrypt.
   *
   * @group OpenSSL
   */
  public function testIsDecryptWork() {
    $encryptMasterCardNumber = Crypt::encrypt($this->masterCardNumber, $this->originEncriptKEY);
    $decryptMasterCardNumber = Crypt::decrypt($encryptMasterCardNumber, $this->originEncriptKEY);
    $this->assertEquals($decryptMasterCardNumber, $this->masterCardNumber);
  }

  /**
   * Test check with decrypt with wrong descryption key.
   *
   * @group OpenSSL
   */
  public function testWrongEncriptKey() {
    $encryptMasterCardNumber = Crypt::encrypt($this->masterCardNumber, $this->originEncriptKEY);
    $decryptMasterCardNumber = Crypt::decrypt($encryptMasterCardNumber, $this->wrongEncriptKEY);
    $this->assertNotEquals($decryptMasterCardNumber, $this->masterCardNumber);
  }

}
