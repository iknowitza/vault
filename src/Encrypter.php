<?php

namespace Iknowitza\Vault;

use Exception;
use Illuminate\Support\Str;
use RuntimeException;


class Encrypter
{
    /**
     * Define the number of blocks that should be read from the source file for each chunk.
     * We chose 255 because on decryption we want to read chunks of 4kb ((255 + 1)*16).
     */
    protected const FILE_ENCRYPTION_BLOCKS = 255;

    /**
     * The encryption key.
     *
     * @var string
     */
    protected string $key;

    /**
     * The algorithm used for encryption.
     *
     * @var string
     */
    protected string $cipher;

    /**
     * Create a new encrypter instance.
     *
     * @param string $key
     * @param string $cipher
     * @return void
     *
     * @throws \RuntimeException
     */
    public function __construct(string $key, string $cipher = 'AES-128-CBC')
    {
        //check if key is base64: and decode it before we continue
        //base64_decode converts the base64-encoded key back to its raw byte form.
        if (Str::startsWith($key, 'base64:')) {
            $key = base64_decode(substr($key, 7));
        }

        //checks if the key and cipher combination is supported.
        if (static::supported($key, $cipher)) {
            $this->key = $key;
            $this->cipher = $cipher;
        } else {
            throw new RuntimeException('The only supported ciphers are AES-128-CBC and AES-256-CBC with the correct key lengths.');
        }
    }

    /**
     * Determine if the given key and cipher combination is valid.
     *
     * @param string $key
     * @param string $cipher
     * @return bool
     */
    public static function supported($key, $cipher): bool
    {
        //calculate the length of the key in bytes, not characters.
        $length = mb_strlen($key, '8bit');

        //then checks the cipher AND key length to be true and returns true.
        return ($cipher === 'AES-128-CBC' && $length === 16) ||
            ($cipher === 'AES-256-CBC' && $length === 32);
    }

    /**
     * Encrypts the source file and saves the result in a new file.
     *
     * @param string $sourcePath Path to file that should be encrypted
     * @param string $destinationPath File name where the encryped file should be written to.
     * @return bool
     * @throws Exception
     */
    public function encrypt(string $sourcePath, string $destinationPath): bool
    {
        //set the input and output files - named accordingly
        $fpOut = $this->openDestinationFile($destinationPath);
        $fpIn = $this->openSourceFile($sourcePath);

        // Put the initialization vector to the beginning of the file
        //It generates a random initialization vector (IV) using openssl_random_pseudo_bytes(16)
        //and writes it to the beginning of the destination file using fwrite(). 
        //The IV is used to initialize the encryption algorithm.
        $iv = openssl_random_pseudo_bytes(16);
        fwrite($fpOut, $iv);

        //here we calculate the number of chunks needed to process the file
        //by dividing the source file size by the chunk size (16 bytes times the constant FILE_ENCRYPTION_BLOCKS).
        $numberOfChunks = ceil(filesize($sourcePath) / (16 * self::FILE_ENCRYPTION_BLOCKS));

        $i = 0;
        //We enters a loop that reads chunks of data from the source file 
        //until the end of the file is reached (feof($fpIn) is false).
        while (! feof($fpIn)) {
            //We read a chunk of plaintext data from the source file using fread()
            //with the size of 16 bytes times the constant FILE_ENCRYPTION_BLOCKS.
            $plaintext = fread($fpIn, 16 * self::FILE_ENCRYPTION_BLOCKS);
            //we encrypt the plaintext using openssl_encrypt() with the specified cipher, key, IV, 
            //and the OPENSSL_RAW_DATA flag, which ensures the ciphertext is returned as raw binary data.
            $ciphertext = openssl_encrypt($plaintext, $this->cipher, $this->key, OPENSSL_RAW_DATA, $iv);

           
            //We check if the size of the plaintext read from the file is different from the requested 
            //chunk size (16 bytes times FILE_ENCRYPTION_BLOCKS) and if it's not the last chunk ($i + 1 < $numberOfChunks). 
            //If so, it seeks back to the beginning of the current chunk and continues to the next iteration of the loop. 
            //This scenario occurs if the file size is not a multiple of the chunk size and there is leftover data that needs to be reprocessed.
            if (strlen($plaintext) !== 16 * self::FILE_ENCRYPTION_BLOCKS
                && $i + 1 < $numberOfChunks
            ) {
                fseek($fpIn, 16 * self::FILE_ENCRYPTION_BLOCKS * $i);

                continue;
            }

            //If the conditions are not met, it takes the first 16 bytes of the ciphertext as the new IV
            //writes the ciphertext to the destination file using fwrite(), and increments the loop counter $i.
            $iv = substr($ciphertext, 0, 16);
            fwrite($fpOut, $ciphertext);

            $i++;
        }
        
        //After the loop finishes, it closes the source and destination files using fclose().
        fclose($fpIn);
        fclose($fpOut);

        //Finally, it returns true to indicate that the encryption process was successful.
        return true;
    }

    /**
     * Decrypts the source file and saves the result in a new file.
     *
     * @param string $sourcePath Path to file that should be decrypted
     * @param string $destinationPath File name where the decryped file should be written to.
     * @return bool
     * @throws Exception
     */
    public function decrypt(string $sourcePath, string $destinationPath): bool
    {
        $fpOut = $this->openDestinationFile($destinationPath);
        $fpIn = $this->openSourceFile($sourcePath);

        //It reads the initialization vector (IV) from the beginning of the source file using fread().
        //The IV was previously written as the first 16 bytes of the encrypted file.
        $iv = fread($fpIn, 16);

        //The method calculates the number of chunks needed to process the file by dividing the
        //source file size minus 16 bytes (to exclude the IV) by the chunk size (16 bytes times(self::FILE_ENCRYPTION_BLOCKS + 1)).
        $numberOfChunks = ceil((filesize($sourcePath) - 16) / (16 * (self::FILE_ENCRYPTION_BLOCKS + 1)));

        $i = 0;
        //It enters a loop that reads chunks of ciphertext data from the source file 
        //until the end of the file is reached (feof($fpIn) is false).
        while (! feof($fpIn)) {
            //Inside the loop, it reads a chunk of ciphertext data from the source file using fread(), 
            //with the size of 16 bytes times (self::FILE_ENCRYPTION_BLOCKS + 1). 
            //This is because one additional block is read for decryption due to the inclusion of the IV.
            $ciphertext = fread($fpIn, 16 * (self::FILE_ENCRYPTION_BLOCKS + 1));

            //It decrypts the ciphertext using openssl_decrypt() with the specified cipher, key, IV,
            //and the OPENSSL_RAW_DATA flag, which assumes the ciphertext is provided as raw binary data.
            $plaintext = openssl_decrypt($ciphertext, $this->cipher, $this->key, OPENSSL_RAW_DATA, $iv);

            //It checks if the size of the ciphertext read from the file is different from the requested
            //chunk size (16 bytes times (self::FILE_ENCRYPTION_BLOCKS + 1)) and 
            //if it's not the last chunk ($i + 1 < $numberOfChunks). 
            //If so, it seeks back to the beginning of the current chunk and continues to the next iteration of the loop. 
            //This scenario occurs if the file size is not a multiple of the chunk size and there is leftover data that needs to be reprocessed.
            if (strlen($ciphertext) !== 16 * (self::FILE_ENCRYPTION_BLOCKS + 1)
                && $i + 1 < $numberOfChunks
            ) {
                fseek($fpIn, 16 + 16 * (self::FILE_ENCRYPTION_BLOCKS + 1) * $i);

                continue;
            }

            //If decryption fails ($plaintext === false), it throws an exception with the message "Decryption failed".
            if ($plaintext === false) {
                throw new Exception('Decryption failed');
            }

            //If decryption is successful, it takes the first 16 bytes of the ciphertext as the new IV,
            //writes the decrypted plaintext to the destination file using fwrite(), and increments the loop counter $i.
            // Get the first 16 bytes of the ciphertext as the next initialization vector
            $iv = substr($ciphertext, 0, 16);
            fwrite($fpOut, $plaintext);

            $i++;
        }

        //After the loop finishes, it closes the source and destination files using fclose().
        fclose($fpIn);
        fclose($fpOut);
        
        //Finally, it returns true to indicate that the decryption process was successful.
        return true;
    }

    /**
     * @throws Exception
     */
    protected function openDestinationFile($destinationPath)
    {
        //It attempts to open the destination file for writing using fopen() with the mode 'w'. 
        //The mode 'w' opens the file for writing and truncates the file to zero length if it already exists. 
        //If the file does not exist, it creates a new empty file.
        if (($fpOut = fopen($destinationPath, 'w')) === false) {
            //If the fopen() function returns false, indicating that the file opening failed, 
            //it throws an exception with the message "Cannot open file for writing".
            throw new Exception('Cannot open file for writing');
        }
        //If the file is successfully opened, it assigns the file pointer to the 
        //variable $fpOut and returns it.
        return $fpOut;
    }

    /**
     * @throws Exception
     */
    protected function openSourceFile($sourcePath)
    {
        //It attempts to open the specified file for reading using the fopen() function. 
        //The fopen() function takes three arguments: the file path ($sourcePath), 
        //the mode in which the file should be opened ('r' indicating read mode), 
        //and a boolean parameter that determines whether to use the include path for 
        //searching the file (set to false).
        if (($fpIn = fopen($sourcePath, 'r', false)) === false) {
            //The result of the fopen() function call is assigned to the variable $fpIn. 
            //If the file cannot be opened (i.e., fopen() returns false), an exception is thrown.
            throw new Exception('Cannot open file for reading');
        }
        //If the file is successfully opened, the function returns the file pointer $fpIn. 
        return $fpIn;
    }
}
