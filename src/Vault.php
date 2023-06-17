<?php

namespace Iknowitza\Vault;

use Exception;
use RuntimeException;
use Illuminate\Support\Str;
use Illuminate\Support\Facades\Storage;


class Vault
{
    /**
     * The storage disk.
     *
     * @var string
     */
    protected string $disk;

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
     * The storage adapter.
     */
    protected $adapter;

    public function __construct()
    {
        //Retrieves the value of the vault config configuration file. 
        $this->disk = config('vault.disk');
        $this->key = config('vault.key');
        $this->cipher = config('vault.cipher');
    }

    /**
     * Set the disk where the files are located.
     *
     * @param string $disk
     * @return $this
     */
    public function disk(string $disk): static
    {
        $this->disk = $disk;

        return $this;
    }

    /**
     * Set the encryption key.
     *
     * @param string $key
     * @return $this
     */
    public function key($key): static
    {
        $this->key = $key;

        return $this;
    }

    /**
     * Create a new encryption key for the given cipher.
     *
     * @return string
     * @throws \Exception
     */
    public static function generateKey(): string
    {
        //We use the random_bytes() function to generate random bytes for the encryption key. 
        //The random_bytes() function is a built-in PHP function that generates cryptographically secure random bytes.
        //If the value of the configuration key 'vault.cipher' is 'AES-128-CBC', the condition evaluates to true, 
        //and the generated key will have a length of 16 bytes (128 bits).
        //
        //If the value of the configuration key 'vault.cipher' is anything other than 'AES-128-CBC', 
        //the condition evaluates to false, and the generated key will have a length of 32 bytes (256 bits).
        return random_bytes(config('vault.cipher') === 'AES-128-CBC' ? 16 : 32);
    }

    /**
     * Encrypt the passed file and saves the result in a new file with ".enc" as suffix.
     *
     * @param string $sourceFile Path to file that should be encrypted, relative to the storage disk specified
     * @param string|null $destinationFile File name where the encrypted file should be written to, relative to the storage disk specified
     * @param bool $deleteSource Delete the source file after encrypting
     * @return $this
     * @throws \Exception
     */
    public function encrypt(string $sourceFile, ?string $destinationFile = null, bool $deleteSource = true): static
    {
        $this->registerServices();

        if (is_null($destinationFile)) {
            $destinationFile = "{$sourceFile}.enc";
        }

        $sourcePath = $this->getFilePath($sourceFile);
        $destPath = $this->getFilePath($destinationFile);

        // Create a new encrypter instance
        $encrypter = new Encrypter($this->key, $this->cipher);

        // If encryption is successful, delete the source file
        if ($encrypter->encrypt($sourcePath, $destPath) && $deleteSource) {
            Storage::disk($this->disk)->delete($sourceFile);
        }

        return $this;
    }

    /**
     * Encrypt the passed file and saves the result in a new file with ".enc" as suffix. The source file is not deleted.
     *
     * @param string $sourceFile Path to file that should be encrypted, relative to the storage disk specified
     * @param string|null $destinationFile File name where the encrypted file should be written to, relative to the storage disk specified
     * @return $this
     * @throws \Exception
     */
    public function encryptCopy(string $sourceFile, ?string $destinationFile = null): static
    {
        return self::encrypt($sourceFile, $destinationFile, false);
    }

    /**
     * Decrypt the passed file and saves the result in a new file, removing the
     * last 4 characters from file name.
     *
     * @param string $sourceFile Path to file that should be decrypted
     * @param string|null $destinationFile File name where the decrypted file should be written to.
     * @return $this
     * @throws \Exception
     */
    public function decrypt(string $sourceFile, ?string $destinationFile = null, bool $deleteSource = true): static
    {
        $this->registerServices();

        if (is_null($destinationFile)) {
            $destinationFile = Str::endsWith($sourceFile, '.enc')
                ? Str::replaceLast('.enc', '', $sourceFile)
                : $sourceFile . '.dec';
        }

        $sourcePath = $this->getFilePath($sourceFile);
        $destPath = $this->getFilePath($destinationFile);

        // Create a new encrypter instance
        $encrypter = new Encrypter($this->key, $this->cipher);

        // If decryption is successful, delete the source file
        if ($encrypter->decrypt($sourcePath, $destPath) && $deleteSource) {
            Storage::disk($this->disk)->delete($sourceFile);
        }

        return $this;
    }

    /**
     * Decrypt the passed file and saves the result in a new file, removing the
     * last 4 characters from file name. Keep the source file
     *
     * @param string $sourceFile Path to file that should be decrypted
     * @param string|null $destinationFile File name where the decrypted file should be written to.
     * @return $this
     * @throws \Exception
     */
    public function decryptCopy(string $sourceFile, ?string $destinationFile = null): static
    {
        return self::decrypt($sourceFile, $destinationFile, false);
    }

    /**
     * @throws \Exception
     */
    public function streamDecrypt($sourceFile): bool
    {
        $this->registerServices();

        $sourcePath = $this->getFilePath($sourceFile);

        // Create a new encrypter instance
        $encrypter = new Encrypter($this->key, $this->cipher);

        return $encrypter->decrypt($sourcePath, 'php://output');
    }

    protected function getFilePath($file): string
    {
        return Storage::disk($this->disk)->path($file);
    }

   

    protected function setAdapter()
    {
        if ($this->adapter) {
            return;
        }

        $this->adapter = Storage::disk($this->disk)->getAdapter();
    }

    protected function registerServices()
    {
        $this->setAdapter();

    }
}
