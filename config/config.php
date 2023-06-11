<?php

return [
    /*
     * The default key used for all file encryption / decryption
     * This package will look for a FILE_VAULT_KEY in your .env file
     * If no FILE_VAULT_KEY is found, then it will use your Laravel APP_KEY
     * MAKE A BACKUP OF THIS KEY. NO DECRYPTION CAN BE DONE WITHOUT IT.
     */
    'key' => env('FILE_VAULT_KEY', env('APP_KEY')),

    /*
     * The cipher used for encryption.
     * Supported options are AES-128-CBC and AES-256-CBC
     */
    'cipher' => 'AES-256-CBC',

    /*
     * The Storage disk used by default to locate your files.
     */
    'disk' => 'local',
];
