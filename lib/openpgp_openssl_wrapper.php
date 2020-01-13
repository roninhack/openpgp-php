<?php

if (function_exists('openssl_encrypt')) {
    class OpenSSLWrapper
    {
        public $cipher;
        public $key;
        public $iv;
        public $key_size;
        public $block_size;

        public function __construct($cipher)
        {
            if ($cipher != 'CAST5-CFB') {
                throw Exception('OpenSSLWrapper is only used for CAST5 right now');
            }
            $this->cipher = $cipher;
            $this->key_size = 16;
            $this->block_size = 8;
            $this->iv = str_repeat("\0", 8);
        }

        public function setKey($key)
        {
            $this->key = $key;
        }

        public function setIV($iv)
        {
            $this->iv = $iv;
        }

        public function encrypt($data)
        {
            return openssl_encrypt($data, $this->cipher, $this->key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $this->iv);
        }

        public function decrypt($data)
        {
            return openssl_decrypt($data, $this->cipher, $this->key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $this->iv);
        }
    }
}
