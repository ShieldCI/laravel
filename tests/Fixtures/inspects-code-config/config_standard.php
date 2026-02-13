<?php

return [
    'name' => 'MyApp',
    'debug' => false,
    'port' => 8080,
    'rate' => 1.5,
    'key' => env('APP_KEY'),
    'debug_env' => env('APP_DEBUG', false),
    'url' => env('APP_URL', 'http://localhost'),
    'nullable' => null,
    'complex' => strtoupper('hello'),
];
