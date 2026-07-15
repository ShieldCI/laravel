<?php

// Fixture file with various function calls for InspectsCode trait testing

function someFunction()
{
    $value = env('APP_KEY');
    $debug = env('APP_DEBUG', 'false');
    $name = config('app.name');
    $port = config('app.port', 8080);
    $flag = config('app.flag', true);
    $result = strlen($name);
    $complex = config(getenv('APP_CONFIG_KEY'));

    // First-class callable syntax: the call's single argument is a
    // VariadicPlaceholder, not an Arg, so argument extraction must skip it.
    $callable = strtoupper(...);
}
