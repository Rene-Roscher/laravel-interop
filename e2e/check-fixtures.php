<?php

declare(strict_types=1);

// php e2e/check-fixtures.php <other envelope-vectors.json>...
//
// The Rust, Go and Node.js packages keep a copy of fixtures/envelope-vectors.json. This fails if
// one of them has drifted from the original: same cases, keys and verdicts (the tokens themselves
// are random).

$strip = function (string $file): string {
    $json = json_decode((string) file_get_contents($file), true, 512, JSON_THROW_ON_ERROR);
    foreach ($json['vectors'] as &$vector) {
        unset($vector['token']);
    }
    unset($json['laravel']);

    return json_encode($json);
};

$original = $strip(__DIR__.'/../fixtures/envelope-vectors.json');
$failed = false;
foreach (array_slice($argv, 1) as $file) {
    $same = $strip($file) === $original;
    echo ($same ? 'ok   ' : 'FAIL ')."$file\n";
    $failed = $failed || ! $same;
}
exit($failed ? 1 : 0);
