<?php

declare(strict_types=1);

// php e2e/compare.php <issued.json> <judged.json> <label>
//
// Holds what an implementation made of the tokens (bin/judge.php and its counterparts) against
// what the tokens should give: the verdict a vector names, or the fields of a seal case. Prints
// the differences and exits non-zero if there are any.

[, $issuedFile, $judgedFile, $label] = $argv + [null, null, null, ''];

$issued = json_decode((string) file_get_contents($issuedFile), true, 512, JSON_THROW_ON_ERROR);
$judged = json_decode((string) file_get_contents($judgedFile), true, 512, JSON_THROW_ON_ERROR);

/** Sorts object keys so that equal JSON compares equal; PHP cannot tell {} from [], so neither can this. */
function canonical(mixed $value): string
{
    $sort = function (mixed $v) use (&$sort) {
        if (is_array($v)) {
            ksort($v);

            return array_map($sort, $v);
        }
        if ($v instanceof stdClass) {
            return $sort(get_object_vars($v));
        }

        return $v;
    };

    return json_encode($sort($value), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRESERVE_ZERO_FRACTION);
}

$problems = [];
$check = function (string $name, array $got, string $verdict, ?array $fields) use (&$problems): void {
    if ($got['verdict'] !== $verdict) {
        $problems[] = "$name: verdict {$got['verdict']}, expected $verdict";

        return;
    }
    if ($fields === null) {
        return;
    }
    foreach (['iat', 'nbf', 'exp'] as $field) {
        if (($got[$field] ?? null) !== $fields[$field]) {
            $problems[] = "$name: $field ".var_export($got[$field] ?? null, true).', expected '.var_export($fields[$field], true);
        }
    }
    if (canonical($got['data'] ?? null) !== canonical($fields['data'])) {
        $problems[] = "$name: data differs";
    }
};

if (count($judged['verdicts']) !== count($issued['verdicts']) || count($judged['sealed']) !== count($issued['sealed'])) {
    fwrite(STDERR, "FAIL $label: judged ".count($judged['verdicts']).'+'.count($judged['sealed']).' tokens, issued '.count($issued['verdicts']).'+'.count($issued['sealed'])."\n");
    exit(1);
}

foreach ($issued['verdicts'] as $i => $v) {
    $fields = $v['expect'] === 'ok'
        ? ['iat' => $v['iat'], 'nbf' => $v['nbf'] ?? null, 'exp' => $v['exp'] ?? null, 'data' => $v['data']]
        : null;
    $check("{$v['cipher']}/{$v['name']}", $judged['verdicts'][$i], $v['expect'], $fields);
}
foreach ($issued['sealed'] as $i => $s) {
    $case = $s['case'];
    $exp = match (true) {
        isset($case['expiry']['in']) => $case['now'] + $case['expiry']['in'],
        isset($case['expiry']['at']) => $case['expiry']['at'],
        default => null,
    };
    $check("{$s['cipher']}/sealed:{$s['name']}", $judged['sealed'][$i], 'ok',
        ['iat' => $case['now'], 'nbf' => $case['not_before'] ?? null, 'exp' => $exp, 'data' => $case['data']]);
}

$total = count($issued['verdicts']) + count($issued['sealed']);
if ($problems) {
    fwrite(STDERR, "FAIL $label: ".count($problems)."/$total\n  ".implode("\n  ", array_slice($problems, 0, 10))."\n");
    exit(1);
}
echo "ok   $label ($total tokens)\n";
