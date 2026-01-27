<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\BestPractices;

use Illuminate\Config\Repository;
use ShieldCI\Analyzers\BestPractices\LogicInBladeAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class LogicInBladeAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        $config = new Repository([
            'shieldci' => [
                'analyzers' => [
                    'best-practices' => [
                        'logic-in-blade' => [
                            'max_php_block_lines' => 10,
                        ],
                    ],
                ],
            ],
        ]);

        return new LogicInBladeAnalyzer($config);
    }

    public function test_passes_with_simple_blade_syntax(): void
    {
        $blade = <<<'BLADE'
<div>
    <h1>{{ $title }}</h1>
    @if($isActive)
        <p>Welcome, {{ $username }}</p>
    @endif
    @foreach($posts as $post)
        <article>{{ $post }}</article>
    @endforeach
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/welcome.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_simple_single_calculation(): void
    {
        $blade = <<<'BLADE'
<div>
    <p>Total: {{ $price * $quantity }}</p>
    <p>Price: {{ $total + $tax }}</p>
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/simple.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_detects_complex_calculations_in_blade(): void
    {
        $blade = <<<'BLADE'
<div>
    <p>Total: {{ ($price * $quantity) + ($tax * $rate) - $discount }}</p>
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/invoice.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('calculation', $result);
    }

    public function test_detects_assignment_calculations(): void
    {
        $blade = <<<'BLADE'
<div>
    @php
        $total = 0;
        $total += $item->price;
    @endphp
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/calc.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('calculation', $result);
    }

    public function test_detects_database_queries_with_db_facade(): void
    {
        $blade = <<<'BLADE'
<div>
    @php
        $users = DB::table('users')->where('active', true)->get();
    @endphp
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/users.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Database query', $result);
    }

    public function test_detects_eloquent_where_query(): void
    {
        $blade = <<<'BLADE'
<div>
    @php
        $users = \App\Models\User::where('active', true)->get();
    @endphp
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/users.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
    }

    public function test_detects_eloquent_find_method(): void
    {
        $blade = <<<'BLADE'
<div>
    {{ $user = User::find(1) }}
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/user.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
    }

    public function test_detects_eloquent_all_method(): void
    {
        $blade = <<<'BLADE'
<div>
    @foreach(User::all() as $user)
        <p>{{ $user->name }}</p>
    @endforeach
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/users.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
    }

    public function test_detects_eloquent_create_method(): void
    {
        $blade = <<<'BLADE'
<div>
    @php
        $user = User::create(['name' => 'John']);
    @endphp
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/user.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
    }

    public function test_detects_model_save_method(): void
    {
        $blade = <<<'BLADE'
<div>
    @php
        $user->name = 'John';
        $user->save();
    @endphp
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/user.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
    }

    public function test_does_not_flag_file_upload_save(): void
    {
        $blade = <<<'BLADE'
<div>
    @php
        $file->save('/path/to/file');
    @endphp
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/upload.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_detects_relationship_queries(): void
    {
        $blade = <<<'BLADE'
<div>
    @php
        $posts = $user->posts()->get();
    @endphp
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/posts.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
    }

    public function test_does_not_flag_config_get(): void
    {
        $blade = <<<'BLADE'
<div>
    <p>{{ config()->get('app.name') }}</p>
    <p>{{ session()->get('user_id') }}</p>
    <p>{{ cache()->get('key') }}</p>
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/config.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_does_not_flag_config_facade_get(): void
    {
        $blade = <<<'BLADE'
<div>
    <p>{{ Config::get('app.name') }}</p>
    <p>{{ Session::get('user_id') }}</p>
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/config.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_detects_php_block_exceeding_threshold(): void
    {
        $blade = <<<'BLADE'
<div>
    @php
        $line1 = 1;
        $line2 = 2;
        $line3 = 3;
        $line4 = 4;
        $line5 = 5;
        $line6 = 6;
        $line7 = 7;
        $line8 = 8;
        $line9 = 9;
        $line10 = 10;
        $line11 = 11;
    @endphp
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/long.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('11 lines', $result);
    }

    public function test_php_block_exactly_at_threshold_passes(): void
    {
        $blade = <<<'BLADE'
<div>
    @php
        $line1 = 1;
        $line2 = 2;
        $line3 = 3;
        $line4 = 4;
        $line5 = 5;
        $line6 = 6;
        $line7 = 7;
        $line8 = 8;
        $line9 = 9;
        $line10 = 10;
    @endphp
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/exact.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_detects_unclosed_php_block(): void
    {
        $blade = <<<'BLADE'
<div>
    @php
        $var = 1;
        $var2 = 2;
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/unclosed.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Unclosed', $result);
    }

    public function test_detects_inline_php(): void
    {
        $blade = <<<'BLADE'
<div>
    <?php echo $var; ?>
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/inline.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Inline PHP', $result);
    }

    public function test_detects_array_filter_in_directive(): void
    {
        $blade = <<<'BLADE'
<div>
    @foreach(array_filter($items) as $item)
        <p>{{ $item }}</p>
    @endforeach
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/filter.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Business logic', $result);
    }

    public function test_detects_collection_filter_in_foreach(): void
    {
        $blade = <<<'BLADE'
<div>
    @foreach($items->filter(fn($i) => $i->active) as $item)
        <p>{{ $item }}</p>
    @endforeach
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/filter.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
    }

    public function test_detects_collection_map_in_foreach(): void
    {
        $blade = <<<'BLADE'
<div>
    @foreach($items->map(fn($i) => $i->name) as $name)
        <p>{{ $name }}</p>
    @endforeach
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/map.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
    }

    public function test_detects_overly_complex_if_conditions(): void
    {
        $blade = <<<'BLADE'
<div>
    @if($user && $user->isAdmin() && $user->isActive() && $user->hasPermission('delete'))
        <p>Allowed</p>
    @endif
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/complex.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
    }

    public function test_allows_reasonable_if_conditions(): void
    {
        $blade = <<<'BLADE'
<div>
    @if($user && $user->isAdmin() && $user->isActive())
        <p>Allowed</p>
    @endif
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/reasonable.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_detects_api_call_with_http_facade(): void
    {
        $blade = <<<'BLADE'
<div>
    @php
        $response = Http::get('https://api.example.com/data');
    @endphp
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/api.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('API call', $result);
    }

    public function test_detects_curl_usage(): void
    {
        $blade = <<<'BLADE'
<div>
    @php
        $ch = curl_init();
        curl_exec($ch);
    @endphp
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/curl.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
    }

    public function test_severity_critical_for_database_queries(): void
    {
        $blade = <<<'BLADE'
<div>
    @php
        $users = User::all();
    @endphp
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/users.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertEquals('critical', $issues[0]->severity->value);
    }

    public function test_severity_high_for_api_calls(): void
    {
        $blade = <<<'BLADE'
<div>
    @php
        $data = Http::get('https://api.example.com');
    @endphp
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/api.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertEquals('high', $issues[0]->severity->value);
    }

    public function test_severity_medium_for_long_php_blocks(): void
    {
        $blade = <<<'BLADE'
<div>
    @php
        $line1 = 1;
        $line2 = 2;
        $line3 = 3;
        $line4 = 4;
        $line5 = 5;
        $line6 = 6;
        $line7 = 7;
        $line8 = 8;
        $line9 = 9;
        $line10 = 10;
        $line11 = 11;
    @endphp
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/long.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertEquals('medium', $issues[0]->severity->value);
    }

    public function test_severity_low_for_calculations(): void
    {
        $blade = <<<'BLADE'
<div>
    {{ ($a * $b) + ($c * $d) }}
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/calc.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertEquals('low', $issues[0]->severity->value);
    }

    public function test_issue_codes_are_set(): void
    {
        $blade = <<<'BLADE'
<div>
    @php
        $users = User::all();
    @endphp
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/users.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertEquals('blade-has-db-query', $issues[0]->code);
    }

    public function test_prevents_duplicate_issues_on_same_line(): void
    {
        $blade = <<<'BLADE'
<div>
    @php
        $users = User::where('active', true)->get();
    @endphp
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/dup.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        // Should only have ONE issue even though both where() and get() match patterns
        $this->assertCount(1, $issues);
    }

    public function test_custom_threshold_configuration(): void
    {
        $config = new Repository([
            'shieldci' => [
                'analyzers' => [
                    'best-practices' => [
                        'logic-in-blade' => [
                            'max_php_block_lines' => 5,
                        ],
                    ],
                ],
            ],
        ]);

        $analyzer = new LogicInBladeAnalyzer($config);

        $blade = <<<'BLADE'
<div>
    @php
        $a = 1;
        $b = 2;
        $c = 3;
        $d = 4;
        $e = 5;
        $f = 6;
    @endphp
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/custom.blade.php' => $blade]);

        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        // Should fail with custom threshold of 5
        $this->assertFailed($result);
    }

    public function test_passes_when_no_views_directory(): void
    {
        $tempDir = $this->createTempDirectory([]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_empty_blade_file(): void
    {
        $blade = '';

        $tempDir = $this->createTempDirectory(['views/empty.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_html_only_blade_file(): void
    {
        $blade = <<<'BLADE'
<div>
    <h1>Welcome</h1>
    <p>This is a static page</p>
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/static.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_code_snippet_is_included(): void
    {
        $blade = <<<'BLADE'
<div>
    @php
        $users = User::all();
    @endphp
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/users.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertNotNull($issues[0]->codeSnippet);
        $this->assertNotEmpty($issues[0]->codeSnippet->getLines());
    }

    public function test_metadata_includes_details(): void
    {
        $blade = <<<'BLADE'
<div>
    @php
        $line1 = 1;
        $line2 = 2;
        $line3 = 3;
        $line4 = 4;
        $line5 = 5;
        $line6 = 6;
        $line7 = 7;
        $line8 = 8;
        $line9 = 9;
        $line10 = 10;
        $line11 = 11;
    @endphp
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/long.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();

        $this->assertArrayHasKey('block_lines', $issues[0]->metadata);
        $this->assertArrayHasKey('max_lines', $issues[0]->metadata);
        $this->assertEquals(11, $issues[0]->metadata['block_lines']);
    }

    public function test_provides_controller_recommendation(): void
    {
        $blade = <<<'BLADE'
<div>
    @php
        $users = User::all();
    @endphp
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/users.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertStringContainsString('controller', strtolower($issues[0]->recommendation));
    }

    // =========================================================================
    // FALSE POSITIVE TESTS - String/Comment Content
    // =========================================================================

    public function test_does_not_flag_db_pattern_in_string(): void
    {
        $blade = <<<'BLADE'
<div>
    @php
        $doc = "Use DB::table() for queries";
    @endphp
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/doc.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_does_not_flag_db_pattern_in_comment(): void
    {
        $blade = <<<'BLADE'
<div>
    @php
        // Call DB::table() to query the database
        $value = 1;
    @endphp
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/comment.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_does_not_flag_api_pattern_in_string(): void
    {
        $blade = <<<'BLADE'
<div>
    @php
        $help = "Call Http::get() for API calls";
    @endphp
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/help.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_does_not_flag_api_pattern_in_comment(): void
    {
        $blade = <<<'BLADE'
<div>
    @php
        // Use Http::get() to fetch data
        $value = 1;
    @endphp
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/api-comment.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    // =========================================================================
    // FALSE POSITIVE TESTS - Substring Matching
    // =========================================================================

    public function test_does_not_flag_variable_name_containing_array_filter(): void
    {
        $blade = <<<'BLADE'
<div>
    @php
        $my_array_filter_function = true;
    @endphp
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/var.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_does_not_flag_array_key_containing_array_filter(): void
    {
        $blade = <<<'BLADE'
<div>
    @php
        $config['array_filter'] = true;
    @endphp
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/config.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_still_detects_actual_array_filter_call(): void
    {
        $blade = <<<'BLADE'
<div>
    @foreach(array_filter($items, fn($i) => $i->active) as $item)
        <p>{{ $item->name }}</p>
    @endforeach
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/filter.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
    }

    // =========================================================================
    // FALSE POSITIVE TESTS - Object Property Math Operations
    // =========================================================================

    public function test_does_not_flag_simple_object_property_math(): void
    {
        $blade = <<<'BLADE'
<div>
    <p>{{ $item->price * $quantity }}</p>
    <p>{{ $product->discount + $tax }}</p>
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/math.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_does_not_flag_mixed_property_and_variable_math(): void
    {
        $blade = <<<'BLADE'
<div>
    <p>{{ $item->price * $qty }}</p>
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/mixed.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    // =========================================================================
    // FALSE POSITIVE TESTS - Extended Save Whitelist
    // =========================================================================

    public function test_does_not_flag_pdf_save(): void
    {
        $blade = <<<'BLADE'
<div>
    @php
        $pdf->save('/path/to/file.pdf');
    @endphp
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/pdf.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_does_not_flag_excel_save(): void
    {
        $blade = <<<'BLADE'
<div>
    @php
        $excel->save('/path/to/file.xlsx');
    @endphp
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/excel.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_does_not_flag_cache_save(): void
    {
        $blade = <<<'BLADE'
<div>
    @php
        $cache->save($data);
    @endphp
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/cache.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_does_not_flag_export_save(): void
    {
        $blade = <<<'BLADE'
<div>
    @php
        $export->save('/path/to/file');
    @endphp
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/export.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    // =========================================================================
    // TRUE POSITIVE TESTS - Additional Collection Methods
    // =========================================================================

    public function test_detects_collection_pluck_in_foreach(): void
    {
        $blade = <<<'BLADE'
<div>
    @foreach($items->pluck('name') as $name)
        <p>{{ $name }}</p>
    @endforeach
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/pluck.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
    }

    public function test_detects_collection_unique_in_foreach(): void
    {
        $blade = <<<'BLADE'
<div>
    @foreach($items->unique() as $item)
        <p>{{ $item }}</p>
    @endforeach
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/unique.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
    }

    public function test_detects_collection_group_by_in_foreach(): void
    {
        $blade = <<<'BLADE'
<div>
    @foreach($items->groupBy('category') as $group)
        <p>{{ $group }}</p>
    @endforeach
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/groupBy.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
    }

    public function test_detects_collect_helper_with_filter(): void
    {
        $blade = <<<'BLADE'
<div>
    @foreach(collect($items)->filter(fn($i) => $i->active) as $item)
        <p>{{ $item }}</p>
    @endforeach
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/collect.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
    }

    // =========================================================================
    // TRUE POSITIVE TESTS - Relationship Queries with Terminal Methods
    // =========================================================================

    public function test_detects_relationship_first(): void
    {
        $blade = <<<'BLADE'
<div>
    @php
        $post = $user->posts()->first();
    @endphp
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/first.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
    }

    public function test_detects_relationship_count(): void
    {
        $blade = <<<'BLADE'
<div>
    @php
        $count = $user->posts()->count();
    @endphp
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/count.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
    }

    public function test_detects_relationship_exists(): void
    {
        $blade = <<<'BLADE'
<div>
    @php
        $hasComments = $post->comments()->exists();
    @endphp
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/exists.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
    }

    public function test_detects_relationship_sum(): void
    {
        $blade = <<<'BLADE'
<div>
    @php
        $total = $order->items()->sum('price');
    @endphp
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/sum.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
    }

    // =========================================================================
    // FALSE POSITIVE TESTS - Null Coalescing
    // =========================================================================

    public function test_does_not_flag_null_coalescing_with_number(): void
    {
        $blade = <<<'BLADE'
<div>
    <p>{{ $value ?? 0 }}</p>
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/null.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_does_not_flag_null_coalescing_with_string(): void
    {
        $blade = <<<'BLADE'
<div>
    <p>{{ $name ?? 'Unknown' }}</p>
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/null-string.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_does_not_flag_null_coalescing_with_property(): void
    {
        $blade = <<<'BLADE'
<div>
    <p>{{ $user->name ?? 'Guest' }}</p>
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/null-prop.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }
}
