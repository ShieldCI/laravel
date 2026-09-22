<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\BestPractices;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\DataProvider;
use ShieldCI\Analyzers\BestPractices\LogicInBladeAnalyzer;
use ShieldCI\AnalyzersCore\ValueObjects\Issue;
use ShieldCI\Tests\AnalyzerTestCase;

class LogicInBladeAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): LogicInBladeAnalyzer
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

    public function test_skips_published_vendor_views(): void
    {
        // Laravel's published notification mail template — framework-authored
        // code under resources/views/vendor/ that the developer cannot fix.
        $blade = <<<'BLADE'
@isset($actionText)
<?php
    $color = match ($level) {
        'success', 'error' => $level,
        default => 'primary',
    };
?>
@endisset
@php
    $rows = \App\Models\Order::where('status', 'paid')->get();
@endphp
BLADE;

        $tempDir = $this->createTempDirectory([
            'views/vendor/notifications/email.blade.php' => $blade,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_flags_same_content_outside_vendor_directory(): void
    {
        // Identical content as the vendor test, but developer-authored — must flag.
        $blade = <<<'BLADE'
@isset($actionText)
<?php
    $color = match ($level) {
        'success', 'error' => $level,
        default => 'primary',
    };
?>
@endisset
@php
    $rows = \App\Models\Order::where('status', 'paid')->get();
@endphp
BLADE;

        $tempDir = $this->createTempDirectory([
            'views/notifications/email.blade.php' => $blade,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertHasIssueContaining('Inline PHP found in Blade template', $result);

        // The raw <?php span used to make the compiled PHP unparseable, so Pass 2 never ran
        // against this fixture and its query went unreported (#415).
        $this->assertHasIssueContaining('Database query found in Blade template', $result);
    }

    public function test_skips_blade_files_under_excluded_paths(): void
    {
        $blade = <<<'BLADE'
<?php $label = strtoupper($status); ?>
<span>{{ $label }}</span>
BLADE;

        $tempDir = $this->createTempDirectory([
            'views/legacy/badge.blade.php' => $blade,
            'views/current/badge.blade.php' => $blade,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);
        $analyzer->setExcludePatterns(['views/legacy/*']);

        $result = $analyzer->analyze();

        $this->assertHasIssueContaining('Inline PHP found in Blade template', $result);

        foreach ($result->getIssues() as $issue) {
            $this->assertStringStartsWith('views/current/', $issue->location->file ?? '');
        }
    }

    public function test_ignores_presentational_findings_in_a_relocated_pagination_view(): void
    {
        // Laravel's pagination template, cosmetically customised and relocated out of
        // resources/views/vendor by Paginator::defaultView(). AbstractPaginator::render()
        // supplies $paginator and the bounded $elements window itself, so there is no
        // controller to move the range arithmetic or the appends() call into.
        $blade = <<<'BLADE'
@if ($paginator->hasPages())
    <nav class="pagination-shell">
        <p>Showing {{ ($paginator->currentPage() - 1) * $paginator->perPage() + 1 }}
           to {{ min($paginator->currentPage() * $paginator->perPage(), $paginator->total()) }}
           of {{ $paginator->total() }}</p>
        @foreach ($elements as $element)
            @if (is_array($element))
                @foreach ($element as $page => $url)
                    @if ($page == $paginator->currentPage())
                        <span>{{ $page }}</span>
                    @else
                        <a href="{{ $paginator->appends(request()->all())->url($page) }}">{{ $page }}</a>
                    @endif
                @endforeach
            @endif
        @endforeach
    </nav>
@endif
BLADE;

        $tempDir = $this->createTempDirectory(['views/pagination/tailwind.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_recognises_a_pagination_component_with_a_custom_receiver_name(): void
    {
        // A <x-pagination> wrapper names the paginator whatever it likes; the paginator
        // contract, not the variable name or the path, is what identifies the view.
        $blade = <<<'BLADE'
@props(['pages'])
@if ($pages->hasPages())
    @if ($pages->onFirstPage())
        <span>prev</span>
    @else
        <a href="{{ $pages->previousPageUrl() }}">prev</a>
    @endif
    <p>{{ ($pages->currentPage() - 1) * $pages->perPage() + 1 }}</p>
@endif
BLADE;

        $tempDir = $this->createTempDirectory(['views/components/pagination.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_still_flags_database_query_in_a_pagination_view(): void
    {
        $blade = <<<'BLADE'
@if ($paginator->hasPages())
    <p>{{ ($paginator->currentPage() - 1) * $paginator->perPage() + 1 }}</p>
    <span>{{ \App\Models\Setting::first()->label }}</span>
    @if ($paginator->onFirstPage())
        <span>prev</span>
    @else
        <a href="{{ $paginator->previousPageUrl() }}">prev</a>
    @endif
@endif
BLADE;

        $tempDir = $this->createTempDirectory(['views/pagination/tailwind.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertHasIssueContaining('Database query found in Blade template', $result);
    }

    public function test_still_flags_api_call_in_a_pagination_view(): void
    {
        $blade = <<<'BLADE'
@if ($paginator->hasPages())
    <p>{{ ($paginator->currentPage() - 1) * $paginator->perPage() + 1 }}</p>
    <span>{{ Http::get('https://example.test/rates') }}</span>
    @if ($paginator->onFirstPage())
        <span>prev</span>
    @else
        <a href="{{ $paginator->previousPageUrl() }}">prev</a>
    @endif
@endif
BLADE;

        $tempDir = $this->createTempDirectory(['views/pagination/tailwind.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertHasIssueContaining('API call found in Blade template', $result);
    }

    public function test_still_flags_inline_php_in_a_pagination_view(): void
    {
        // Structural hygiene stays reported: the developer owns this template now and can
        // swap raw <?php for @php.
        $blade = <<<'BLADE'
@if ($paginator->hasPages())
<?php $label = 'page'; ?>
    @if ($paginator->onFirstPage())
        <span>{{ $label }}</span>
    @else
        <a href="{{ $paginator->previousPageUrl() }}">{{ $label }}</a>
    @endif
@endif
BLADE;

        $tempDir = $this->createTempDirectory(['views/pagination/tailwind.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertHasIssueContaining('Inline PHP found in Blade template', $result);
    }

    public function test_does_not_treat_an_ordinary_view_that_renders_links_as_a_pagination_view(): void
    {
        // Rendering a paginator's links is not the same as being its link-window template.
        $blade = <<<'BLADE'
@foreach ($users as $user)
    <li>{{ ($user->credits - $user->used) * 2 }}</li>
@endforeach
{{ $users->links() }}
BLADE;

        $tempDir = $this->createTempDirectory(['views/users/index.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertHasIssueContaining('Complex calculation found in Blade template', $result);
    }

    public function test_single_paginator_method_does_not_exempt_a_view(): void
    {
        // One paginator method is the ordinary "hide the pager when it fits" guard. The
        // exemption needs two distinct methods on the same receiver.
        $blade = <<<'BLADE'
@if ($users->hasPages())
    <div>{{ ($total - $used) * $rate }}</div>
    {{ $users->links() }}
@endif
BLADE;

        $tempDir = $this->createTempDirectory(['views/users/index.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertHasIssueContaining('Complex calculation found in Blade template', $result);
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

        $this->assertWarning($result);
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

        $this->assertWarning($result);
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

        $this->assertWarning($result);
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

    public function test_single_statement_php_directive_does_not_trigger_unclosed_block(): void
    {
        $blade = <<<'BLADE'
<div>
    @php($total = $days['total'])
    @php($count = $items['count'])
    <p>{{ $total }}</p>
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/single-php.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
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

        $this->assertWarning($result);
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

        $this->assertWarning($result);
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

        $this->assertWarning($result);
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

        $this->assertWarning($result);
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

        $this->assertWarning($result);
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

    public function test_flags_file_get_contents_on_a_url_as_an_api_call(): void
    {
        $blade = <<<'BLADE'
<pre>{{ file_get_contents('https://api.example.test/rates') }}</pre>
BLADE;

        $tempDir = $this->createTempDirectory(['views/rates.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('API call found in Blade template', $result);
    }

    public function test_flags_file_get_contents_on_a_concatenated_url(): void
    {
        $blade = <<<'BLADE'
<pre>{{ file_get_contents('https://api.example.test/rates/' . $code) }}</pre>
BLADE;

        $tempDir = $this->createTempDirectory(['views/rates.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('API call found in Blade template', $result);
    }

    public function test_flags_file_get_contents_on_an_interpolated_url(): void
    {
        $blade = <<<'BLADE'
<pre>{{ file_get_contents("https://api.example.test/rates/{$code}") }}</pre>
BLADE;

        $tempDir = $this->createTempDirectory(['views/rates.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('API call found in Blade template', $result);
    }

    public function test_flags_file_get_contents_on_a_url_helper(): void
    {
        $blade = <<<'BLADE'
<pre>{{ file_get_contents(url('/api/rates')) }}</pre>
BLADE;

        $tempDir = $this->createTempDirectory(['views/rates.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('API call found in Blade template', $result);
    }

    public function test_does_not_flag_file_get_contents_on_a_path_helper(): void
    {
        // Inlining an SVG from public_path() and reading a text blob from storage_path() are
        // local file reads, not outbound requests.
        $blade = <<<'BLADE'
<span>{!! file_get_contents(public_path('img/logo.svg')) !!}</span>
<pre>{{ file_get_contents(storage_path('app/release-notes.txt')) }}</pre>
BLADE;

        $tempDir = $this->createTempDirectory(['views/logo.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_does_not_flag_file_get_contents_on_a_relative_path_literal(): void
    {
        $blade = <<<'BLADE'
<pre>{{ file_get_contents('data/notes.txt') }}</pre>
BLADE;

        $tempDir = $this->createTempDirectory(['views/notes.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_does_not_flag_file_get_contents_on_a_variable(): void
    {
        // The argument could hold either a path or a URL. The local read is the common case by
        // far, so an argument that proves nothing is left alone rather than named an API call.
        $blade = <<<'BLADE'
<pre>{{ file_get_contents($path) }}</pre>
BLADE;

        $tempDir = $this->createTempDirectory(['views/notes.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_severity_high_for_database_queries(): void
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
        $this->assertEquals('high', $issues[0]->severity->value);
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

        $this->assertWarning($result);
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

        $this->assertWarning($result);
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
        $this->assertEquals('blade-has-db-query', $issues[0]->metadata['code']);
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
        $this->assertWarning($result);
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

        $this->assertWarning($result);
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

        $this->assertWarning($result);
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

        $this->assertWarning($result);
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

        $this->assertWarning($result);
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

        $this->assertWarning($result);
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

        $this->assertWarning($result);
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

    // =========================================================================
    // FALSE POSITIVE TESTS - Non-Eloquent Static Calls
    // =========================================================================

    public function test_does_not_flag_collection_where(): void
    {
        $blade = <<<'BLADE'
<div>
    @php
        $filtered = Collection::where('status', 'active');
    @endphp
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/collection.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_does_not_flag_arr_where(): void
    {
        $blade = <<<'BLADE'
<div>
    @php
        $filtered = Arr::where($items, fn($item) => $item > 5);
    @endphp
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/arr.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_does_not_flag_arr_first(): void
    {
        $blade = <<<'BLADE'
<div>
    @php
        $first = Arr::first($items, fn($item) => $item > 5);
    @endphp
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/arr-first.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_does_not_flag_carbon_create(): void
    {
        $blade = <<<'BLADE'
<div>
    @php
        $date = Carbon::create(2024, 1, 1);
    @endphp
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/carbon.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_does_not_flag_carbon_immutable_create(): void
    {
        $blade = <<<'BLADE'
<div>
    @php
        $date = CarbonImmutable::create(2024, 1, 1);
    @endphp
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/carbon-immutable.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_does_not_flag_datetime_create(): void
    {
        $blade = <<<'BLADE'
<div>
    @php
        $date = DateTime::create();
    @endphp
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/datetime.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_does_not_flag_factory_create(): void
    {
        $blade = <<<'BLADE'
<div>
    @php
        $instance = Factory::create();
    @endphp
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/factory.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_still_flags_eloquent_model_where(): void
    {
        $blade = <<<'BLADE'
<div>
    @php
        $users = User::where('active', true)->get();
    @endphp
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/user.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Database query', $result);
    }

    public function test_still_flags_eloquent_model_create(): void
    {
        $blade = <<<'BLADE'
<div>
    @php
        $order = Order::create(['status' => 'pending']);
    @endphp
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/order.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Database query', $result);
    }

    public function test_still_flags_eloquent_model_all(): void
    {
        $blade = <<<'BLADE'
<div>
    @foreach(Product::all() as $product)
        <p>{{ $product->name }}</p>
    @endforeach
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/product.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
    }

    public function test_still_flags_eloquent_model_first(): void
    {
        $blade = <<<'BLADE'
<div>
    @php
        $post = Post::first();
    @endphp
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/post.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
    }

    // =========================================================================
    // FALSE POSITIVE TESTS - Unknown Classes Without Terminal Methods
    // =========================================================================

    public function test_does_not_flag_unknown_class_where_without_terminal(): void
    {
        $blade = <<<'BLADE'
<div>
    @php
        $result = CustomQueryBuilder::where('x', 'y');
    @endphp
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/custom.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_does_not_flag_repository_where(): void
    {
        $blade = <<<'BLADE'
<div>
    @php
        $users = UserRepository::where('active', true);
    @endphp
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/repo.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_does_not_flag_query_builder_find_without_terminal(): void
    {
        $blade = <<<'BLADE'
<div>
    @php
        $item = SomeService::find($id);
    @endphp
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/service.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_flags_model_fqcn_where(): void
    {
        $blade = <<<'BLADE'
<div>
    @php
        $users = \App\Models\User::where('active', true);
    @endphp
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/fqcn.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Database query', $result);
    }

    public function test_flags_model_fqcn_find(): void
    {
        $blade = <<<'BLADE'
<div>
    @php
        $user = \App\Models\User::find(1);
    @endphp
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/fqcn-find.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
    }

    public function test_flags_short_class_where_with_terminal(): void
    {
        $blade = <<<'BLADE'
<div>
    @php
        $users = User::where('active', true)->get();
    @endphp
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/terminal.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Database query', $result);
    }

    public function test_flags_short_class_where_with_first_terminal(): void
    {
        $blade = <<<'BLADE'
<div>
    @php
        $user = User::where('active', true)->first();
    @endphp
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/terminal-first.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
    }

    // =========================================================================
    // FALSE POSITIVE TESTS - Collection Variable Detection
    // =========================================================================

    public function test_does_not_flag_collection_items_count(): void
    {
        $blade = <<<'BLADE'
<div>
    @php
        $total = $collection->items()->count();
    @endphp
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/collection-items.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_does_not_flag_items_variable_method(): void
    {
        $blade = <<<'BLADE'
<div>
    @php
        $first = $items->filter()->first();
    @endphp
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/items-filter.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_does_not_flag_data_variable_get(): void
    {
        $blade = <<<'BLADE'
<div>
    @php
        $result = $data->transform()->get();
    @endphp
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/data-transform.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_does_not_flag_results_variable_first(): void
    {
        $blade = <<<'BLADE'
<div>
    @php
        $first = $results->filter()->first();
    @endphp
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/results-filter.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_still_flags_user_posts_get(): void
    {
        $blade = <<<'BLADE'
<div>
    @php
        $posts = $user->posts()->get();
    @endphp
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/user-posts.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
    }

    public function test_still_flags_post_comments_count(): void
    {
        $blade = <<<'BLADE'
<div>
    @php
        $count = $post->comments()->count();
    @endphp
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/post-comments.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
    }

    public function test_does_not_flag_my_collection_variable(): void
    {
        $blade = <<<'BLADE'
<div>
    @php
        $first = $myCollection->map()->first();
    @endphp
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/my-collection.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_does_not_flag_user_list_variable(): void
    {
        $blade = <<<'BLADE'
<div>
    @php
        $first = $userList->filter()->first();
    @endphp
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/user-list.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    // =========================================================================
    // AMBIGUOUS SUFFIX TESTS - Resource, Manager, Builder
    // =========================================================================

    public function test_flags_ambiguous_suffix_with_terminal_method_get(): void
    {
        $blade = <<<'BLADE'
<div>
    @php
        $resources = OrderResource::where('status', 'active')->get();
    @endphp
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/resource.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Database query', $result);
    }

    public function test_flags_ambiguous_suffix_with_terminal_method_first(): void
    {
        $blade = <<<'BLADE'
<div>
    @php
        $manager = UserManager::where('role', 'admin')->first();
    @endphp
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/manager.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Database query', $result);
    }

    public function test_flags_ambiguous_suffix_with_terminal_method_count(): void
    {
        $blade = <<<'BLADE'
<div>
    @php
        $count = QueryBuilder::where('active', true)->count();
    @endphp
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/builder.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Database query', $result);
    }

    public function test_does_not_flag_ambiguous_suffix_without_terminal_method(): void
    {
        $blade = <<<'BLADE'
<div>
    @php
        $query = OrderResource::where('status', 'active');
    @endphp
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/resource-no-terminal.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_does_not_flag_manager_suffix_without_terminal_method(): void
    {
        $blade = <<<'BLADE'
<div>
    @php
        $query = UserManager::where('role', 'admin');
    @endphp
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/manager-no-terminal.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_does_not_flag_builder_suffix_without_terminal_method(): void
    {
        $blade = <<<'BLADE'
<div>
    @php
        $query = QueryBuilder::where('active', true);
    @endphp
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/builder-no-terminal.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_flags_resource_suffix_with_paginate_terminal(): void
    {
        $blade = <<<'BLADE'
<div>
    @php
        $items = ProductResource::where('in_stock', true)->paginate(10);
    @endphp
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/resource-paginate.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
    }

    public function test_flags_resource_suffix_with_pluck_terminal(): void
    {
        $blade = <<<'BLADE'
<div>
    @php
        $names = CategoryResource::where('active', true)->pluck('name');
    @endphp
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/resource-pluck.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
    }

    public function test_still_skips_definite_non_model_suffix_even_with_terminal(): void
    {
        // Service is a DEFINITE non-model suffix, so should be skipped
        // even with a terminal method present
        $blade = <<<'BLADE'
<div>
    @php
        $result = UserService::where('active', true)->get();
    @endphp
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/service-terminal.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_still_skips_repository_suffix_even_with_terminal(): void
    {
        $blade = <<<'BLADE'
<div>
    @php
        $users = UserRepository::where('active', true)->get();
    @endphp
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/repo-terminal.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    // =========================================================================
    // COMPUTATION COST TESTS (NEW)
    // =========================================================================

    /**
     * Run the analyzer over a single Blade template and return only its nested-loop findings.
     *
     * Filtering by code (rather than asserting on the whole result) keeps these cases honest:
     * an unrelated rule firing inside a fixture cannot make a "no nested-loop issue" test pass or fail.
     *
     * @param  array<string, mixed>  $config
     * @return list<Issue>
     */
    private function nestedForeachIssues(string $blade, array $config = []): array
    {
        $tempDir = $this->createTempDirectory(['views/nested.blade.php' => $blade]);

        $analyzer = new LogicInBladeAnalyzer(new Repository([
            'shieldci' => ['analyzers' => ['best-practices' => ['logic-in-blade' => $config]]],
        ]));
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        return array_values(array_filter(
            $analyzer->analyze()->getIssues(),
            fn ($issue): bool => ($issue->metadata['code'] ?? null) === 'blade-nested-foreach'
        ));
    }

    public function test_detects_nested_foreach_that_searches_for_the_outer_item(): void
    {
        // The inner loop scans every post to find the ones belonging to the current user:
        // O(n×m) work for O(n) of output. Grouping posts by user_id in the controller removes it.
        $blade = <<<'BLADE'
<div>
    @foreach($users as $user)
        <h2>{{ $user->name }}</h2>
        @foreach($allPosts as $post)
            @if($post->user_id === $user->id)
                <p>{{ $post->title }}</p>
            @endif
        @endforeach
    @endforeach
</div>
BLADE;

        $issues = $this->nestedForeachIssues($blade);

        $this->assertCount(1, $issues);
        $this->assertStringContainsString('scans a collection for each outer item', $issues[0]->message);
    }

    public function test_nested_foreach_has_medium_severity(): void
    {
        $blade = <<<'BLADE'
<div>
    @foreach($users as $user)
        @foreach($allPosts as $post)
            @if($post->user_id == $user->id)
                <p>{{ $post->title }}</p>
            @endif
        @endforeach
    @endforeach
</div>
BLADE;

        $issues = $this->nestedForeachIssues($blade);

        $this->assertCount(1, $issues);
        $this->assertEquals('medium', $issues[0]->severity->value);
    }

    public function test_ignores_partition_iteration_over_a_grouped_array(): void
    {
        // The regression test for issue #276. Every option is rendered exactly once — the sum of the
        // group sizes is the total option count — so this is O(n), not O(n²).
        $blade = <<<'BLADE'
<select name="city">
    @foreach($cityOptions as $country => $options)
        <optgroup label="{{ $country }}">
            @foreach($options as $option)
                <option value="{{ $option['value'] }}">{{ $option['label'] }}</option>
            @endforeach
        </optgroup>
    @endforeach
</select>
BLADE;

        $this->assertSame([], $this->nestedForeachIssues($blade));
    }

    public function test_ignores_iteration_over_an_array_key_of_the_outer_item(): void
    {
        $blade = <<<'BLADE'
<div>
    @foreach($records as $record)
        @foreach($record['users'] as $user)
            <p>{{ $user['name'] }}</p>
        @endforeach
    @endforeach
</div>
BLADE;

        $this->assertSame([], $this->nestedForeachIssues($blade));
    }

    public function test_ignores_lookup_keyed_by_the_outer_item(): void
    {
        // An O(1) hash lookup returning only this city's own rows — per-item, so still O(n) overall.
        $blade = <<<'BLADE'
<div>
    @foreach($cities as $city)
        @forelse($membershipData[$city->id]['items'] as $item)
            <p>{{ $item['label'] }}</p>
        @empty
            <p>None</p>
        @endforelse
    @endforeach
</div>
BLADE;

        $this->assertSame([], $this->nestedForeachIssues($blade));
    }

    public function test_ignores_relationship_access_on_the_outer_item(): void
    {
        // Iterating a relation renders each product once. Whether it lazy-loads depends on the
        // controller's with() call, which a Blade template cannot see — so this stays silent.
        $blade = <<<'BLADE'
<div>
    @foreach($categories as $category)
        <h2>{{ $category->name }}</h2>
        @foreach($category->products as $product)
            <p>{{ $product->name }}</p>
        @endforeach
    @endforeach
</div>
BLADE;

        $this->assertSame([], $this->nestedForeachIssues($blade));
    }

    public function test_ignores_grid_rendering(): void
    {
        // The inner collection is unrelated to the outer one, but nothing is searched: the loop
        // renders one cell per row/column pair, so its cost is the size of its own output.
        $blade = <<<'BLADE'
<table>
    @foreach($rows as $row)
        <tr>
            @foreach($columns as $column)
                <td>{{ $row[$column] }}</td>
            @endforeach
        </tr>
    @endforeach
</table>
BLADE;

        $this->assertSame([], $this->nestedForeachIssues($blade));
    }

    public function test_ignores_triple_nested_partition_iteration(): void
    {
        $blade = <<<'BLADE'
<div>
    @foreach($continents as $continent => $countries)
        @foreach($countries as $country => $cities)
            @foreach($cities as $city)
                <p>{{ $city['name'] }}</p>
            @endforeach
        @endforeach
    @endforeach
</div>
BLADE;

        $this->assertSame([], $this->nestedForeachIssues($blade));
    }

    public function test_detects_nested_foreach_that_searches_by_the_inner_loop_key(): void
    {
        // The same linear search as the value-variable form, written against the loop key: for
        // each city, scan every listing group to find the one that matches.
        $blade = <<<'BLADE'
<div>
    @foreach($cities as $city)
        @foreach($allListings as $listingCity => $listings)
            @if($listingCity == $city->slug)
                <span>{{ count($listings) }}</span>
            @endif
        @endforeach
    @endforeach
</div>
BLADE;

        $issues = $this->nestedForeachIssues($blade);

        $this->assertCount(1, $issues);
        $this->assertStringContainsString('scans a collection for each outer item', $issues[0]->message);
    }

    public function test_detects_nested_foreach_that_matches_inner_key_to_outer_key(): void
    {
        $blade = <<<'BLADE'
<div>
    @foreach($totalsByMonth as $month => $total)
        @foreach($budgetsByMonth as $budgetMonth => $budget)
            @if($budgetMonth == $month)
                <td>{{ $total }} / {{ $budget }}</td>
            @endif
        @endforeach
    @endforeach
</div>
BLADE;

        $this->assertCount(1, $this->nestedForeachIssues($blade));
    }

    public function test_ignores_partition_iteration_compared_on_the_inner_key(): void
    {
        // The inner loop walks the outer item's own array, so every cell is visited once. The
        // comparison is a display decision, not a search.
        $blade = <<<'BLADE'
<table>
    @foreach($rows as $row)
        @foreach($row as $key => $cell)
            @if($key == $highlight)
                <td class="active">{{ $cell }}</td>
            @else
                <td>{{ $cell }}</td>
            @endif
        @endforeach
    @endforeach
</table>
BLADE;

        $this->assertSame([], $this->nestedForeachIssues($blade));
    }

    public function test_ignores_grid_rendering_with_a_keyed_inner_loop(): void
    {
        // Unrelated inner collection, but nothing is matched back to the outer item: the grid
        // costs exactly what it renders. Naming the inner key must not change that.
        $blade = <<<'BLADE'
<table>
    @foreach($rows as $row)
        <tr>
            @foreach($columns as $i => $column)
                <td>{{ $row[$column] }}</td>
            @endforeach
        </tr>
    @endforeach
</table>
BLADE;

        $this->assertSame([], $this->nestedForeachIssues($blade));
    }

    public function test_max_foreach_depth_is_configurable(): void
    {
        $blade = <<<'BLADE'
<div>
    @foreach($users as $user)
        @foreach($allPosts as $post)
            @if($post->user_id === $user->id)
                <p>{{ $post->title }}</p>
            @endif
        @endforeach
    @endforeach
</div>
BLADE;

        $this->assertCount(1, $this->nestedForeachIssues($blade));
        $this->assertSame([], $this->nestedForeachIssues($blade, ['max_foreach_depth' => 3]));
    }

    public function test_passes_with_single_foreach(): void
    {
        $blade = <<<'BLADE'
<div>
    @foreach($items as $item)
        <p>{{ $item }}</p>
    @endforeach
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/single.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_detects_regex_in_foreach(): void
    {
        $blade = <<<'BLADE'
<div>
    @foreach($items as $item)
        @php
            $clean = preg_replace('/[^a-zA-Z]/', '', $item->name);
        @endphp
        <p>{{ $clean }}</p>
    @endforeach
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/regex.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('Expensive computation', $result);
    }

    public function test_detects_str_replace_in_foreach(): void
    {
        $blade = <<<'BLADE'
<div>
    @foreach($items as $item)
        <p>{{ str_replace('_', ' ', $item->slug) }}</p>
    @endforeach
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/str-replace.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('Expensive computation', $result);
    }

    public function test_passes_regex_outside_loop(): void
    {
        $blade = <<<'BLADE'
<div>
    @php
        $clean = preg_replace('/[^a-zA-Z]/', '', $title);
    @endphp
    <h1>{{ $clean }}</h1>
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/regex-outside.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_detects_to_array_in_blade(): void
    {
        $blade = <<<'BLADE'
<div>
    @php
        $data = $users->toArray();
    @endphp
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/to-array.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('Expensive computation', $result);
    }

    public function test_detects_to_json_in_blade(): void
    {
        $blade = <<<'BLADE'
<div>
    @php
        $json = $collection->toJson();
    @endphp
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/to-json.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('Expensive computation', $result);
    }

    public function test_does_not_flag_to_array_in_string(): void
    {
        $blade = <<<'BLADE'
<div>
    @php
        $msg = "Use ->toArray() to convert";
    @endphp
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/to-array-string.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_expensive_computation_code_is_set(): void
    {
        $blade = <<<'BLADE'
<div>
    @php
        $data = $users->toArray();
    @endphp
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/code.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $issues = $result->getIssues();
        $computeIssue = null;
        foreach ($issues as $issue) {
            if (($issue->metadata['code'] ?? null) === 'blade-expensive-computation') {
                $computeIssue = $issue;
                break;
            }
        }
        $this->assertNotNull($computeIssue);
    }

    public function test_nested_foreach_metadata_includes_depth(): void
    {
        $blade = <<<'BLADE'
<div>
    @foreach($users as $user)
        @foreach($allPosts as $post)
            @if($post->user_id === $user->id)
                <p>{{ $post->title }}</p>
            @endif
        @endforeach
    @endforeach
</div>
BLADE;

        $issues = $this->nestedForeachIssues($blade);

        $this->assertCount(1, $issues);
        $this->assertArrayHasKey('depth', $issues[0]->metadata);
        $this->assertEquals(2, $issues[0]->metadata['depth']);
    }

    // =========================================================================
    // MULTI-LINE DB CHAIN DETECTION TESTS
    // =========================================================================

    public function test_detects_multi_line_where_get_chain(): void
    {
        $blade = <<<'BLADE'
<div>
    @php
        $users = User::where('active', true)
            ->get();
    @endphp
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/multi-get.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Database query', $result);
    }

    public function test_detects_multi_line_where_first_chain(): void
    {
        $blade = <<<'BLADE'
<div>
    @php
        $user = User::where('email', $email)
            ->first();
    @endphp
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/multi-first.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Database query', $result);
    }

    public function test_detects_multi_line_fqcn_where_without_terminal(): void
    {
        $blade = <<<'BLADE'
<div>
    @php
        $query = \App\Models\User::where('active', true)
            ->orderBy('name');
    @endphp
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/multi-fqcn.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Database query', $result);
    }

    public function test_does_not_flag_multi_line_non_eloquent_chain(): void
    {
        $blade = <<<'BLADE'
<div>
    @php
        $filtered = Collection::where('status', 'active')
            ->first();
    @endphp
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/multi-collection.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_does_not_flag_multi_line_service_chain(): void
    {
        $blade = <<<'BLADE'
<div>
    @php
        $result = UserService::where('active', true)
            ->get();
    @endphp
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/multi-service.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_does_not_flag_multi_line_chain_without_terminal(): void
    {
        $blade = <<<'BLADE'
<div>
    @php
        $query = SomeClass::where('x', 'y')
            ->orderBy('name');
    @endphp
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/multi-no-terminal.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_multi_line_chain_stops_at_blank_line(): void
    {
        $blade = <<<'BLADE'
<div>
    @php
        $query = User::where('active', true)

            ->get();
    @endphp
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/multi-blank.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        // AST correctly detects the chain across blank lines (blank lines don't break PHP expressions)
        $this->assertFailed($result);
        $this->assertHasIssueContaining('Database query', $result);
    }

    public function test_multi_line_chain_stops_at_endphp(): void
    {
        $blade = <<<'BLADE'
<div>
    @php
        $query = User::where('active', true)
    @endphp
    @php
            ->get();
    @endphp
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/multi-endphp.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        // @endphp boundary stops the scan — should NOT detect multi-line chain
        $this->assertPassed($result);
    }

    public function test_detects_multi_line_db_facade_chain(): void
    {
        // DB:: is a DEFINITE_DB_PATTERN, so it's caught on line 1 by hasDbQuery()
        $blade = <<<'BLADE'
<div>
    @php
        $users = DB::table('users')
            ->where('active', true)
            ->get();
    @endphp
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/multi-db.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Database query', $result);
    }

    public function test_multi_line_chain_with_ambiguous_suffix_and_terminal(): void
    {
        $blade = <<<'BLADE'
<div>
    @php
        $items = OrderResource::where('status', 'active')
            ->get();
    @endphp
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/multi-resource.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Database query', $result);
    }

    // =========================================================================
    // BLOCK COMMENT FALSE POSITIVE TESTS
    // =========================================================================

    public function test_does_not_flag_db_pattern_in_single_line_block_comment(): void
    {
        $blade = <<<'BLADE'
<div>
    @php
        /* DB::table('users')->get(); */
        $value = 1;
    @endphp
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/block-comment-single.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_does_not_flag_db_pattern_in_multi_line_block_comment(): void
    {
        $blade = <<<'BLADE'
<div>
    @php
        /*
         * DB::table('users')->get();
         * User::all();
         */
        $value = 1;
    @endphp
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/block-comment-multi.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_does_not_flag_api_call_in_block_comment(): void
    {
        $blade = <<<'BLADE'
<div>
    @php
        /* Http::get('https://api.example.com') */
        $value = 1;
    @endphp
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/block-comment-api.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_still_flags_code_after_block_comment_closes(): void
    {
        $blade = <<<'BLADE'
<div>
    @php
        /*
         * This is a comment
         */
        $users = User::all();
    @endphp
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/block-comment-then-code.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Database query', $result);
    }

    public function test_does_not_flag_block_comment_delimiter_in_string(): void
    {
        $blade = <<<'BLADE'
<div>
    @php
        $x = "/* not a comment */";
        $users = User::all();
    @endphp
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/block-delimiter-in-string.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        // The /* is inside a string, so User::all() should still be flagged
        $this->assertFailed($result);
        $this->assertHasIssueContaining('Database query', $result);
    }

    public function test_block_comment_spanning_many_lines(): void
    {
        $blade = <<<'BLADE'
<div>
    @php
        /*
         * Line 1
         * Line 2
         * Line 3
         * DB::table('users')->get();
         * User::all();
         * Http::get('https://api.example.com');
         */
        $value = 1;
    @endphp
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/block-comment-long.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_blade_props_directive(): void
    {
        $blade = <<<'BLADE'
@props(['url'])
<tr>
<td class="header">
<a href="{{ $url }}" style="display: inline-block;">
<img src="{{ asset('images/logo.png') }}" alt="{{ config('app.name') }}">
</a>
</td>
</tr>
BLADE;

        $tempDir = $this->createTempDirectory(['views/mail/header.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_blade_aware_directive(): void
    {
        $blade = <<<'BLADE'
@aware(['color' => 'gray'])
<div>{{ $color }}</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/component.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    // =========================================================================
    // @PHP BLOCK DETECTION (#411)
    // =========================================================================

    /**
     * Text that merely reads "@php" is not a directive. Blade compiles every one of these back
     * to itself, so reporting an unclosed block against them recommended an @endphp that would
     * have changed what the template renders.
     *
     * The annotation is not redundant with the attribute: composer allows phpunit ^9
     * through ^13, and the CI matrix resolves 9 on Laravel 9, which reads only the
     * annotation, while 12 dropped annotations and reads only the attribute.
     *
     * @dataProvider phpMentionProvider
     */
    #[DataProvider('phpMentionProvider')]
    public function test_a_mention_of_the_php_directive_is_not_an_unclosed_block(string $blade): void
    {
        $tempDir = $this->createTempDirectory(['views/mention.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $this->assertPassed($analyzer->analyze());
    }

    /**
     * @return array<string, array{string}>
     */
    public static function phpMentionProvider(): array
    {
        return [
            'a mention in prose' => ["<div>\n    <p>Use @php blocks here.</p>\n</div>\n"],
            'a mention in an html comment' => ["<div>\n    <!-- @php -->\n</div>\n"],
            'the escape' => ["<div>\n    <p>@@php renders the directive itself.</p>\n</div>\n"],
            // Blade turns this into one self-contained PHP tag pair, so nothing stays open.
            'a block opened and closed on one line' => ["<div>\n    @php \$label = 'badge'; @endphp\n    <span>{{ \$label }}</span>\n</div>\n"],
            // storeVerbatimBlocks() empties this before storePhpBlocks() ever runs.
            'a directive shown inside verbatim' => ["<div>\n@verbatim\n    @php\n@endverbatim\n</div>\n"],
            // compileComments() strips this, so nothing of it reaches the browser.
            'a directive inside a blade comment' => ["<div>\n{{--\n    @php\n--}}\n</div>\n"],
            // A longer name is a different directive, so the word boundary must hold.
            'a directive whose name merely starts with php' => ["<div>\n    @phpunit\n    <p>{{ \$x }}</p>\n</div>\n"],
        ];
    }

    /**
     * The narrowed reading still has to catch the thing it is for. A sentence mentioning the
     * directive sits above a real opener here, and only the opener may be reported.
     */
    public function test_an_unclosed_block_is_reported_against_its_opening_line(): void
    {
        $blade = <<<'BLADE'
<div>
    <p>Write your setup in a @php block.</p>
    @php
        $var = 1;
</div>
BLADE;

        $issues = $this->structuralIssues($blade, 'blade-unclosed-php-block');

        $this->assertCount(1, $issues);
        $this->assertSame(3, $issues[0]->location?->line);
    }

    /**
     * One cursor could only ever describe one block. Reading spans reports each of them.
     */
    public function test_each_oversized_block_is_reported_at_its_own_opening_line(): void
    {
        $body = str_repeat("        \$x = 1;\n", 11);
        $blade = "<div>\n    @php\n".$body."    @endphp\n    @php\n".$body."    @endphp\n</div>\n";

        $issues = $this->structuralIssues($blade, 'blade-php-block-too-long');

        $this->assertCount(2, $issues);
        $this->assertSame(2, $issues[0]->location?->line);
        $this->assertSame(15, $issues[1]->location?->line);
        $this->assertSame(11, $issues[0]->metadata['block_lines']);
        $this->assertSame(11, $issues[1]->metadata['block_lines']);
    }

    /**
     * A "<?php" on a line inside a block body is the author's own PHP or text in a string,
     * not a raw tag they should be told to replace.
     *
     * The annotation is not redundant with the attribute: composer allows phpunit ^9
     * through ^13, and the CI matrix resolves 9 on Laravel 9, which reads only the
     * annotation, while 12 dropped annotations and reads only the attribute.
     *
     * @dataProvider inlinePhpInsideABodyProvider
     */
    #[DataProvider('inlinePhpInsideABodyProvider')]
    public function test_inline_php_inside_a_block_body_is_not_reported(string $blade): void
    {
        $this->assertSame([], $this->structuralIssues($blade, 'blade-inline-php'));
    }

    /**
     * @return array<string, array{string}>
     */
    public static function inlinePhpInsideABodyProvider(): array
    {
        return [
            'inside a @php block' => ["<div>\n    @php\n        \$snippet = '<?php echo 1; ?>';\n    @endphp\n    <code>{{ \$snippet }}</code>\n</div>\n"],
            'inside a raw tag body' => ["<div>\n    @php\n        \$a = 1;\n    @endphp\n    @php\n        \$snippet = '<?php echo 1; ?>';\n    @endphp\n</div>\n"],
        ];
    }

    /**
     * The opening line of a raw tag is never inside a body, so it stays reported. That is the
     * whole point of the rule, and suppressing it would be the easy way to get the test above
     * to pass for the wrong reason.
     */
    public function test_the_opening_line_of_a_raw_tag_is_still_reported(): void
    {
        $blade = "<div>\n<?php\n    \$snippet = '<?php echo 1; ?>';\n?>\n</div>\n";

        $issues = $this->structuralIssues($blade, 'blade-inline-php');

        $this->assertCount(1, $issues);
        $this->assertSame(2, $issues[0]->location?->line);
    }

    /**
     * Run the analyzer over a single Blade template and return only findings carrying $code.
     *
     * Filtering by code keeps these cases honest: an unrelated rule firing inside a fixture
     * cannot make the assertion pass or fail for the wrong reason.
     *
     * @return list<Issue>
     */
    private function structuralIssues(string $blade, string $code): array
    {
        $tempDir = $this->createTempDirectory(['views/structure.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        return array_values(array_filter(
            $analyzer->analyze()->getIssues(),
            fn ($issue): bool => ($issue->metadata['code'] ?? null) === $code
        ));
    }
}
