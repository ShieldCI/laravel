<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\BestPractices;

use ShieldCI\Analyzers\BestPractices\LogicInBladeAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class LogicInBladeAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new LogicInBladeAnalyzer;
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

    public function test_detects_complex_calculations_in_blade(): void
    {
        $blade = <<<'BLADE'
<div>
    @php
        $total = 0;
        foreach ($items as $item) {
            $total += $item->price * $item->quantity;
        }
        $tax = $total * 0.1;
        $grandTotal = $total + $tax;
    @endphp
    <p>Total: {{ $grandTotal }}</p>
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

    public function test_detects_database_queries_in_blade(): void
    {
        $blade = <<<'BLADE'
<div>
    @php
        $users = \App\Models\User::where('active', true)->get();
    @endphp
    @foreach($users as $user)
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

    public function test_detects_business_logic_in_blade(): void
    {
        $blade = <<<'BLADE'
<div>
    @php
        if ($order->status === 'pending' && $order->total > 100) {
            $discount = $order->total * 0.1;
            $order->discount = $discount;
            $order->save();
        }
    @endphp
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/checkout.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
    }

    public function test_provides_controller_recommendation(): void
    {
        $blade = <<<'BLADE'
<div>
    @php
        $total = array_sum(array_map(fn($item) => $item->price, $items));
    @endphp
    <p>Total: {{ $total }}</p>
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['views/cart.blade.php' => $blade]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['views']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertGreaterThan(0, count($issues));
        $this->assertStringContainsString('controller', $issues[0]->recommendation);
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
}
