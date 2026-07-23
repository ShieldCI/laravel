<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\BestPractices;

use PhpParser\NodeTraverser;
use ShieldCI\Analyzers\BestPractices\AccessorRegistry;
use ShieldCI\Analyzers\BestPractices\EloquentNPlusOneAnalyzer;
use ShieldCI\Analyzers\BestPractices\ModelAttributesRegistry;
use ShieldCI\Analyzers\BestPractices\ModelScanResult;
use ShieldCI\Analyzers\BestPractices\NPlusOneVisitor;
use ShieldCI\Analyzers\BestPractices\RelationshipRegistry;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\AnalyzersCore\Support\AstParser;
use ShieldCI\Tests\AnalyzerTestCase;

class EloquentNPlusOneAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new EloquentNPlusOneAnalyzer($this->parser);
    }

    public function test_seeded_binding_flags_lazy_relation_in_a_loop(): void
    {
        // Force-load EloquentNPlusOneAnalyzer.php: ModelScanResult, RelationshipRegistry, etc.
        // live in that file but aren't individually PSR-4 addressable, so referencing them
        // directly (without ever instantiating the analyzer) needs an explicit autoload nudge.
        class_exists(EloquentNPlusOneAnalyzer::class);

        // A view-shaped snippet: $cities has no query assignment here — its type/eager-loads
        // must come from the seed, exactly as a Blade template would receive them.
        $code = <<<'PHP'
        <?php
        foreach ($cities as $city) {
            echo $city->airports->count();
        }
        PHP;

        $ast = (new AstParser)->parseCode($code);
        $scanResult = new ModelScanResult(new RelationshipRegistry, new ModelAttributesRegistry, new AccessorRegistry);
        // Register 'airports' as a real relationship on City so registry lookup succeeds.
        $scanResult->relationships->add('City', 'airports');

        $visitor = new NPlusOneVisitor($scanResult, [
            'cities' => ['type' => 'Collection<City>', 'eagerLoads' => []],
        ]);
        $traverser = new NodeTraverser;
        $traverser->addVisitor($visitor);
        $traverser->traverse($ast);

        $this->assertNotEmpty($visitor->getIssues());
        $this->assertSame('airports', $visitor->getIssues()[0]['relationship']);
    }

    public function test_seeded_eager_load_suppresses_the_finding(): void
    {
        class_exists(EloquentNPlusOneAnalyzer::class);

        $code = <<<'PHP'
        <?php
        foreach ($cities as $city) {
            echo $city->airports->count();
        }
        PHP;

        $ast = (new AstParser)->parseCode($code);
        $scanResult = new ModelScanResult(new RelationshipRegistry, new ModelAttributesRegistry, new AccessorRegistry);
        $scanResult->relationships->add('City', 'airports');

        $visitor = new NPlusOneVisitor($scanResult, [
            'cities' => ['type' => 'Collection<City>', 'eagerLoads' => ['airports']],
        ]);
        $traverser = new NodeTraverser;
        $traverser->addVisitor($visitor);
        $traverser->traverse($ast);

        $this->assertSame([], $visitor->getIssues());
    }

    public function test_passes_uniqueness_probe_while_loop(): void
    {
        // Generate-until-unique idiom: the exists() query IS the loop condition and the
        // probed value ($code) is reassigned each iteration. This is a bounded uniqueness
        // search, not a per-row N+1, and the eager-loading remediation does not apply.
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\Question;
use Illuminate\Support\Str;

class CatalogueService
{
    private function generateCode($pillar, string $text): string
    {
        $base = $pillar->slug.'_'.Str::slug($text, '_');
        $code = $base;
        $n = 1;
        while (Question::where('code', $code)->exists()) {
            $code = $base.'_'.(++$n);
        }

        return $code;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/CatalogueService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_uniqueness_probe_do_while_loop(): void
    {
        // Same idiom in do-while form: probed value reassigned in the body, exists() in the
        // condition.
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\Post;
use Illuminate\Support\Str;

class SlugGenerator
{
    public function unique(string $base): string
    {
        $slug = $base;
        do {
            $slug = $base.'-'.Str::random(4);
        } while (Post::where('slug', $slug)->exists());

        return $slug;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/SlugGenerator.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_still_detects_exists_check_per_item_in_foreach(): void
    {
        // A genuine N+1: running an existence check for every item in a fetched collection.
        // This is NOT a uniqueness-probe condition, so it must remain flagged.
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\Question;

class Importer
{
    public function run(array $codes): array
    {
        $existing = [];
        foreach ($codes as $code) {
            if (Question::where('code', $code)->exists()) {
                $existing[] = $code;
            }
        }

        return $existing;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/Importer.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
    }

    public function test_detects_n_plus_one_queries(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class PostController
{
    public function index()
    {
        $posts = Post::all();

        foreach ($posts as $post) {
            echo $post->user->name;
            echo $post->comments->count();
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/PostController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('N+1', $result);
    }

    public function test_passes_with_eager_loading(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class PostController
{
    public function index()
    {
        $posts = Post::with(['user', 'comments'])->get();

        foreach ($posts as $post) {
            echo $post->user->name;
            echo $post->comments->count();
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/PostController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_inline_foreach_closure_eager_loading(): void
    {
        // Mirrors Compass AssessmentService::stageQuestionCodes: eager loading applied inline
        // in the foreach() expression via a closure-constrained relation.
        $code = <<<'PHP'
<?php

namespace App\Services\Assessment;

class AssessmentService
{
    public function stageQuestionCodes()
    {
        $codesByPillar = [];
        foreach (Pillar::with(['questions' => fn ($q) => $q->where('is_active', true)])->orderBy('display_order')->get() as $pillar) {
            $questions = $pillar->questions->map(fn ($question) => $question->code)->all();
            $codesByPillar[$pillar->slug] = $questions;
        }

        return $codesByPillar;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/Assessment/AssessmentService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_assigned_closure_keyed_eager_loading(): void
    {
        // Mirrors Compass CatalogueController::index: closure-keyed eager loading with a
        // nested ->with() assigned to a variable, then iterated.
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers\Staff;

class CatalogueController
{
    public function index()
    {
        $pillars = Pillar::with([
            'questions' => fn ($q) => $q->withoutGlobalScopes()->with('options')->orderBy('display_order'),
        ])->orderBy('display_order')->get();

        foreach ($pillars as $pillar) {
            echo $pillar->questions->count();
        }

        return $pillars;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/Staff/CatalogueController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_standalone_aggregate_not_in_loop(): void
    {
        // Mirrors Compass ConsoleMetricsService::kpis: standalone aggregate queries are
        // not per-row loops and must not be flagged as N+1.
        $code = <<<'PHP'
<?php

namespace App\Services\Console;

class ConsoleMetricsService
{
    public function kpis()
    {
        return [
            'completed' => Assessment::where('status', 'completed')->count(),
            'total' => Business::count(),
        ];
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/Console/ConsoleMetricsService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_column_constrained_eager_loading(): void
    {
        // with('project:id,uuid,name') — Laravel column-selection syntax.
        // The ':id,uuid,name' suffix is stripped at runtime; the relationship name is 'project'.
        $modelCode = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Report extends Model
{
    public function project()
    {
        return $this->belongsTo(Project::class);
    }
}
PHP;

        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\Report;

class DashboardStatsService
{
    public function recentReports()
    {
        $reports = Report::query()
            ->with('project:id,uuid,name')
            ->get();

        foreach ($reports as $report) {
            echo $report->project->name;
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/Report.php' => $modelCode,
            'app/Http/Controllers/DashboardStatsService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_single_relationship_string(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class PostController
{
    public function index()
    {
        $posts = Post::with('user')->get();

        foreach ($posts as $post) {
            echo $post->user->name;
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/PostController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_static_call_with(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class PostController
{
    public function index()
    {
        $posts = Post::with(['user'])->get();

        foreach ($posts as $post) {
            echo $post->user->name;
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/PostController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_detects_in_for_loop(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class PostController
{
    public function index()
    {
        $posts = Post::all();

        for ($i = 0; $i < count($posts); $i++) {
            // Not detected - for loops don't track loop variable
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/PostController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // For loops without tracked variables should pass
        $this->assertPassed($result);
    }

    public function test_detects_in_nested_foreach_loops(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class PostController
{
    public function index()
    {
        $posts = Post::all();

        foreach ($posts as $post) {
            echo $post->user->name; // N+1 on outer loop

            foreach ($post->comments as $comment) {
                echo $comment->author->name; // N+1 on inner loop
            }
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/PostController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        // Should detect at least the outer loop N+1
        $this->assertHasIssueContaining('user', $result);
    }

    public function test_passes_for_common_model_properties(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class PostController
{
    public function index()
    {
        $posts = Post::all();

        foreach ($posts as $post) {
            echo $post->id;
            echo $post->name;
            echo $post->email;
            echo $post->created_at;
            echo $post->updated_at;
            echo $post->deleted_at;
            echo $post->title;
            echo $post->content;
            echo $post->status;
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/PostController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_deduplicates_same_relationship_multiple_times(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class PostController
{
    public function index()
    {
        $posts = Post::all();

        foreach ($posts as $post) {
            echo $post->user->name;  // Line 10
            echo $post->user->email; // Line 11 - same relationship
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/PostController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        // Should only report 'user' once (deduplicated)
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
    }

    public function test_passes_with_load_method(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class PostController
{
    public function index()
    {
        $posts = Post::all();
        $posts->load('user');

        foreach ($posts as $post) {
            echo $post->user->name;
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/PostController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_when_load_missing_used(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class PostController
{
    public function index()
    {
        $posts = Post::all();
        $posts->loadMissing('user');

        foreach ($posts as $post) {
            echo $post->user->name;
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/PostController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_handles_parse_errors_gracefully(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class PostController
{
    public function index()
    {
        $posts = Post::all(
        // Invalid syntax - missing closing parenthesis
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/PostController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should not crash, should pass (no valid files to analyze)
        $this->assertPassed($result);
    }

    public function test_detects_different_variables_same_relationship_same_line(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class PostController
{
    public function index()
    {
        $posts = Post::all();
        $comments = Comment::all();

        foreach ($posts as $post) {
            echo $post->user->name;
        }

        foreach ($comments as $comment) {
            echo $comment->user->name; // Same relationship, different variable
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/PostController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        // Should detect both (fixed deduplication bug)
        $issues = $result->getIssues();
        $this->assertGreaterThanOrEqual(2, count($issues));
    }

    public function test_passes_with_multiple_with_calls(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class PostController
{
    public function index()
    {
        $posts = Post::with('user')->with('comments')->get();

        foreach ($posts as $post) {
            echo $post->user->name;
            echo $post->comments->count();
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/PostController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_detects_nested_relationship_n_plus_one(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class PostController
{
    public function index()
    {
        $posts = Post::with('user')->get();

        foreach ($posts as $post) {
            // user is eager loaded, but user->team is not
            echo $post->user->team->name;
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/PostController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('user.team', $result);
    }

    public function test_passes_with_dot_notation_eager_loading(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class PostController
{
    public function index()
    {
        $posts = Post::with('user.team')->get();

        foreach ($posts as $post) {
            echo $post->user->team->name;
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/PostController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_detects_partial_eager_loading_missing_nested(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class PostController
{
    public function index()
    {
        // Only 'user' is eager loaded, not 'user.profile'
        $posts = Post::with('user')->get();

        foreach ($posts as $post) {
            echo $post->user->profile->bio; // N+1 on profile
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/PostController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('user.profile', $result);
    }

    public function test_handles_deep_nested_relationships(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class PostController
{
    public function index()
    {
        $posts = Post::all();

        foreach ($posts as $post) {
            // Deep nesting: 4 levels
            echo $post->user->team->department->company->name;
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/PostController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        // Should detect the deepest nested relationship that looks like a relationship
        $this->assertHasIssueContaining('user.team.department.company', $result);
    }

    public function test_passes_with_deep_dot_notation_eager_loading(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class PostController
{
    public function index()
    {
        $posts = Post::with('user.team.department')->get();

        foreach ($posts as $post) {
            echo $post->user->team->department->name;
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/PostController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_nested_chain_ending_with_property_is_not_flagged(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class PostController
{
    public function index()
    {
        $posts = Post::with('user')->get();

        foreach ($posts as $post) {
            // 'name' is a property, not a relationship
            echo $post->user->name;
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/PostController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should pass because 'user' is eager loaded and 'name' is a property
        $this->assertPassed($result);
    }

    public function test_multiple_nested_relationships_detected(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class PostController
{
    public function index()
    {
        $posts = Post::all();

        foreach ($posts as $post) {
            echo $post->user->team->name;       // N+1 on user.team
            echo $post->category->parent->name; // N+1 on category.parent
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/PostController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        // Should detect multiple nested relationship issues
        $this->assertGreaterThanOrEqual(2, count($issues));
    }

    public function test_passes_with_relation_loaded_check_in_if_condition(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class PostController
{
    public function index()
    {
        $posts = Post::all();

        foreach ($posts as $post) {
            if ($post->relationLoaded('user')) {
                echo $post->user->name;
            }
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/PostController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should pass - developer checked with relationLoaded()
        $this->assertPassed($result);
    }

    public function test_passes_with_relation_loaded_in_ternary(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class PostController
{
    public function index()
    {
        $posts = Post::all();

        foreach ($posts as $post) {
            $userName = $post->relationLoaded('user') ? $post->user->name : 'Unknown';
            echo $userName;
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/PostController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should pass - developer checked with relationLoaded()
        $this->assertPassed($result);
    }

    public function test_passes_with_relation_loaded_early_return(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class PostController
{
    public function index()
    {
        $posts = Post::all();

        foreach ($posts as $post) {
            if (!$post->relationLoaded('user')) {
                continue;
            }
            echo $post->user->name;
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/PostController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should pass - developer checked with relationLoaded() before access
        $this->assertPassed($result);
    }

    public function test_relation_loaded_does_not_protect_unrelated_relationships(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class PostController
{
    public function index()
    {
        $posts = Post::all();

        foreach ($posts as $post) {
            if ($post->relationLoaded('user')) {
                echo $post->user->name;
            }
            // Comments is NOT checked with relationLoaded()
            echo $post->comments->count();
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/PostController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should fail - comments relationship is not protected
        $this->assertFailed($result);
        $this->assertHasIssueContaining('comments', $result);
    }

    public function test_relation_loaded_protects_nested_relationships(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class PostController
{
    public function index()
    {
        $posts = Post::all();

        foreach ($posts as $post) {
            if ($post->relationLoaded('user')) {
                // Accessing nested relationships is also protected
                echo $post->user->team->name;
            }
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/PostController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should pass - the first relationship in chain (user) was checked
        $this->assertPassed($result);
    }

    public function test_relation_loaded_check_does_not_leak_between_loops(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class PostController
{
    public function index()
    {
        $posts = Post::all();
        $comments = Comment::all();

        foreach ($posts as $post) {
            if ($post->relationLoaded('author')) {
                echo $post->author->name;
            }
        }

        // New loop - relationLoaded check from previous loop should not apply
        foreach ($comments as $comment) {
            echo $comment->author->name;
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/PostController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should fail - the second loop's author access is not protected
        $this->assertFailed($result);
        $this->assertHasIssueContaining('author', $result);
    }

    public function test_detects_query_inside_loop(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class UserController
{
    public function index()
    {
        $users = User::all();

        foreach ($users as $user) {
            $orders = Order::where('user_id', $user->id)->get();
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Order::where', $result);
    }

    public function test_detects_find_inside_loop(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class PostController
{
    public function index()
    {
        $userIds = [1, 2, 3, 4, 5];

        foreach ($userIds as $userId) {
            $user = User::find($userId);
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/PostController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('User::find', $result);
    }

    public function test_does_not_flag_update_or_create_inside_loop(): void
    {
        // updateOrCreate() is a deliberate per-row write, not an accidental read N+1.
        $code = <<<'PHP'
<?php

namespace App\Services;

class CatalogueImporter
{
    public function import(array $pillars)
    {
        foreach ($pillars as $data) {
            Pillar::updateOrCreate(['slug' => $data['slug']], $data);
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/CatalogueImporter.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_does_not_flag_first_or_create_inside_loop(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class TagSyncer
{
    public function sync(array $tags)
    {
        foreach ($tags as $name) {
            Tag::firstOrCreate(['name' => $name]);
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/TagSyncer.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_does_not_flag_upsert_inside_loop(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class PriceWriter
{
    public function write(array $batches)
    {
        foreach ($batches as $batch) {
            Price::upsert($batch, ['sku'], ['amount']);
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/PriceWriter.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_skips_seeder_files_for_query_in_loop(): void
    {
        // A read-per-iteration that WOULD flag under app/ — proves the directory skip
        // works independently of the write-upsert exclusion.
        $code = <<<'PHP'
<?php

namespace Database\Seeders;

class CatalogueSeeder
{
    public function run()
    {
        $rows = [['code' => 'a'], ['code' => 'b']];

        foreach ($rows as $row) {
            $lookup = Lookup::where('code', $row['code'])->first();
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'database/seeders/CatalogueSeeder.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['database']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_detects_first_inside_loop(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class OrderController
{
    public function index()
    {
        $items = Item::all();

        foreach ($items as $item) {
            $product = Product::where('sku', $item->sku)->first();
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/OrderController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Product::where', $result);
    }

    public function test_detects_multiple_queries_inside_loop(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class ReportController
{
    public function index()
    {
        $users = User::all();

        foreach ($users as $user) {
            $orders = Order::where('user_id', $user->id)->get();
            $payments = Payment::where('user_id', $user->id)->get();
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/ReportController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertGreaterThanOrEqual(2, count($issues));
    }

    public function test_passes_when_query_is_outside_loop(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class UserController
{
    public function index()
    {
        $users = User::all();
        $allOrders = Order::all(); // Query outside loop is fine

        foreach ($users as $user) {
            echo $user->name;
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_detects_count_aggregate_inside_loop(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class StatsController
{
    public function index()
    {
        $categories = Category::all();

        foreach ($categories as $category) {
            $productCount = Product::where('category_id', $category->id)->count();
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/StatsController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Product::where', $result);
    }

    public function test_passes_with_closure_keyed_eager_loading(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class PostController
{
    public function index()
    {
        $posts = Post::with([
            'user' => fn ($q) => $q->select('id', 'name'),
            'comments.author',
        ])->get();

        foreach ($posts as $post) {
            echo $post->user->name;
            echo $post->comments->first()->author->name;
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/PostController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_mixed_closure_and_string_eager_loading(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class PostController
{
    public function index()
    {
        $posts = Post::with([
            'user' => function ($query) {
                $query->select('id', 'name', 'email');
            },
            'tags',
            'category' => fn ($q) => $q->withCount('products'),
        ])->get();

        foreach ($posts as $post) {
            echo $post->user->email;
            echo $post->tags->pluck('name');
            echo $post->category->name;
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/PostController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_does_not_flag_cache_facade_inside_loop(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class UserController
{
    public function index()
    {
        $users = User::all();

        foreach ($users as $user) {
            $cached = Cache::get('user_' . $user->id);
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should pass - Cache::get() is not a database query
        $this->assertPassed($result);
    }

    public function test_does_not_flag_config_facade_inside_loop(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class UserController
{
    public function index()
    {
        $items = Item::all();

        foreach ($items as $item) {
            $setting = Config::get('app.timezone');
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should pass - Config::get() is not a database query
        $this->assertPassed($result);
    }

    public function test_does_not_flag_session_facade_inside_loop(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class UserController
{
    public function index()
    {
        $users = User::all();

        foreach ($users as $user) {
            $data = Session::get('user_data_' . $user->id);
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should pass - Session::get() is not a database query
        $this->assertPassed($result);
    }

    public function test_does_not_flag_query_not_dependent_on_loop_variable(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class UserController
{
    public function index()
    {
        $users = User::all();

        foreach ($users as $user) {
            // This query doesn't use $user at all - same query repeated
            $admins = Admin::where('active', true)->get();
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should pass - query doesn't depend on loop variable (wasteful but not N+1)
        $this->assertPassed($result);
    }

    public function test_does_not_flag_chunk_inside_loop(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class UserController
{
    public function index()
    {
        $users = User::all();

        foreach ($users as $user) {
            Order::where('user_id', $user->id)->chunk(100, function($orders) {
                // Process chunk
            });
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should pass - chunk() is intentional batching
        $this->assertPassed($result);
    }

    public function test_does_not_flag_cursor_inside_loop(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class UserController
{
    public function index()
    {
        $users = User::all();

        foreach ($users as $user) {
            foreach (Order::where('user_id', $user->id)->cursor() as $order) {
                // Process order
            }
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should pass - cursor() is memory-efficient streaming
        $this->assertPassed($result);
    }

    public function test_does_not_flag_lazy_inside_loop(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class UserController
{
    public function index()
    {
        $users = User::all();

        foreach ($users as $user) {
            $orders = Order::where('user_id', $user->id)->lazy();
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should pass - lazy() is memory-efficient streaming
        $this->assertPassed($result);
    }

    public function test_flags_query_dependent_on_loop_variable(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class UserController
{
    public function index()
    {
        $users = User::all();

        foreach ($users as $user) {
            $orders = Order::where('user_id', $user->id)->get();
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should FAIL - classic N+1, query depends on $user
        $this->assertFailed($result);
        $this->assertHasIssueContaining('Order::where', $result);
    }

    public function test_flags_query_with_loop_variable_in_closure(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class UserController
{
    public function index()
    {
        $users = User::all();

        foreach ($users as $user) {
            $orders = Order::where(fn($q) => $q->where('user_id', $user->id))->get();
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should FAIL - closure captures loop variable
        $this->assertFailed($result);
        $this->assertHasIssueContaining('Order::where', $result);
    }

    public function test_flags_query_with_loop_variable_in_arrow_function(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class UserController
{
    public function index()
    {
        $users = User::all();

        foreach ($users as $user) {
            $orders = Order::whereHas('items', fn($q) => $q->where('buyer_id', $user->id))->get();
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should FAIL - arrow function references loop variable
        $this->assertFailed($result);
        $this->assertHasIssueContaining('Order::whereHas', $result);
    }

    public function test_does_not_flag_multiple_non_query_facades(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class UserController
{
    public function index()
    {
        $users = User::all();

        foreach ($users as $user) {
            $cached = Cache::get('user_' . $user->id);
            $setting = Config::get('users.default_role');
            $session = Session::get('user_pref_' . $user->id);
            $logged = Log::info('Processing user ' . $user->id);
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should pass - none of these are database queries
        $this->assertPassed($result);
    }

    public function test_flags_direct_find_with_loop_variable(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class UserController
{
    public function index()
    {
        $userIds = [1, 2, 3, 4, 5];

        foreach ($userIds as $userId) {
            $user = User::find($userId);
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should FAIL - find() with loop variable is N+1
        $this->assertFailed($result);
        $this->assertHasIssueContaining('User::find', $result);
    }

    public function test_does_not_flag_find_without_loop_variable(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class UserController
{
    public function index()
    {
        $items = Item::all();
        $adminId = 1;

        foreach ($items as $item) {
            // Query doesn't depend on $item, uses constant $adminId
            $admin = User::find($adminId);
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should pass - query doesn't depend on loop variable
        $this->assertPassed($result);
    }

    public function test_does_not_flag_query_when_closure_captures_but_does_not_use_variable(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class UserController
{
    public function index()
    {
        $users = User::all();

        foreach ($users as $user) {
            // Closure captures $user but doesn't use it - query doesn't depend on $user
            // This is not a true N+1 pattern (same query every iteration, not loop-dependent)
            $posts = Post::where('active', true)->get(function($q) use ($user) {
                $q->where('published', true); // No $user reference
            });
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should pass - query doesn't depend on loop variable (just captured, not used)
        // This fixes false positives where closure captures variable but doesn't use it
        $this->assertPassed($result);
    }

    public function test_flags_query_when_closure_uses_captured_variable(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class UserController
{
    public function index()
    {
        $users = User::all();

        foreach ($users as $user) {
            // Closure captures AND uses $user - query depends on $user, legitimate N+1
            $posts = Post::where(function($q) use ($user) {
                $q->where('user_id', $user->id); // Actually uses $user
            })->get();
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should fail - this is a legitimate N+1 query
        $this->assertFailed($result);
    }

    public function test_for_loop_flags_query_using_counter_variable(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class UserController
{
    public function index()
    {
        $ids = [1, 2, 3, 4, 5];

        for ($i = 0; $i < count($ids); $i++) {
            // Query uses $i in array access - true N+1 pattern
            $user = User::find($ids[$i]);
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should flag - uses $i (counter variable) in query
        $this->assertFailed($result);
        $this->assertHasIssueContaining('User::find', $result);
    }

    public function test_for_loop_ignores_query_not_using_counter(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class UserController
{
    public function index()
    {
        for ($i = 0; $i < 10; $i++) {
            // Same query every iteration - doesn't use $i
            $admins = User::where('role', 'admin')->get();
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should NOT flag - query doesn't depend on $i
        $this->assertPassed($result);
    }

    public function test_while_loop_flags_query_using_condition_variable(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class UserController
{
    public function index()
    {
        $page = 1;
        $hasMore = true;

        while ($hasMore && $page < 100) {
            // Query uses $page - true N+1 pattern
            $records = Record::where('page', $page)->get();
            $page++;
            $hasMore = count($records) > 0;
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should flag - uses $page (condition variable) in query
        $this->assertFailed($result);
        $this->assertHasIssueContaining('Record::where', $result);
    }

    public function test_while_loop_ignores_query_not_using_condition_variable(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class UserController
{
    public function index()
    {
        $hasMore = true;

        while ($hasMore) {
            // Same query every iteration - doesn't use $hasMore
            $config = Config::get('key');
            $hasMore = someExternalCheck();
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should NOT flag - Config::get is not a query, and doesn't use $hasMore
        $this->assertPassed($result);
    }

    public function test_do_while_flags_query_using_condition_variable(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class UserController
{
    public function index()
    {
        $cursor = 0;

        do {
            // Query uses $cursor - true N+1 pattern
            $records = Record::where('id', '>', $cursor)->first();
            $cursor = $records ? $records->id : null;
        } while ($cursor !== null);
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should flag - uses $cursor (condition variable) in query
        $this->assertFailed($result);
        $this->assertHasIssueContaining('Record::where', $result);
    }

    public function test_do_while_ignores_query_not_using_condition_variable(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class UserController
{
    public function index()
    {
        $shouldContinue = true;

        do {
            // Same query every iteration - doesn't use $shouldContinue
            $settings = Setting::where('key', 'default')->first();
            $shouldContinue = someCheck();
        } while ($shouldContinue);
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should NOT flag - query doesn't depend on $shouldContinue
        $this->assertPassed($result);
    }

    public function test_for_loop_with_no_init_does_not_flag(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class UserController
{
    public function index()
    {
        $i = 0;
        // For loop with no init expression
        for (; $i < 10; $i++) {
            $admins = User::where('role', 'admin')->get();
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should NOT flag - can't track loop variable when init is empty
        $this->assertPassed($result);
    }

    public function test_while_loop_with_method_call_condition_ignores_unrelated_query(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class UserController
{
    public function index()
    {
        $iterator = new Iterator();

        while ($iterator->hasNext()) {
            // Query doesn't use iterator
            $users = User::where('active', true)->get();
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should NOT flag - query doesn't depend on $iterator
        $this->assertPassed($result);
    }

    public function test_while_loop_with_method_call_condition_flags_related_query(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class UserController
{
    public function index()
    {
        $iterator = new Iterator();

        while ($iterator->hasNext()) {
            // Query uses iterator
            $record = Record::find($iterator->current());
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should flag - query uses $iterator
        $this->assertFailed($result);
        $this->assertHasIssueContaining('Record::find', $result);
    }

    // -------------------------------------------------------------------------
    // Registry-based detection tests (EloquentModelRelationshipScanner)
    // -------------------------------------------------------------------------

    public function test_does_not_flag_hash_column_when_model_has_no_such_relationship(): void
    {
        $modelCode = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Project extends Model
{
    public function owner()
    {
        return $this->belongsTo(User::class);
    }
}
PHP;

        $controllerCode = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\Project;

class ValidateSatisAuth
{
    public function handle()
    {
        $projects = Project::get();

        foreach ($projects as $project) {
            echo $project->api_token_hash;
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/Project.php' => $modelCode,
            'app/Http/Controllers/ValidateSatisAuth.php' => $controllerCode,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_does_not_flag_result_count_columns_when_model_has_no_such_relationship(): void
    {
        $modelCode = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Report extends Model
{
    public function project()
    {
        return $this->belongsTo(Project::class);
    }
}
PHP;

        $controllerCode = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\Report;

class ProjectController
{
    public function show()
    {
        $reports = Report::get();

        foreach ($reports as $report) {
            echo $report->passed;
            echo $report->failed;
            echo $report->warnings;
            echo $report->errors;
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/Report.php' => $modelCode,
            'app/Http/Controllers/ProjectController.php' => $controllerCode,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_detects_relationship_from_scanned_model_file(): void
    {
        $modelCode = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Post extends Model
{
    public function comments()
    {
        return $this->hasMany(Comment::class);
    }
}
PHP;

        $controllerCode = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\Post;

class PostController
{
    public function index()
    {
        $posts = Post::get();

        foreach ($posts as $post) {
            echo $post->comments;
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/Post.php' => $modelCode,
            'app/Http/Controllers/PostController.php' => $controllerCode,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('comments', $result);
    }

    public function test_passes_when_scanned_relationship_is_eager_loaded(): void
    {
        $modelCode = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Post extends Model
{
    public function comments()
    {
        return $this->hasMany(Comment::class);
    }
}
PHP;

        $controllerCode = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\Post;

class PostController
{
    public function index()
    {
        $posts = Post::with('comments')->get();

        foreach ($posts as $post) {
            echo $post->comments;
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/Post.php' => $modelCode,
            'app/Http/Controllers/PostController.php' => $controllerCode,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_eager_load_prefix_covers_intermediate_access(): void
    {
        $modelCode = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Post extends Model
{
    public function user()
    {
        return $this->belongsTo(User::class);
    }
}
PHP;

        $controllerCode = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\Post;

class PostController
{
    public function index()
    {
        $posts = Post::with('user.team')->get();

        foreach ($posts as $post) {
            echo $post->user;
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/Post.php' => $modelCode,
            'app/Http/Controllers/PostController.php' => $controllerCode,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_infers_model_type_through_collection_variable(): void
    {
        $modelCode = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Post extends Model
{
    public function tags()
    {
        return $this->belongsToMany(Tag::class);
    }
}
PHP;

        $controllerCode = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\Post;

class PostController
{
    public function index()
    {
        $posts = Post::get();

        foreach ($posts as $post) {
            echo $post->tags;
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/Post.php' => $modelCode,
            'app/Http/Controllers/PostController.php' => $controllerCode,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('tags', $result);
    }

    public function test_does_not_flag_find_result_scalar_columns(): void
    {
        $modelCode = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Post extends Model
{
    public function user()
    {
        return $this->belongsTo(User::class);
    }
}
PHP;

        $controllerCode = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\Post;

class PostController
{
    public function show($id)
    {
        $post = Post::find($id);

        foreach ([$post] as $p) {
            echo $p->title;
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/Post.php' => $modelCode,
            'app/Http/Controllers/PostController.php' => $controllerCode,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_detects_relation_method_query_call_in_loop(): void
    {
        $modelCode = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Post extends Model
{
    public function comments()
    {
        return $this->hasMany(Comment::class);
    }
}
PHP;

        $controllerCode = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\Post;

class PostController
{
    public function index()
    {
        $posts = Post::get();

        foreach ($posts as $post) {
            $count = $post->comments()->count();
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/Post.php' => $modelCode,
            'app/Http/Controllers/PostController.php' => $controllerCode,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('comments', $result);
    }

    public function test_does_not_flag_property_access_when_variable_type_is_unknown(): void
    {
        // Simulates $projects = $user->teams()->flatMap(...) — no static-call type inference.
        // When the loop variable's model type cannot be determined, the analyzer should
        // stay silent rather than guess (conservative: false negatives over false positives).
        $modelCode = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Project extends Model
{
    public function owner()
    {
        return $this->belongsTo(User::class);
    }
}
PHP;

        $controllerCode = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\Project;

class ValidateSatisAuth
{
    public function handle($user)
    {
        // flatMap produces an unknown-type collection — no static-call signature
        $projects = $user->teams()->with('projects')->get()->flatMap(
            fn ($team) => $team->projects
        );

        foreach ($projects as $project) {
            echo $project->api_token_hash;
            echo $project->passed;
            echo $project->total_issues;
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/Project.php' => $modelCode,
            'app/Http/Controllers/ValidateSatisAuth.php' => $controllerCode,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_does_not_flag_when_model_is_in_registry_but_property_is_not_a_relationship(): void
    {
        // When we have precise type info AND the model is in the registry,
        // any property NOT listed as a relationship must not be flagged.
        $modelCode = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Report extends Model
{
    protected $fillable = ['passed', 'failed', 'warnings', 'errors', 'skipped'];

    public function project()
    {
        return $this->belongsTo(Project::class);
    }
}
PHP;

        $controllerCode = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\Report;

class DashboardController
{
    public function index()
    {
        $reports = Report::get();

        foreach ($reports as $report) {
            echo $report->passed;
            echo $report->failed;
            echo $report->warnings;
            echo $report->errors;
            echo $report->skipped;
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/Report.php' => $modelCode,
            'app/Http/Controllers/DashboardController.php' => $controllerCode,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_does_not_flag_accessor_property_when_model_is_in_registry(): void
    {
        // Accessor methods (getXxxAttribute) should not be flagged as relationships.
        $modelCode = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Post extends Model
{
    public function getFullTitleAttribute()
    {
        return $this->title . ' — ' . $this->subtitle;
    }

    public function comments()
    {
        return $this->hasMany(Comment::class);
    }
}
PHP;

        $controllerCode = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\Post;

class PostController
{
    public function index()
    {
        $posts = Post::get();

        foreach ($posts as $post) {
            echo $post->full_title;
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/Post.php' => $modelCode,
            'app/Http/Controllers/PostController.php' => $controllerCode,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_does_not_flag_accessor_property_when_model_has_no_relationships(): void
    {
        // Regression test: Config defines zero relationships, so it never enters the
        // relationshipRegistry (which is keyed only by models that define at least one
        // relationship). That used to make isActualOrProbableRelationship() fall through
        // to the heuristic path, which has no accessor/attribute awareness and flagged
        // 'value_preview' as a probable relationship. Accessors must be suppressed
        // regardless of whether their model defines any relationships.
        $modelCode = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Config extends Model
{
    public function getValuePreviewAttribute(): string
    {
        return str($this->value)->limit(50)->toString();
    }
}
PHP;

        $controllerCode = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\Config;

class ConfigController
{
    public function index()
    {
        $configs = Config::all();

        foreach ($configs as $config) {
            echo $config->value_preview;
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/Config.php' => $modelCode,
            'app/Http/Controllers/ConfigController.php' => $controllerCode,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_lock_for_update_in_loop_is_not_flagged(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class StockController
{
    public function issue(array $items): void
    {
        foreach ($items as $item) {
            // Pessimistic lock is inherently per-row - not an N+1 to fix
            $stock = StoreItem::lockForUpdate()->whereKey($item['id'])->firstOrFail();
            $stock->decrement('quantity', $item['qty']);
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/StockController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should pass - a lockForUpdate chain cannot be eager-loaded or batched
        $this->assertPassed($result);
    }

    public function test_shared_lock_in_loop_is_not_flagged(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class StockController
{
    public function read(array $ids): void
    {
        foreach ($ids as $id) {
            $row = StoreItem::where('id', $id)->sharedLock()->first();
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/StockController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should pass - sharedLock anywhere in the chain marks it per-row
        $this->assertPassed($result);
    }

    public function test_lockless_chain_in_loop_is_still_flagged(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class StockController
{
    public function issue(array $items): void
    {
        foreach ($items as $item) {
            // Same shape as the lock tests but without a lock - genuine N+1
            $stock = StoreItem::whereKey($item['id'])->firstOrFail();
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/StockController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should flag - loop-dependent query with no lock in the chain
        $this->assertFailed($result);
        $this->assertHasIssueContaining('StoreItem::whereKey', $result);
    }

    public function test_find_followed_by_return_in_loop_is_not_flagged(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class AssignmentController
{
    public function attach(array $incoming): string
    {
        foreach ($incoming as $employeeId) {
            if ($this->deployedElsewhere($employeeId)) {
                // Runs at most once: the branch unconditionally leaves the loop
                $employee = Employee::find($employeeId);

                return 'already deployed';
            }
        }

        return 'attached';
    }

    private function deployedElsewhere(int $id): bool
    {
        return $id > 100;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/AssignmentController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should pass - the query's branch returns, so it executes at most once
        $this->assertPassed($result);
    }

    public function test_chain_query_followed_by_return_in_loop_is_not_flagged(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class AssignmentController
{
    public function attach(array $ids): ?object
    {
        foreach ($ids as $id) {
            if ($id > 100) {
                $employee = Employee::where('id', $id)->first();

                return $employee;
            }
        }

        return null;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/AssignmentController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should pass - method-chain query followed by an unconditional return
        $this->assertPassed($result);
    }

    public function test_query_followed_by_throw_in_loop_is_not_flagged(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class ItemController
{
    public function validateAll(array $ids): void
    {
        foreach ($ids as $id) {
            if ($id < 0) {
                $item = Item::find($id);

                throw new \RuntimeException('invalid item');
            }
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/ItemController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should pass - throw unconditionally exits the loop
        $this->assertPassed($result);
    }

    public function test_query_followed_by_break_in_single_loop_is_not_flagged(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class ItemController
{
    public function firstMatch(array $ids): void
    {
        foreach ($ids as $id) {
            if ($id > 100) {
                $match = Item::find($id);
                break;
            }
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/ItemController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should pass - break exits the only enclosing loop
        $this->assertPassed($result);
    }

    public function test_query_followed_by_log_then_return_is_not_flagged(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class AssignmentController
{
    public function attach(array $ids): string
    {
        foreach ($ids as $id) {
            if ($id > 100) {
                $employee = Employee::find($id);
                Log::info('conflict found');

                return 'conflict';
            }
        }

        return 'attached';
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/AssignmentController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should pass - plain expression statements cannot re-enter the loop
        $this->assertPassed($result);
    }

    public function test_query_in_if_with_return_after_if_is_not_flagged(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class ItemController
{
    public function firstOnly(array $ids): ?object
    {
        foreach ($ids as $id) {
            if ($id > 0) {
                $item = Item::find($id);
            }

            return $item ?? null;
        }

        return null;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/ItemController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should pass - the loop body unconditionally returns after the if block
        $this->assertPassed($result);
    }

    public function test_query_in_elseif_and_else_followed_by_return_is_not_flagged(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class ItemController
{
    public function resolve(array $ids): ?object
    {
        foreach ($ids as $id) {
            if ($id === 0) {
                continue;
            } elseif ($id < 100) {
                $a = Item::find($id);

                return $a;
            } else {
                $b = Item::find($id);

                return $b;
            }
        }

        return null;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/ItemController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should pass - both branches unconditionally return after their query
        $this->assertPassed($result);
    }

    public function test_query_with_conditional_return_still_flagged(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class UserController
{
    public function firstActive(array $ids): ?object
    {
        foreach ($ids as $id) {
            // The query runs every iteration; only the return is conditional
            $user = User::find($id);
            if ($user !== null) {
                return $user;
            }
        }

        return null;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should flag - the loop can iterate again after the query
        $this->assertFailed($result);
        $this->assertHasIssueContaining('User::find', $result);
    }

    public function test_query_followed_by_break_in_nested_loop_still_flagged(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class ItemController
{
    public function scan(array $groups): void
    {
        foreach ($groups as $group) {
            foreach ($group as $id) {
                if ($id > 5) {
                    // break only exits the inner loop; the outer loop repeats
                    $item = Item::find($id);
                    break;
                }
            }
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/ItemController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should flag - the query can run once per outer iteration
        $this->assertFailed($result);
        $this->assertHasIssueContaining('Item::find', $result);
    }

    public function test_query_then_return_inside_try_still_flagged(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class ItemController
{
    public function firstResolvable(array $ids): ?object
    {
        foreach ($ids as $id) {
            try {
                $item = Item::find($id);

                return $item;
            } catch (\Throwable $e) {
                // A throwing query is caught and the loop resumes
                continue;
            }
        }

        return null;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/ItemController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should flag - inside try, the loop can resume via the catch block
        $this->assertFailed($result);
        $this->assertHasIssueContaining('Item::find', $result);
    }

    public function test_query_in_while_condition_still_flagged_despite_return_after_loop(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class CategoryController
{
    public function rootOf(array $seeds): mixed
    {
        foreach ($seeds as $seed) {
            $currentId = $seed;
            // The query re-runs on every while iteration - the return below
            // only exits after the whole chain walk
            while ($category = Category::find($currentId)) {
                $currentId = $category->parent_id;
            }

            return $currentId;
        }

        return null;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/CategoryController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should flag - a loop-header query repeats even though the outer
        // foreach body ends in a return
        $this->assertFailed($result);
        $this->assertHasIssueContaining('Category::find', $result);
    }
}
