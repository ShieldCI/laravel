<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\BestPractices;

use ShieldCI\Analyzers\BestPractices\EloquentNPlusOneAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class EloquentNPlusOneAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new EloquentNPlusOneAnalyzer($this->parser);
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
}
